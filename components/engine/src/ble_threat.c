#include "ble_threat.h"
#include <string.h>

void ble_reset(ble_engine_t *e) { memset(e, 0, sizeof(*e)); }

static ble_trk_entry_t *trk_find(ble_engine_t *e, const uint8_t addr[6])
{
    for (uint16_t i = 0; i < BLE_TRK_TABLE; i++)
        if (e->trk[i].used && memcmp(e->trk[i].addr, addr, 6) == 0)
            return &e->trk[i];
    return NULL;
}

static ble_trk_entry_t *trk_alloc(ble_engine_t *e)
{
    ble_trk_entry_t *lru = &e->trk[0];
    for (uint16_t i = 0; i < BLE_TRK_TABLE; i++) {
        if (!e->trk[i].used) return &e->trk[i];
        if (e->trk[i].last_ms < lru->last_ms) lru = &e->trk[i];
    }
    return lru;
}

void ble_feed(ble_engine_t *e, const uint8_t addr[6], int8_t rssi,
              const uint8_t *adv, uint8_t adv_len, uint32_t now_ms)
{
    ble_tracker_t fam = ble_classify_tracker(adv, adv_len);
    if (fam != BLE_TRK_NONE) {
        ble_trk_entry_t *t = trk_find(e, addr);
        if (!t) {
            t = trk_alloc(e);
            memset(t, 0, sizeof(*t));
            memcpy(t->addr, addr, 6);
            t->family = fam;
            t->first_ms = now_ms;
            t->used = true;
        }
        t->last_ms = now_ms;
        t->rssi = rssi;
        t->hits++;
    }

    ble_spam_t sp = ble_classify_spam(adv, adv_len);
    if (sp != BLE_SPAM_NONE) {
        ble_spam_entry_t *s = &e->spam[e->spam_head];
        memcpy(s->addr, addr, 6);
        s->kind = sp;
        s->t_ms = now_ms;
        s->used = true;
        e->spam_head = (uint16_t)((e->spam_head + 1) % BLE_SPAM_TABLE);
    }
}

aegis_verdict_t ble_eval_tracker(ble_engine_t *e, uint32_t now_ms,
                                 aegis_finding_t *out)
{
    uint8_t best = 0; ble_trk_entry_t *win = NULL;
    for (uint16_t i = 0; i < BLE_TRK_TABLE; i++) {
        ble_trk_entry_t *t = &e->trk[i];
        if (!t->used) continue;
        uint32_t span = t->last_ms - t->first_ms;
        if (span == 0 || t->hits < 3) continue;   /* one glimpse is not a stalker */

        /* Score grows with dwell span (capped at the 2-min reference) and with
         * repeat sightings. A tag lingering with you across minutes and many
         * adverts is the signal. Ceiling honours address-rotation uncertainty. */
        int span_pts = (int)((span > BLE_TRK_DWELL_MS ? BLE_TRK_DWELL_MS : span)
                             * 60 / BLE_TRK_DWELL_MS);          /* 0..60 */
        int hit_pts  = (int)(t->hits > 30 ? 30 : t->hits);      /* 0..30 */
        uint8_t sc = aegis_clamp_score(span_pts + hit_pts);
        if (sc > best) { best = sc; win = t; }
    }

    aegis_verdict_t v = aegis_verdict_of(best);
    if (out) {
        memset(out, 0, sizeof(*out));
        out->kind = AEGIS_KIND_BLE_TRACKER;
        out->verdict = v;
        out->score = best;
        out->last_ms = now_ms;
        if (win) {
            memcpy(out->mac, win->addr, 6);
            out->rssi = win->rssi;
            out->hits = win->hits;
            out->first_ms = win->first_ms;
            strncpy(out->label, ble_tracker_name(win->family), sizeof(out->label) - 1);
        }
    }
    return v;
}

aegis_verdict_t ble_eval_spam(ble_engine_t *e, uint32_t now_ms,
                              aegis_finding_t *out)
{
    /* Count DISTINCT advertiser addresses carrying a pairing advert in-window. */
    uint8_t seen[BLE_SPAM_TABLE][6]; int nseen = 0;
    ble_spam_t witness = BLE_SPAM_NONE;
    for (uint16_t i = 0; i < BLE_SPAM_TABLE; i++) {
        ble_spam_entry_t *s = &e->spam[i];
        if (!s->used) continue;
        if ((now_ms - s->t_ms) > BLE_SPAM_WINDOW_MS) continue;
        bool dup = false;
        for (int k = 0; k < nseen; k++)
            if (memcmp(seen[k], s->addr, 6) == 0) { dup = true; break; }
        if (!dup && nseen < (int)BLE_SPAM_TABLE) {
            memcpy(seen[nseen++], s->addr, 6);
            witness = s->kind;
        }
    }

    /* Floor: a couple of real nearby devices advertise pairing legitimately.
     * A flood shows dozens of distinct addresses in a 4s window. */
    int score = 0;
    if (nseen > 3) score = (nseen - 3) * 8;    /* 3->0, 8->40, 12->72 */
    uint8_t s = aegis_clamp_score(score);

    aegis_verdict_t v = aegis_verdict_of(s);
    if (out) {
        memset(out, 0, sizeof(*out));
        out->kind = AEGIS_KIND_BLE_SPAM;
        out->verdict = v;
        out->score = s;
        out->hits = (uint32_t)nseen;
        out->last_ms = now_ms;
        snprintf(out->label, sizeof(out->label), "%s x%d", ble_spam_name(witness), nseen);
    }
    return v;
}
