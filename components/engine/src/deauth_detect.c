#include "deauth_detect.h"
#include <string.h>

void deauth_reset(deauth_engine_t *e)
{
    memset(e, 0, sizeof(*e));
}

/* Drop events older than the window, keeping the ring a true sliding window. */
static void deauth_expire(deauth_engine_t *e, uint32_t now_ms)
{
    while (e->count) {
        uint16_t oldest = (uint16_t)((e->head + DEAUTH_RING - e->count) % DEAUTH_RING);
        uint32_t age = now_ms - e->ring[oldest].t_ms;
        if (age <= DEAUTH_WINDOW_MS) break;
        e->count--;
    }
}

void deauth_feed(deauth_engine_t *e, const wifi_mgmt_t *m, uint16_t reason,
                 int8_t rssi, uint8_t channel, uint32_t now_ms)
{
    (void)rssi; (void)channel;
    if (!m || !m->valid || m->type != WIFI_FTYPE_MGMT) return;
    if (m->subtype != WIFI_STYPE_DEAUTH && m->subtype != WIFI_STYPE_DISASSOC) return;

    /* A broadcast-addressed deauth kicks every client at once - the loudest
     * flood signature. Reason 7 ("class 3 frame from nonassociated STA") is a
     * tell of tools that spray without a real association. Weight them up. */
    uint8_t weight = 1;
    if (wifi_is_broadcast(m->addr1)) weight += 3;
    if (reason == 7)                 weight += 1;

    deauth_expire(e, now_ms);

    deauth_evt_t *slot = &e->ring[e->head];
    slot->t_ms   = now_ms;
    slot->weight = weight;
    memcpy(slot->bssid, m->addr3, 6);
    e->head = (uint16_t)((e->head + 1) % DEAUTH_RING);
    if (e->count < DEAUTH_RING) e->count++;
}

aegis_verdict_t deauth_eval(deauth_engine_t *e, uint32_t now_ms,
                            aegis_finding_t *out)
{
    deauth_expire(e, now_ms);

    /* Weighted event mass in the window, plus the busiest BSSID. */
    uint32_t mass = 0;
    /* small tally of up to 8 distinct BSSIDs to name the worst offender */
    uint8_t  cand[8][6];  uint32_t cand_hits[8];  int ncand = 0;
    for (uint16_t i = 0; i < e->count; i++) {
        uint16_t idx = (uint16_t)((e->head + DEAUTH_RING - 1 - i) % DEAUTH_RING);
        deauth_evt_t *ev = &e->ring[idx];
        mass += ev->weight;
        int f = -1;
        for (int c = 0; c < ncand; c++)
            if (memcmp(cand[c], ev->bssid, 6) == 0) { f = c; break; }
        if (f < 0 && ncand < 8) { f = ncand++; memcpy(cand[f], ev->bssid, 6); cand_hits[f] = 0; }
        if (f >= 0) cand_hits[f]++;
    }

    int best = -1; uint32_t best_hits = 0;
    for (int c = 0; c < ncand; c++)
        if (cand_hits[c] > best_hits) { best_hits = cand_hits[c]; best = c; }

    /* Score curve. Floor: a handful of frames (mass < 5) stays CLEAR - that is
     * ordinary roaming. From there it climbs; ELEVATED near ~6-8 frames,
     * LIKELY once a real flood (~20 weighted events / 3s) is sustained. */
    int score = 0;
    if (mass >= 5) score = (int)((mass - 4) * 5);   /* 5->5, 10->30, 18->70 */
    uint8_t s = aegis_clamp_score(score);
    aegis_verdict_t v = aegis_verdict_of(s);

    if (v >= AEGIS_ELEVATED) {
        if (e->first_ms == 0) e->first_ms = now_ms;
    } else {
        e->first_ms = 0;
    }

    if (out) {
        memset(out, 0, sizeof(*out));
        out->kind    = AEGIS_KIND_DEAUTH_FLOOD;
        out->verdict = v;
        out->score   = s;
        out->hits    = mass;
        out->first_ms= e->first_ms ? e->first_ms : now_ms;
        out->last_ms = now_ms;
        if (best >= 0) {
            memcpy(out->mac, cand[best], 6);
            aegis_mac_str(out->label, sizeof(out->label), cand[best]);
        }
    }
    return v;
}
