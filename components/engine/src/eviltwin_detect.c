#include "eviltwin_detect.h"
#include <string.h>

void eviltwin_reset(eviltwin_engine_t *e) { memset(e, 0, sizeof(*e)); }

static et_ssid_t *find_or_add_ssid(eviltwin_engine_t *e, const char *ssid)
{
    for (uint8_t i = 0; i < e->n; i++)
        if (strcmp(e->tbl[i].ssid, ssid) == 0) return &e->tbl[i];
    if (e->n >= ET_MAX_SSID) return NULL;
    et_ssid_t *s = &e->tbl[e->n++];
    memset(s, 0, sizeof(*s));
    strncpy(s->ssid, ssid, sizeof(s->ssid) - 1);
    return s;
}

void eviltwin_feed(eviltwin_engine_t *e, const uint8_t *buf, uint16_t len,
                   int8_t rssi, uint32_t now_ms)
{
    wifi_mgmt_t m;
    if (!wifi_parse_mgmt(buf, len, &m)) return;
    if (m.type != WIFI_FTYPE_MGMT) return;
    if (m.subtype != WIFI_STYPE_BEACON && m.subtype != WIFI_STYPE_PROBE_RESP) return;

    char ssid[33];
    uint8_t sl = wifi_copy_ssid(buf, len, ssid, sizeof(ssid));
    if (sl == 0) return;    /* hidden/wildcard SSID - nothing to correlate */

    et_ssid_t *s = find_or_add_ssid(e, ssid);
    if (!s) return;

    uint8_t chan = wifi_beacon_channel(buf, len);
    uint8_t sec  = wifi_beacon_security(buf, len);

    /* upsert this BSSID under the SSID */
    for (uint8_t i = 0; i < s->nap; i++) {
        if (memcmp(s->aps[i].bssid, m.addr3, 6) == 0) {
            s->aps[i].channel = chan ? chan : s->aps[i].channel;
            s->aps[i].security = sec;
            s->aps[i].rssi = rssi;
            s->aps[i].last_ms = now_ms;
            return;
        }
    }
    if (s->nap >= ET_MAX_AP_PER_SSID) return;
    et_ap_t *ap = &s->aps[s->nap++];
    memcpy(ap->bssid, m.addr3, 6);
    ap->channel = chan; ap->security = sec; ap->rssi = rssi;
    ap->last_ms = now_ms; ap->trusted = false;
}

void eviltwin_lock_baseline(eviltwin_engine_t *e)
{
    for (uint8_t i = 0; i < e->n; i++)
        for (uint8_t j = 0; j < e->tbl[i].nap; j++)
            e->tbl[i].aps[j].trusted = true;
    e->baseline_locked = true;
}


void eviltwin_clear_baseline(eviltwin_engine_t *e)
{
    for (uint8_t i = 0; i < e->n; i++)
        for (uint8_t j = 0; j < e->tbl[i].nap; j++)
            e->tbl[i].aps[j].trusted = false;
    e->baseline_locked = false;
}

aegis_verdict_t eviltwin_eval(eviltwin_engine_t *e, uint32_t now_ms,
                              aegis_finding_t *out)
{
    (void)now_ms;
    uint8_t best = 0; int best_si = -1, best_ap = -1;

    for (uint8_t i = 0; i < e->n; i++) {
        et_ssid_t *s = &e->tbl[i];
        if (s->nap < 2 && !e->baseline_locked) continue;

        /* look for the contradictions */
        bool sec_conflict = false;
        uint8_t sec0 = s->aps[0].security;
        int untrusted_ap = -1;
        for (uint8_t j = 0; j < s->nap; j++) {
            if (s->aps[j].security != sec0) sec_conflict = true;
            if (e->baseline_locked && !s->aps[j].trusted) untrusted_ap = j;
        }

        int score = 0; int off_ap = 0;
        if (s->nap >= 2) { score = 40; off_ap = s->nap - 1; }  /* duplicate: ELEVATED */
        if (sec_conflict) {                                    /* the strong tell     */
            score = 78; off_ap = 0;
            for (uint8_t j = 0; j < s->nap; j++)
                if (s->aps[j].security != sec0) { off_ap = j; break; }
        }
        if (untrusted_ap >= 0) {                               /* baseline violation  */
            if (score < 80) score = 80;
            off_ap = untrusted_ap;
        }

        uint8_t sc = aegis_clamp_score(score);
        if (sc > best) { best = sc; best_si = i; best_ap = off_ap; }
    }

    aegis_verdict_t v = aegis_verdict_of(best);
    if (out) {
        memset(out, 0, sizeof(*out));
        out->kind = AEGIS_KIND_EVIL_TWIN;
        out->verdict = v;
        out->score = best;
        out->last_ms = now_ms;
        if (best_si >= 0) {
            et_ssid_t *s = &e->tbl[best_si];
            et_ap_t *ap = &s->aps[best_ap < 0 ? 0 : best_ap];
            memcpy(out->mac, ap->bssid, 6);
            out->rssi = ap->rssi;
            out->channel = ap->channel;
            strncpy(out->label, s->ssid, sizeof(out->label) - 1);
        }
    }
    return v;
}
