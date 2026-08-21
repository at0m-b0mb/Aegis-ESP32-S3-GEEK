#include "beacon_flood.h"
#include <string.h>

void beacon_flood_reset(beacon_flood_engine_t *e) { memset(e, 0, sizeof(*e)); }

static bf_ap_t *bf_find(beacon_flood_engine_t *e, const uint8_t bssid[6])
{
    for (uint16_t i = 0; i < BF_TABLE; i++)
        if (e->tbl[i].used && memcmp(e->tbl[i].bssid, bssid, 6) == 0)
            return &e->tbl[i];
    return NULL;
}

/* Grab a free slot, or evict the least-recently-seen entry. */
static bf_ap_t *bf_alloc(beacon_flood_engine_t *e)
{
    bf_ap_t *lru = &e->tbl[0];
    for (uint16_t i = 0; i < BF_TABLE; i++) {
        if (!e->tbl[i].used) { e->n++; return &e->tbl[i]; }
        if (e->tbl[i].last_ms < lru->last_ms) lru = &e->tbl[i];
    }
    return lru;    /* table full: reuse the stalest slot */
}

void beacon_flood_feed(beacon_flood_engine_t *e, const uint8_t *buf,
                       uint16_t len, uint32_t now_ms)
{
    wifi_mgmt_t m;
    if (!wifi_parse_mgmt(buf, len, &m)) return;
    if (m.type != WIFI_FTYPE_MGMT || m.subtype != WIFI_STYPE_BEACON) return;

    bf_ap_t *ap = bf_find(e, m.addr3);
    if (ap) { ap->last_ms = now_ms; return; }
    ap = bf_alloc(e);
    memcpy(ap->bssid, m.addr3, 6);
    ap->first_ms = ap->last_ms = now_ms;
    ap->used = true;
}

aegis_verdict_t beacon_flood_eval(beacon_flood_engine_t *e, uint32_t now_ms,
                                  aegis_finding_t *out)
{
    uint32_t arrivals = 0;   /* BSSIDs first seen within the window */
    for (uint16_t i = 0; i < BF_TABLE; i++)
        if (e->tbl[i].used && (now_ms - e->tbl[i].first_ms) <= BF_WINDOW_MS)
            arrivals++;

    /* Floor: up to ~8 fresh APs in 5s is a plausible busy street (hotspots,
     * people walking by). Above that the score climbs; LIKELY once dozens of
     * brand-new BSSIDs appear in one window - which a real place cannot do. */
    int score = 0;
    if (arrivals > 8) score = (int)((arrivals - 8) * 4);  /* 8->0, 17->36 (ELEVATED), 26->72 (LIKELY) */
    uint8_t s = aegis_clamp_score(score);

    aegis_verdict_t v = aegis_verdict_of(s);
    if (out) {
        memset(out, 0, sizeof(*out));
        out->kind = AEGIS_KIND_BEACON_FLOOD;
        out->verdict = v;
        out->score = s;
        out->hits = arrivals;
        out->last_ms = now_ms;
        snprintf(out->label, sizeof(out->label), "%lu new APs/%us",
                 (unsigned long)arrivals, (unsigned)(BF_WINDOW_MS / 1000));
    }
    return v;
}
