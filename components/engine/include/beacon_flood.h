/*
 * beacon_flood.h - detect a storm of fabricated access points (mdk3/mdk4).
 *
 * The robust signature is not "many APs" (a dense office legitimately has 40+).
 * It is the ARRIVAL RATE of never-before-seen BSSIDs. In a real environment new
 * APs appear a few at a time as people and phone-hotspots wander past. A beacon
 * flood injects dozens of brand-new (often sequential or random) BSSIDs per
 * second. So we score how many DISTINCT BSSIDs first appeared inside the recent
 * window, not the raw total - that stays quiet in a merely-busy place.
 */
#ifndef BEACON_FLOOD_H
#define BEACON_FLOOD_H

#include "aegis_threat.h"
#include "aegis_wifi80211.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BF_TABLE        192u     /* BSSIDs remembered (LRU-evicted)        */
#define BF_WINDOW_MS    5000u    /* "new arrivals" are counted over this   */

typedef struct {
    uint8_t  bssid[6];
    uint32_t first_ms;
    uint32_t last_ms;
    bool     used;
} bf_ap_t;

typedef struct {
    bf_ap_t  tbl[BF_TABLE];
    uint16_t n;
} beacon_flood_engine_t;

void beacon_flood_reset(beacon_flood_engine_t *e);

/* Feed a raw beacon frame buffer. Non-beacon frames are ignored. */
void beacon_flood_feed(beacon_flood_engine_t *e, const uint8_t *buf,
                       uint16_t len, uint32_t now_ms);

aegis_verdict_t beacon_flood_eval(beacon_flood_engine_t *e, uint32_t now_ms,
                                  aegis_finding_t *out);

#ifdef __cplusplus
}
#endif
#endif /* BEACON_FLOOD_H */
