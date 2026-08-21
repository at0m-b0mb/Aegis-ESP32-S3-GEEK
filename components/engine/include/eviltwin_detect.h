/*
 * eviltwin_detect.h - detect one SSID advertised by conflicting access points.
 *
 * Honesty is the whole game here. A single SSID legitimately coming from many
 * BSSIDs is *normal* - every enterprise/mesh network roams that way. So seeing
 * two BSSIDs for one SSID is at most ELEVATED. What actually distinguishes an
 * evil twin is a CONTRADICTION the real network would never produce:
 *   - the same SSID offered with a different security class (open clone of a
 *     WPA2 network is the classic captive-portal twin), or
 *   - a new BSSID impersonating an SSID you locked as your trusted baseline.
 * Only those cross into LIKELY.
 */
#ifndef EVILTWIN_DETECT_H
#define EVILTWIN_DETECT_H

#include "aegis_threat.h"
#include "aegis_wifi80211.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ET_MAX_SSID          24
#define ET_MAX_AP_PER_SSID   6

typedef struct {
    uint8_t  bssid[6];
    uint8_t  channel;
    uint8_t  security;   /* 0 open, 1 wpa1/wep, 2 rsn (wpa2/3) */
    int8_t   rssi;
    uint32_t last_ms;
    bool     trusted;    /* set when the environment was locked as baseline */
} et_ap_t;

typedef struct {
    char    ssid[33];
    uint8_t nap;
    et_ap_t aps[ET_MAX_AP_PER_SSID];
} et_ssid_t;

typedef struct {
    et_ssid_t tbl[ET_MAX_SSID];
    uint8_t   n;
    bool      baseline_locked;
} eviltwin_engine_t;

void eviltwin_reset(eviltwin_engine_t *e);

/* Feed a raw beacon / probe-response frame buffer (the engine parses SSID,
 * channel, security and BSSID itself). Non-beacon frames are ignored. */
void eviltwin_feed(eviltwin_engine_t *e, const uint8_t *buf, uint16_t len,
                   int8_t rssi, uint32_t now_ms);

/* Freeze the currently-seen APs as the trusted baseline. After this, any NEW
 * BSSID appearing for one of these SSIDs is treated as an impersonator. */
void eviltwin_lock_baseline(eviltwin_engine_t *e);
/* Disarm the baseline: forget trusted marks so the field can be re-learned. */
void eviltwin_clear_baseline(eviltwin_engine_t *e);

aegis_verdict_t eviltwin_eval(eviltwin_engine_t *e, uint32_t now_ms,
                              aegis_finding_t *out);

#ifdef __cplusplus
}
#endif
#endif /* EVILTWIN_DETECT_H */
