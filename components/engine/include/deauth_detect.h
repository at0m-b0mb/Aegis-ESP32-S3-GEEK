/*
 * deauth_detect.h - 802.11 deauthentication / disassociation flood detector.
 *
 * A deauth frame is legitimate: APs use it for roaming and load balancing. So a
 * few are normal and MUST NOT alarm. The attack signature is a sustained RATE,
 * especially deauths addressed to the broadcast address (one attacker kicking
 * every client of a network at once) and/or reason code 7. This engine scores
 * the rate inside a sliding window and never alarms on a lone frame.
 */
#ifndef DEAUTH_DETECT_H
#define DEAUTH_DETECT_H

#include "aegis_threat.h"
#include "aegis_wifi80211.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DEAUTH_WINDOW_MS     3000u   /* rate is measured over this window   */
#define DEAUTH_RING          256u    /* max events remembered in the window */

typedef struct {
    uint32_t t_ms;
    uint8_t  bssid[6];
    uint8_t  weight;      /* broadcast/reason-7 frames count for more */
} deauth_evt_t;

typedef struct {
    deauth_evt_t ring[DEAUTH_RING];
    uint16_t     head;        /* next write slot                          */
    uint16_t     count;       /* live entries (<= DEAUTH_RING)            */
    /* rolling picture of the worst offender in the current window */
    uint8_t      top_bssid[6];
    uint32_t     top_hits;
    uint32_t     first_ms;    /* when the current episode crossed ELEVATED*/
} deauth_engine_t;

void deauth_reset(deauth_engine_t *e);

/* Feed one parsed management frame. Non-deauth/disassoc frames are ignored, so
 * the on-device glue can pass every management frame through. reason is from
 * wifi_reason_code(); rssi/channel are informational for the finding. now_ms is
 * a monotonic millisecond clock supplied by the caller. */
void deauth_feed(deauth_engine_t *e, const wifi_mgmt_t *m, uint16_t reason,
                 int8_t rssi, uint8_t channel, uint32_t now_ms);

/* Evaluate the current window into a finding. Safe to call every UI tick.
 * Returns the verdict; fills *out when non-NULL. */
aegis_verdict_t deauth_eval(deauth_engine_t *e, uint32_t now_ms,
                            aegis_finding_t *out);

#ifdef __cplusplus
}
#endif
#endif /* DEAUTH_DETECT_H */
