/*
 * ble_threat.h - two BLE detectors sharing one observer feed.
 *
 * TRACKER: a tracker being merely present is not a threat - your own earbuds
 *   and phone speak Find My. The threat is one that FOLLOWS: the same tag seen
 *   again and again over a long span. We score dwell-span x sightings, with an
 *   honest ceiling because address rotation hides part of the truth.
 *
 * SPAM: BLE pop-up spam tools randomise the source address every packet, so the
 *   signature is not one loud device but an EXPLOSION of distinct addresses all
 *   carrying a pairing-type advert in a short window. We count distinct pairing
 *   advertisers, not raw packets.
 */
#ifndef BLE_THREAT_H
#define BLE_THREAT_H

#include "aegis_threat.h"
#include "aegis_ble.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BLE_TRK_TABLE     32u
#define BLE_TRK_DWELL_MS  120000u   /* 2 min of following starts to matter   */
#define BLE_SPAM_TABLE    64u
#define BLE_SPAM_WINDOW_MS 4000u

typedef struct {
    uint8_t       addr[6];
    ble_tracker_t family;
    uint32_t      first_ms;
    uint32_t      last_ms;
    uint32_t      hits;
    int8_t        rssi;
    bool          used;
} ble_trk_entry_t;

typedef struct {
    uint8_t   addr[6];
    ble_spam_t kind;
    uint32_t  t_ms;
    bool      used;
} ble_spam_entry_t;

typedef struct {
    ble_trk_entry_t  trk[BLE_TRK_TABLE];
    ble_spam_entry_t spam[BLE_SPAM_TABLE];
    uint16_t         spam_head;
} ble_engine_t;

void ble_reset(ble_engine_t *e);

/* Feed one advertising report. addr is the 6-byte advertiser address. */
void ble_feed(ble_engine_t *e, const uint8_t addr[6], int8_t rssi,
              const uint8_t *adv, uint8_t adv_len, uint32_t now_ms);

aegis_verdict_t ble_eval_tracker(ble_engine_t *e, uint32_t now_ms,
                                 aegis_finding_t *out);
aegis_verdict_t ble_eval_spam(ble_engine_t *e, uint32_t now_ms,
                              aegis_finding_t *out);

#ifdef __cplusplus
}
#endif
#endif /* BLE_THREAT_H */
