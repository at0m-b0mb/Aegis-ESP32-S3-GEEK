/*
 * aegis_threat.h - shared threat vocabulary for the Aegis detection engines.
 *
 * Every engine in components/engine speaks this language. The engines are pure
 * C with NO ESP-IDF dependency so they compile and run on a host (see
 * test/host). Time is always passed in from the caller as a millisecond
 * counter; an engine never reads a clock itself. That is what makes the
 * detectors deterministic and unit-testable.
 *
 * Honesty rules (inherited from the Flipper detector line - Argus, Bulwark,
 * Faraday, ...):
 *   - A passive listener can prove the PRESENCE of an attack signature. It can
 *     never prove ABSENCE. So there is no "SAFE" verdict. The best we say is
 *     AEGIS_CLEAR, which means "no signature seen in the window", not "safe".
 *   - Confidence is a curve with a floor, not a switch. A couple of deauth
 *     frames is normal roaming; a verdict only climbs to LIKELY on a sustained,
 *     structured signal. Each engine documents its own floor.
 */
#ifndef AEGIS_THREAT_H
#define AEGIS_THREAT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Rising confidence. Deliberately no "SAFE" / "CONFIRMED" member: a passive
 * receiver earns neither. */
typedef enum {
    AEGIS_CLEAR    = 0,  /* nothing matching a signature in the current window */
    AEGIS_ELEVATED = 1,  /* a signature is forming - watch, do not yet cry wolf */
    AEGIS_LIKELY   = 2,  /* a structured attack signature is sustained          */
} aegis_verdict_t;

/* The families of threat Aegis can name. Kept small and specific. */
typedef enum {
    AEGIS_KIND_NONE = 0,
    AEGIS_KIND_DEAUTH_FLOOD,   /* 802.11 deauth/disassoc denial of service      */
    AEGIS_KIND_EVIL_TWIN,      /* one SSID advertised by conflicting APs         */
    AEGIS_KIND_BEACON_FLOOD,   /* a storm of fabricated APs (mdk3/mdk4)          */
    AEGIS_KIND_BLE_TRACKER,    /* a Find My / Tile / SmartTag style tag lingering*/
    AEGIS_KIND_BLE_SPAM,       /* BLE advertising popup-spam flood               */
    AEGIS_KIND__COUNT
} aegis_kind_t;

/* Confidence is 0..100. These thresholds map a score to a verdict. The ceiling
 * of 96 is deliberate: a passive detector never reaches 100. */
#define AEGIS_SCORE_MAX        96
#define AEGIS_ELEVATED_AT      35
#define AEGIS_LIKELY_AT        70

/* One reportable finding. Small and flat so it copies cheaply into a UI row or
 * an SD log line. MACs are raw 6-byte; the UI formats them. */
typedef struct {
    aegis_kind_t    kind;
    aegis_verdict_t verdict;
    uint8_t         score;      /* 0..AEGIS_SCORE_MAX                        */
    uint8_t         mac[6];     /* primary offender (BSSID or BLE addr)      */
    int8_t          rssi;       /* last dBm, or 0 if not meaningful          */
    uint8_t         channel;    /* Wi-Fi channel, or 0 for BLE              */
    char            label[33];  /* SSID or short human tag, NUL-terminated  */
    uint32_t        first_ms;   /* when this finding first crossed ELEVATED */
    uint32_t        last_ms;    /* most recent supporting evidence          */
    uint32_t        hits;       /* supporting frames/adverts counted        */
} aegis_finding_t;

/* Map a raw 0..100 score to a verdict using the shared thresholds. */
static inline aegis_verdict_t aegis_verdict_of(uint8_t score)
{
    if (score >= AEGIS_LIKELY_AT)   return AEGIS_LIKELY;
    if (score >= AEGIS_ELEVATED_AT) return AEGIS_ELEVATED;
    return AEGIS_CLEAR;
}

static inline const char *aegis_verdict_str(aegis_verdict_t v)
{
    switch (v) {
        case AEGIS_LIKELY:   return "LIKELY";
        case AEGIS_ELEVATED: return "ELEVATED";
        default:             return "CLEAR";
    }
}

static inline const char *aegis_kind_str(aegis_kind_t k)
{
    switch (k) {
        case AEGIS_KIND_DEAUTH_FLOOD: return "DEAUTH FLOOD";
        case AEGIS_KIND_EVIL_TWIN:    return "EVIL TWIN";
        case AEGIS_KIND_BEACON_FLOOD: return "BEACON FLOOD";
        case AEGIS_KIND_BLE_TRACKER:  return "BLE TRACKER";
        case AEGIS_KIND_BLE_SPAM:     return "BLE SPAM";
        default:                      return "-";
    }
}

/* clamp helper shared by the engines */
static inline uint8_t aegis_clamp_score(int s)
{
    if (s < 0)                return 0;
    if (s > AEGIS_SCORE_MAX)  return AEGIS_SCORE_MAX;
    return (uint8_t)s;
}


/* Format a 6-byte MAC as AA:BB:CC:DD:EE:FF into a caller buffer (needs >=18). */
static inline void aegis_mac_str(char *out, size_t cap, const uint8_t mac[6])
{
    snprintf(out, cap, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

#ifdef __cplusplus
}
#endif
#endif /* AEGIS_THREAT_H */
