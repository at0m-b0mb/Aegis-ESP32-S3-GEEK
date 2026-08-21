/*
 * aegis_ble.h - parse BLE advertising data and classify tracker / spam adverts.
 *
 * The NimBLE observer glue on-device hands each advertising report to the
 * engine as {addr[6], rssi, adv[], adv_len, now}. This header walks the AD
 * structures ([len][type][data...]) and recognises the specific signatures the
 * two BLE detectors key on. No ESP-IDF dependency, so it is host-testable.
 *
 * Limitation stated honestly: Find My rotates its BLE address about every 15
 * minutes, so any address-keyed "how long has it followed me" measure is a
 * LOWER bound for Find My tags. Tile and SmartTag rotate far less, so they are
 * tracked more reliably. The engine never claims certainty it cannot have.
 */
#ifndef AEGIS_BLE_H
#define AEGIS_BLE_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* GAP AD types we use */
#define BLE_AD_UUID16_INC    0x02
#define BLE_AD_UUID16_CMPL   0x03
#define BLE_AD_NAME_CMPL     0x09
#define BLE_AD_SVC_DATA16    0x16
#define BLE_AD_MFG           0xFF

/* Company identifiers (little-endian in the packet) */
#define BLE_CID_APPLE        0x004C
#define BLE_CID_MICROSOFT    0x0006
#define BLE_CID_SAMSUNG      0x0075

/* 16-bit service UUIDs of interest */
#define BLE_UUID_TILE_OLD    0xFEED
#define BLE_UUID_TILE_NEW    0xFEEC
#define BLE_UUID_FASTPAIR    0xFE2C
#define BLE_UUID_SMARTTAG    0xFD5A

/* Apple Continuity message types (first byte after the company id) */
#define APPLE_TYPE_PROX_PAIR 0x07   /* AirPods-style proximity pairing */
#define APPLE_TYPE_NEARBY_ACT 0x0F  /* "nearby action" pop-ups         */
#define APPLE_TYPE_FINDMY    0x12   /* offline finding (AirTag/Find My)*/

typedef enum {
    BLE_TRK_NONE = 0,
    BLE_TRK_FINDMY,     /* Apple Find My network tag (AirTag / 3rd party) */
    BLE_TRK_TILE,
    BLE_TRK_SMARTTAG,   /* Samsung Galaxy SmartTag */
} ble_tracker_t;

typedef enum {
    BLE_SPAM_NONE = 0,
    BLE_SPAM_APPLE,     /* Continuity proximity/nearby-action pop-up */
    BLE_SPAM_FASTPAIR,  /* Google Fast Pair                          */
    BLE_SPAM_SWIFTPAIR, /* Microsoft Swift Pair                      */
} ble_spam_t;

/* Find an AD structure by type. On hit sets val + vlen into the buffer. */
static inline bool ble_ad_find(const uint8_t *adv, uint8_t len, uint8_t adtype,
                               const uint8_t **val, uint8_t *vlen)
{
    uint8_t p = 0;
    while (p + 1 < len) {
        uint8_t l = adv[p];
        if (l == 0) break;
        if (p + 1 + l > len) break;    /* truncated */
        uint8_t t = adv[p + 1];
        if (t == adtype) {
            if (val)  *val  = adv + p + 2;
            if (vlen) *vlen = (uint8_t)(l - 1);
            return true;
        }
        p += l + 1;
    }
    return false;
}

/* Manufacturer company id (0 if no manufacturer AD). */
static inline uint16_t ble_company_id(const uint8_t *adv, uint8_t len)
{
    const uint8_t *v; uint8_t vl;
    if (ble_ad_find(adv, len, BLE_AD_MFG, &v, &vl) && vl >= 2)
        return (uint16_t)v[0] | ((uint16_t)v[1] << 8);
    return 0;
}

/* True if a 16-bit service UUID (in a UUID list or service-data AD) matches. */
static inline bool ble_has_uuid16(const uint8_t *adv, uint8_t len, uint16_t uuid)
{
    const uint8_t *v; uint8_t vl;
    for (uint8_t adt = BLE_AD_UUID16_INC; adt <= BLE_AD_UUID16_CMPL; adt++) {
        if (ble_ad_find(adv, len, adt, &v, &vl)) {
            for (uint8_t i = 0; i + 1 < vl; i += 2)
                if (((uint16_t)v[i] | ((uint16_t)v[i + 1] << 8)) == uuid) return true;
        }
    }
    if (ble_ad_find(adv, len, BLE_AD_SVC_DATA16, &v, &vl) && vl >= 2)
        if (((uint16_t)v[0] | ((uint16_t)v[1] << 8)) == uuid) return true;
    return false;
}

static inline ble_tracker_t ble_classify_tracker(const uint8_t *adv, uint8_t len)
{
    const uint8_t *v; uint8_t vl;
    if (ble_company_id(adv, len) == BLE_CID_APPLE &&
        ble_ad_find(adv, len, BLE_AD_MFG, &v, &vl) && vl >= 3 &&
        v[2] == APPLE_TYPE_FINDMY)
        return BLE_TRK_FINDMY;
    if (ble_has_uuid16(adv, len, BLE_UUID_TILE_OLD) ||
        ble_has_uuid16(adv, len, BLE_UUID_TILE_NEW))
        return BLE_TRK_TILE;
    if (ble_has_uuid16(adv, len, BLE_UUID_SMARTTAG) ||
        ble_company_id(adv, len) == BLE_CID_SAMSUNG)
        return BLE_TRK_SMARTTAG;
    return BLE_TRK_NONE;
}

static inline ble_spam_t ble_classify_spam(const uint8_t *adv, uint8_t len)
{
    const uint8_t *v; uint8_t vl;
    if (ble_company_id(adv, len) == BLE_CID_APPLE &&
        ble_ad_find(adv, len, BLE_AD_MFG, &v, &vl) && vl >= 3 &&
        (v[2] == APPLE_TYPE_PROX_PAIR || v[2] == APPLE_TYPE_NEARBY_ACT))
        return BLE_SPAM_APPLE;
    if (ble_has_uuid16(adv, len, BLE_UUID_FASTPAIR))
        return BLE_SPAM_FASTPAIR;
    if (ble_company_id(adv, len) == BLE_CID_MICROSOFT)
        return BLE_SPAM_SWIFTPAIR;
    return BLE_SPAM_NONE;
}

static inline const char *ble_tracker_name(ble_tracker_t t)
{
    switch (t) {
        case BLE_TRK_FINDMY:   return "Find My tag";
        case BLE_TRK_TILE:     return "Tile";
        case BLE_TRK_SMARTTAG: return "SmartTag";
        default:               return "-";
    }
}

static inline const char *ble_spam_name(ble_spam_t s)
{
    switch (s) {
        case BLE_SPAM_APPLE:     return "Apple pair-spam";
        case BLE_SPAM_FASTPAIR:  return "Fast Pair spam";
        case BLE_SPAM_SWIFTPAIR: return "Swift Pair spam";
        default:                 return "-";
    }
}

#ifdef __cplusplus
}
#endif
#endif /* AEGIS_BLE_H */
