/*
 * aegis_wifi80211.h - just enough 802.11 to feed the Wi-Fi detectors.
 *
 * The ESP32-S3 promiscuous callback hands us a raw 802.11 MAC frame (no
 * radiotap header) plus an rx_ctrl block with RSSI and channel. This header
 * parses only the fields the detectors need, defensively, from a length-checked
 * byte buffer. It has no ESP-IDF dependency - the on-device glue copies the
 * frame bytes + rssi + channel into these calls.
 */
#ifndef AEGIS_WIFI80211_H
#define AEGIS_WIFI80211_H

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Frame Control type/subtype (the two we care about live in "management"). */
#define WIFI_FTYPE_MGMT          0x0

/* Management subtypes */
#define WIFI_STYPE_ASSOC_REQ     0x0
#define WIFI_STYPE_PROBE_REQ     0x4
#define WIFI_STYPE_PROBE_RESP    0x5
#define WIFI_STYPE_BEACON        0x8
#define WIFI_STYPE_DISASSOC      0xA
#define WIFI_STYPE_AUTH          0xB
#define WIFI_STYPE_DEAUTH        0xC

/* Tagged parameter element IDs used in beacon / probe-response bodies. */
#define WIFI_EID_SSID            0
#define WIFI_EID_DS_PARAM        3    /* current channel                     */
#define WIFI_EID_RSN             48   /* WPA2/WPA3 robust security network   */
#define WIFI_EID_VENDOR          221  /* WPA1 lives here (Microsoft OUI)     */

/* A parsed management-frame view. Pointers/lengths reference into the caller's
 * buffer; nothing is copied except when the caller asks for the SSID. */
typedef struct {
    uint8_t  type;        /* WIFI_FTYPE_*                          */
    uint8_t  subtype;     /* WIFI_STYPE_*                          */
    uint8_t  addr1[6];    /* receiver / destination (FF.. = bcast) */
    uint8_t  addr2[6];    /* transmitter / source                  */
    uint8_t  addr3[6];    /* BSSID for most management frames      */
    uint16_t seq;         /* sequence number (12-bit)              */
    bool     valid;       /* false if the buffer was too short     */
} wifi_mgmt_t;

/* Parse the fixed 802.11 management header. Returns false (and sets valid=0)
 * if len is too small to contain a 24-byte MAC header. */
static inline bool wifi_parse_mgmt(const uint8_t *buf, uint16_t len, wifi_mgmt_t *out)
{
    memset(out, 0, sizeof(*out));
    if (!buf || len < 24) return false;
    uint16_t fc = (uint16_t)buf[0] | ((uint16_t)buf[1] << 8);
    out->type    = (uint8_t)((fc >> 2) & 0x3);
    out->subtype = (uint8_t)((fc >> 4) & 0xF);
    memcpy(out->addr1, buf + 4,  6);
    memcpy(out->addr2, buf + 10, 6);
    memcpy(out->addr3, buf + 16, 6);
    out->seq   = (uint16_t)(((buf[22] | (buf[23] << 8)) >> 4) & 0x0FFF);
    out->valid = true;
    return true;
}

static inline bool wifi_is_broadcast(const uint8_t mac[6])
{
    return (mac[0] & mac[1] & mac[2] & mac[3] & mac[4] & mac[5]) == 0xFF;
}

/* Deauth/disassoc carry a 2-byte reason code right after the 24-byte header. */
static inline uint16_t wifi_reason_code(const uint8_t *buf, uint16_t len)
{
    if (len < 26) return 0;
    return (uint16_t)buf[24] | ((uint16_t)buf[25] << 8);
}

/* Walk the tagged parameters of a beacon / probe-response body (which starts
 * 12 bytes after the 24-byte header: timestamp(8)+interval(2)+caps(2)) looking
 * for one element id. On hit, sets val + val_len into the buffer and returns
 * true. */
static inline bool wifi_find_eid(const uint8_t *buf, uint16_t len, uint8_t eid,
                                 const uint8_t **val, uint8_t *val_len)
{
    uint16_t p = 24 + 12;                 /* start of tagged params */
    while (p + 2 <= len) {
        uint8_t id  = buf[p];
        uint8_t l   = buf[p + 1];
        if (p + 2 + l > len) break;       /* malformed / truncated  */
        if (id == eid) {
            if (val)     *val     = buf + p + 2;
            if (val_len) *val_len = l;
            return true;
        }
        p += 2 + l;
    }
    return false;
}

/* Copy the SSID out of a beacon/probe-response into a NUL-terminated buffer of
 * size cap (<=33). Returns the SSID length (0 = hidden / wildcard). */
static inline uint8_t wifi_copy_ssid(const uint8_t *buf, uint16_t len,
                                     char *out, uint8_t cap)
{
    const uint8_t *v = NULL; uint8_t vl = 0;
    if (cap) out[0] = '\0';
    if (!wifi_find_eid(buf, len, WIFI_EID_SSID, &v, &vl)) return 0;
    if (vl > cap - 1) vl = cap - 1;
    for (uint8_t i = 0; i < vl; i++)
        out[i] = (v[i] >= 0x20 && v[i] < 0x7F) ? (char)v[i] : '.';
    out[vl] = '\0';
    return vl;
}

/* Channel advertised in the DS Parameter Set (0 if absent). */
static inline uint8_t wifi_beacon_channel(const uint8_t *buf, uint16_t len)
{
    const uint8_t *v = NULL; uint8_t vl = 0;
    if (wifi_find_eid(buf, len, WIFI_EID_DS_PARAM, &v, &vl) && vl >= 1)
        return v[0];
    return 0;
}

/* Coarse security class of a beacon: 0=open, 1=WPA(1) vendor, 2=RSN(WPA2/3).
 * Used by the evil-twin engine to flag an SSID that changes its lock. */
static inline uint8_t wifi_beacon_security(const uint8_t *buf, uint16_t len)
{
    if (wifi_find_eid(buf, len, WIFI_EID_RSN, NULL, NULL)) return 2;
    /* capability info bit 4 (privacy) at offset 24+10 hints WEP/WPA if no RSN */
    if (len >= 24 + 12) {
        uint16_t caps = (uint16_t)buf[24 + 10] | ((uint16_t)buf[24 + 11] << 8);
        if (caps & 0x0010) return 1;   /* privacy bit set, no RSN => WPA1/WEP */
    }
    return 0;
}

#ifdef __cplusplus
}
#endif
#endif /* AEGIS_WIFI80211_H */
