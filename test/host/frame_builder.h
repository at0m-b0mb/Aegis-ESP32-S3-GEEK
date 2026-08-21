/* Synthetic 802.11 frame builders for host tests. */
#ifndef FRAME_BUILDER_H
#define FRAME_BUILDER_H
#include <stdint.h>
#include <string.h>

/* Build a management frame header into buf. Returns length written (24).
 * subtype is WIFI_STYPE_*. a1/a2/a3 are 6-byte MACs (NULL => zeros). */
static inline uint16_t mk_mgmt(uint8_t *buf, uint8_t subtype,
                        const uint8_t *a1, const uint8_t *a2, const uint8_t *a3,
                        uint16_t seq)
{
    memset(buf, 0, 24);
    uint16_t fc = (uint16_t)((0x0 << 2) | (subtype << 4)); /* type=mgmt(0) */
    buf[0] = fc & 0xFF; buf[1] = (fc >> 8) & 0xFF;
    if (a1) memcpy(buf + 4, a1, 6);
    if (a2) memcpy(buf + 10, a2, 6);
    if (a3) memcpy(buf + 16, a3, 6);
    buf[22] = (uint8_t)((seq << 4) & 0xFF);
    buf[23] = (uint8_t)((seq >> 4) & 0xFF);
    return 24;
}

/* Append a deauth/disassoc reason code (2 bytes). Returns new length. */
static inline uint16_t mk_reason(uint8_t *buf, uint16_t len, uint16_t reason)
{
    buf[len] = reason & 0xFF; buf[len + 1] = (reason >> 8) & 0xFF;
    return len + 2;
}

/* Build a beacon: header(24) + fixed params(12) + SSID tag + DS(channel) +
 * optional RSN tag. Returns total length. sec: 0=open,2=RSN. */
static inline uint16_t mk_beacon(uint8_t *buf, const uint8_t *bssid,
                          const char *ssid, uint8_t channel, uint8_t sec)
{
    uint16_t n = mk_mgmt(buf, 0x8 /*beacon*/, NULL, bssid, bssid, 1);
    memset(buf + n, 0, 12);            /* timestamp(8)+interval(2)+caps(2) */
    if (sec) { buf[n + 10] |= 0x10; }  /* privacy bit in caps              */
    n += 12;
    uint8_t sl = (uint8_t)strlen(ssid);
    buf[n++] = 0; buf[n++] = sl; memcpy(buf + n, ssid, sl); n += sl;   /* SSID */
    buf[n++] = 3; buf[n++] = 1; buf[n++] = channel;                    /* DS   */
    if (sec == 2) { buf[n++] = 48; buf[n++] = 2; buf[n++] = 0x01; buf[n++] = 0x00; }
    return n;
}
#endif

/* ---- BLE advertising-data builders (append AD structures) ---- */
static inline uint8_t ad_put(uint8_t *adv, uint8_t n, uint8_t type,
                             const uint8_t *data, uint8_t dlen)
{
    adv[n++] = (uint8_t)(dlen + 1);   /* length covers type + data */
    adv[n++] = type;
    if (data && dlen) { memcpy(adv + n, data, dlen); n += dlen; }
    return n;
}
/* Apple manufacturer advert with a given Continuity type byte + filler. */
static inline uint8_t ad_apple(uint8_t *adv, uint8_t apple_type, uint8_t fill)
{
    uint8_t body[24]; body[0] = 0x4C; body[1] = 0x00; body[2] = apple_type;
    for (int i = 3; i < 20; i++) body[i] = fill;
    return ad_put(adv, 0, 0xFF /*MFG*/, body, 20);
}
/* 16-bit service-data advert (e.g. Tile 0xFEED, Fast Pair 0xFE2C). */
static inline uint8_t ad_svc16(uint8_t *adv, uint16_t uuid)
{
    uint8_t body[4] = { (uint8_t)(uuid & 0xFF), (uint8_t)(uuid >> 8), 0x01, 0x02 };
    return ad_put(adv, 0, 0x16 /*SVC_DATA16*/, body, 4);
}
