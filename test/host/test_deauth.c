#include "aegis_test.h"
#include "frame_builder.h"
#include "deauth_detect.h"

static const uint8_t AP[6]   = {0x02,0xAA,0xBB,0xCC,0xDD,0xEE};
static const uint8_t STA[6]  = {0x02,0x11,0x22,0x33,0x44,0x55};
static const uint8_t BCAST[6]= {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

static void feed_deauth(deauth_engine_t *e, const uint8_t *a1, const uint8_t *bssid,
                        uint16_t reason, uint32_t t)
{
    uint8_t f[64];
    uint16_t n = mk_mgmt(f, WIFI_STYPE_DEAUTH, a1, bssid, bssid, 1);
    n = mk_reason(f, n, reason);
    wifi_mgmt_t m; wifi_parse_mgmt(f, n, &m);
    deauth_feed(e, &m, wifi_reason_code(f, n), -40, 6, t);
}

TEST_MAIN_BEGIN
    SUITE("deauth: roaming floor - a few targeted deauths stay CLEAR");
    {
        deauth_engine_t e; deauth_reset(&e);
        aegis_finding_t out;
        for (int i = 0; i < 3; i++) feed_deauth(&e, STA, AP, 3, 1000 + i * 200);
        aegis_verdict_t v = deauth_eval(&e, 1600, &out);
        CHECK(v == AEGIS_CLEAR, "3 targeted deauths should be CLEAR, got %s (score %u)",
              aegis_verdict_str(v), out.score);
    }

    SUITE("deauth: broadcast flood crosses LIKELY");
    {
        deauth_engine_t e; deauth_reset(&e);
        aegis_finding_t out;
        for (int i = 0; i < 12; i++) feed_deauth(&e, BCAST, AP, 7, 1000 + i * 50);
        aegis_verdict_t v = deauth_eval(&e, 1600, &out);
        CHECK(v == AEGIS_LIKELY, "broadcast flood should be LIKELY, got %s (score %u)",
              aegis_verdict_str(v), out.score);
        CHECK(memcmp(out.mac, AP, 6) == 0, "offender BSSID should be the AP");
        CHECK(out.kind == AEGIS_KIND_DEAUTH_FLOOD, "kind should be deauth flood");
    }

    SUITE("deauth: window slides - old flood expires back to CLEAR");
    {
        deauth_engine_t e; deauth_reset(&e);
        aegis_finding_t out;
        for (int i = 0; i < 12; i++) feed_deauth(&e, BCAST, AP, 7, 1000 + i * 50);
        (void)deauth_eval(&e, 1600, &out);
        aegis_verdict_t v = deauth_eval(&e, 1600 + 5000, &out); /* 5s later */
        CHECK(v == AEGIS_CLEAR, "flood should expire after the window, got %s",
              aegis_verdict_str(v));
    }

    SUITE("deauth: non-deauth mgmt frames are ignored");
    {
        deauth_engine_t e; deauth_reset(&e);
        aegis_finding_t out;
        uint8_t f[128];
        uint16_t n = mk_beacon(f, AP, "CoffeeShop", 6, 2);
        wifi_mgmt_t m; wifi_parse_mgmt(f, n, &m);
        for (int i = 0; i < 30; i++) deauth_feed(&e, &m, 0, -50, 6, 1000 + i * 20);
        CHECK(deauth_eval(&e, 1700, &out) == AEGIS_CLEAR, "beacons must not trip deauth");
    }
TEST_MAIN_END
