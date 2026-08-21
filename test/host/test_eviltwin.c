#include "aegis_test.h"
#include "frame_builder.h"
#include "eviltwin_detect.h"

static const uint8_t AP1[6] = {0x02,0x00,0x00,0x00,0x00,0x01};
static const uint8_t AP2[6] = {0x02,0x00,0x00,0x00,0x00,0x02};

TEST_MAIN_BEGIN
    SUITE("eviltwin: single AP per SSID is CLEAR");
    {
        eviltwin_engine_t e; eviltwin_reset(&e); aegis_finding_t o;
        uint8_t f[128]; uint16_t n = mk_beacon(f, AP1, "HomeNet", 6, 2);
        eviltwin_feed(&e, f, n, -40, 1000);
        CHECK(eviltwin_eval(&e, 1100, &o) == AEGIS_CLEAR, "1 AP must be CLEAR");
    }

    SUITE("eviltwin: two BSSIDs same security -> only ELEVATED (legit roaming)");
    {
        eviltwin_engine_t e; eviltwin_reset(&e); aegis_finding_t o;
        uint8_t f[128];
        uint16_t n = mk_beacon(f, AP1, "CorpWiFi", 6, 2); eviltwin_feed(&e, f, n, -40, 1000);
        n = mk_beacon(f, AP2, "CorpWiFi", 11, 2);         eviltwin_feed(&e, f, n, -50, 1000);
        aegis_verdict_t v = eviltwin_eval(&e, 1100, &o);
        CHECK(v == AEGIS_ELEVATED, "dup BSSID same-sec should be ELEVATED not LIKELY, got %s",
              aegis_verdict_str(v));
    }

    SUITE("eviltwin: same SSID, open clone of a WPA2 net -> LIKELY");
    {
        eviltwin_engine_t e; eviltwin_reset(&e); aegis_finding_t o;
        uint8_t f[128];
        uint16_t n = mk_beacon(f, AP1, "CorpWiFi", 6, 2); eviltwin_feed(&e, f, n, -40, 1000);
        n = mk_beacon(f, AP2, "CorpWiFi", 6, 0);          eviltwin_feed(&e, f, n, -35, 1000);
        aegis_verdict_t v = eviltwin_eval(&e, 1100, &o);
        CHECK(v == AEGIS_LIKELY, "security-class conflict should be LIKELY, got %s (%u)",
              aegis_verdict_str(v), o.score);
        CHECK(strcmp(o.label, "CorpWiFi") == 0, "finding should name the SSID");
    }

    SUITE("eviltwin: baseline lock flags a NEW impersonating BSSID");
    {
        eviltwin_engine_t e; eviltwin_reset(&e); aegis_finding_t o;
        uint8_t f[128];
        uint16_t n = mk_beacon(f, AP1, "MyHome", 6, 2); eviltwin_feed(&e, f, n, -40, 1000);
        eviltwin_lock_baseline(&e);
        n = mk_beacon(f, AP2, "MyHome", 6, 2);          eviltwin_feed(&e, f, n, -30, 2000);
        aegis_verdict_t v = eviltwin_eval(&e, 2100, &o);
        CHECK(v == AEGIS_LIKELY, "new BSSID for a locked SSID should be LIKELY, got %s",
              aegis_verdict_str(v));
        CHECK(memcmp(o.mac, AP2, 6) == 0, "offender should be the new BSSID");
    }
TEST_MAIN_END
