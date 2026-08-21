#include "aegis_test.h"
#include "frame_builder.h"
#include "beacon_flood.h"

TEST_MAIN_BEGIN
    SUITE("beacon flood: a handful of real APs stays CLEAR");
    {
        beacon_flood_engine_t e; beacon_flood_reset(&e); aegis_finding_t o;
        uint8_t f[128];
        for (int i = 0; i < 6; i++) {
            uint8_t bssid[6] = {0x02,0,0,0,0,(uint8_t)i};
            char ssid[16]; snprintf(ssid, sizeof(ssid), "AP_%d", i);
            uint16_t n = mk_beacon(f, bssid, ssid, 6, 2);
            beacon_flood_feed(&e, f, n, 1000 + i * 100);
        }
        CHECK(beacon_flood_eval(&e, 1700, &o) == AEGIS_CLEAR, "6 APs must be CLEAR");
    }

    SUITE("beacon flood: 30 brand-new BSSIDs in-window -> LIKELY");
    {
        beacon_flood_engine_t e; beacon_flood_reset(&e); aegis_finding_t o;
        uint8_t f[128];
        for (int i = 0; i < 30; i++) {
            uint8_t bssid[6] = {0x02,0,0,0,(uint8_t)(i>>8),(uint8_t)i};
            uint16_t n = mk_beacon(f, bssid, "x", 6, 0);
            beacon_flood_feed(&e, f, n, 1000 + i * 20);
        }
        aegis_verdict_t v = beacon_flood_eval(&e, 1700, &o);
        CHECK(v == AEGIS_LIKELY, "30 new BSSIDs should be LIKELY, got %s (hits %u)",
              aegis_verdict_str(v), o.hits);
    }

    SUITE("beacon flood: repeats of the same APs do NOT inflate the count");
    {
        beacon_flood_engine_t e; beacon_flood_reset(&e); aegis_finding_t o;
        uint8_t f[128];
        for (int rep = 0; rep < 20; rep++)
            for (int i = 0; i < 5; i++) {
                uint8_t bssid[6] = {0x02,0,0,0,0,(uint8_t)i};
                uint16_t n = mk_beacon(f, bssid, "stable", 6, 2);
                beacon_flood_feed(&e, f, n, 1000 + rep * 50);
            }
        CHECK(beacon_flood_eval(&e, 2000, &o) == AEGIS_CLEAR,
              "5 APs beaconing repeatedly must stay CLEAR (got %u new)", o.hits);
    }
TEST_MAIN_END
