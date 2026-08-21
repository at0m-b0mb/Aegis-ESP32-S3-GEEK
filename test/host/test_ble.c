#include "aegis_test.h"
#include "frame_builder.h"
#include "ble_threat.h"

TEST_MAIN_BEGIN
    SUITE("ble tracker: a Tile lingering with you for minutes -> alarm");
    {
        ble_engine_t e; ble_reset(&e); aegis_finding_t o;
        uint8_t adv[32]; uint8_t n = ad_svc16(adv, BLE_UUID_TILE_OLD);
        uint8_t addr[6] = {0x11,0,0,0,0,0x01};
        for (int i = 0; i < 20; i++) ble_feed(&e, addr, -55, adv, n, 1000 + i * 8000);
        aegis_verdict_t v = ble_eval_tracker(&e, 1000 + 20 * 8000, &o);
        CHECK(v >= AEGIS_ELEVATED, "a persistent Tile should alarm, got %s (%u)",
              aegis_verdict_str(v), o.score);
        CHECK(o.kind == AEGIS_KIND_BLE_TRACKER, "kind should be tracker");
    }

    SUITE("ble tracker: a single glimpse is NOT a stalker");
    {
        ble_engine_t e; ble_reset(&e); aegis_finding_t o;
        uint8_t adv[32]; uint8_t n = ad_svc16(adv, BLE_UUID_TILE_OLD);
        uint8_t addr[6] = {0x11,0,0,0,0,0x02};
        ble_feed(&e, addr, -55, adv, n, 1000);
        CHECK(ble_eval_tracker(&e, 1100, &o) == AEGIS_CLEAR, "one sighting must be CLEAR");
    }

    SUITE("ble spam: many distinct addresses pairing-spamming -> LIKELY");
    {
        ble_engine_t e; ble_reset(&e); aegis_finding_t o;
        uint8_t adv[32]; uint8_t n = ad_apple(adv, APPLE_TYPE_NEARBY_ACT, 0xAB);
        for (int i = 0; i < 12; i++) {
            uint8_t addr[6] = {0x40,0,0,0,(uint8_t)(i>>8),(uint8_t)i};  /* randomised src */
            ble_feed(&e, addr, -40, adv, n, 1000 + i * 100);
        }
        aegis_verdict_t v = ble_eval_spam(&e, 2200, &o);
        CHECK(v == AEGIS_LIKELY, "12 distinct pair-spammers should be LIKELY, got %s (%u)",
              aegis_verdict_str(v), o.hits);
    }

    SUITE("ble spam: two legit nearby devices are CLEAR");
    {
        ble_engine_t e; ble_reset(&e); aegis_finding_t o;
        uint8_t adv[32]; uint8_t n = ad_svc16(adv, BLE_UUID_FASTPAIR);
        uint8_t a1[6] = {0x50,0,0,0,0,1}, a2[6] = {0x50,0,0,0,0,2};
        for (int i = 0; i < 5; i++) { ble_feed(&e, a1, -40, adv, n, 1000 + i*200);
                                      ble_feed(&e, a2, -45, adv, n, 1000 + i*200); }
        CHECK(ble_eval_spam(&e, 2000, &o) == AEGIS_CLEAR, "2 devices must be CLEAR");
    }
TEST_MAIN_END
