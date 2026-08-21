#include "aegis_test.h"
#include "ui.h"
#include <string.h>

static uint16_t g_buf[240 * 135];

static void set_slot(ui_state_t *st, ui_slot_t s, aegis_verdict_t v, uint8_t score,
                     const char *label)
{
    st->f[s].verdict = v;
    st->f[s].score = score;
    strncpy(st->f[s].label, label, sizeof(st->f[s].label) - 1);
}

static bool has_color(const canvas_t *cv, uint16_t c)
{
    for (int i = 0; i < cv->w * cv->h; i++) if (cv->px[i] == c) return true;
    return false;
}

TEST_MAIN_BEGIN
    canvas_t cv; cv_init(&cv, g_buf, 240, 135);

    SUITE("ui: all-clear frame fits the panel and shows no red");
    {
        ui_state_t st; memset(&st, 0, sizeof(st));
        st.wifi_ok = st.ble_ok = true;
        for (int i = 0; i < UI_SLOT_COUNT; i++) set_slot(&st,(ui_slot_t)i,AEGIS_CLEAR,0,"-");
        ui_render(&cv, &st);
        CHECK(cv.oob == 0, "all-clear layout must not draw off-panel, oob=%u", cv.oob);
        CHECK(!has_color(&cv, CV_LIKELY), "a clear airspace shows no LIKELY red");
        CHECK(ui_worst(&st) == AEGIS_CLEAR, "worst of all-clear is CLEAR");
    }

    SUITE("ui: a LIKELY finding tints the header and paints red");
    {
        ui_state_t st; memset(&st, 0, sizeof(st));
        st.wifi_ok = st.ble_ok = true;
        for (int i = 0; i < UI_SLOT_COUNT; i++) set_slot(&st,(ui_slot_t)i,AEGIS_CLEAR,0,"-");
        set_slot(&st, UI_SLOT_DEAUTH, AEGIS_LIKELY, 88, "AA:BB:CC:DD:EE:FF");
        st.sweep_deg = 120;
        ui_render(&cv, &st);
        CHECK(cv.oob == 0, "under-attack layout must not draw off-panel, oob=%u", cv.oob);
        CHECK(ui_worst(&st) == AEGIS_LIKELY, "worst is LIKELY");
        CHECK(g_buf[16 * 240 + 120] == CV_LIKELY, "header underline is tinted LIKELY");
        CHECK(has_color(&cv, CV_LIKELY), "a red blip/bar is painted");
    }

    SUITE("ui: worst-case (every slot LIKELY, max labels) still fits");
    {
        ui_state_t st; memset(&st, 0, sizeof(st));
        st.wifi_ok = st.ble_ok = true; st.baseline_locked = true;
        for (int i = 0; i < UI_SLOT_COUNT; i++)
            set_slot(&st,(ui_slot_t)i,AEGIS_LIKELY,96,"WWWWWWWWWWWWWWWWWWWWWWWWWWWWWWWW");
        st.sweep_deg = 300;
        ui_render(&cv, &st);
        CHECK(cv.oob == 0, "saturated layout must not overflow, oob=%u", cv.oob);
    }

    SUITE("ui: splash fits");
    {
        ui_render_splash(&cv);
        CHECK(cv.oob == 0, "splash must not draw off-panel, oob=%u", cv.oob);
    }
TEST_MAIN_END
