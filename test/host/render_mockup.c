/* Render the real Aegis dashboard UI to BMP files, so the on-device screen can
 * be previewed without hardware. Usage: render_mockup <out_dir> */
#include "ui.h"
#include "bmp.h"
#include <string.h>
#include <stdio.h>

static uint16_t g_buf[240 * 135];

static void slot(ui_state_t *st, ui_slot_t s, aegis_verdict_t v, uint8_t sc, const char *l)
{
    st->f[s].verdict = v; st->f[s].score = sc;
    strncpy(st->f[s].label, l, sizeof(st->f[s].label) - 1);
}

static void save(const char *dir, const char *name, const ui_state_t *st, int splash)
{
    canvas_t cv; cv_init(&cv, g_buf, 240, 135);
    if (splash) ui_render_splash(&cv); else ui_render(&cv, st);
    char path[512]; snprintf(path, sizeof(path), "%s/%s", dir, name);
    bmp_write(path, &cv, 3);           /* 3x = 720x405 */
    printf("  wrote %s (oob=%u)\n", path, cv.oob);
}

int main(int argc, char **argv)
{
    const char *dir = argc > 1 ? argv[1] : ".";
    ui_state_t st;

    /* 1. all clear */
    memset(&st, 0, sizeof(st)); st.wifi_ok = st.ble_ok = true; st.sweep_deg = 45;
    for (int i = 0; i < UI_SLOT_COUNT; i++) slot(&st,(ui_slot_t)i,AEGIS_CLEAR,0,"-");
    save(dir, "mock_clear.bmp", &st, 0);

    /* 2. under attack: deauth flood + evil twin, tracker forming */
    memset(&st, 0, sizeof(st)); st.wifi_ok = st.ble_ok = true;
    st.sweep_deg = 200; st.baseline_locked = true;
    slot(&st, UI_SLOT_DEAUTH,   AEGIS_LIKELY,   90, "02:AA:BB:CC:DD:EE");
    slot(&st, UI_SLOT_EVILTWIN, AEGIS_LIKELY,   80, "CorpWiFi");
    slot(&st, UI_SLOT_BEACON,   AEGIS_CLEAR,     0, "-");
    slot(&st, UI_SLOT_TRACKER,  AEGIS_ELEVATED, 48, "Find My tag");
    slot(&st, UI_SLOT_SPAM,     AEGIS_CLEAR,     0, "-");
    save(dir, "mock_attack.bmp", &st, 0);

    /* 3. BLE-heavy: spam flood + tracker */
    memset(&st, 0, sizeof(st)); st.wifi_ok = st.ble_ok = true; st.sweep_deg = 320;
    slot(&st, UI_SLOT_DEAUTH,   AEGIS_CLEAR,     0, "-");
    slot(&st, UI_SLOT_EVILTWIN, AEGIS_CLEAR,     0, "-");
    slot(&st, UI_SLOT_BEACON,   AEGIS_ELEVATED, 40, "18 new APs/5s");
    slot(&st, UI_SLOT_TRACKER,  AEGIS_LIKELY,   76, "Tile");
    slot(&st, UI_SLOT_SPAM,     AEGIS_LIKELY,   88, "Apple pair-spam x12");
    save(dir, "mock_ble.bmp", &st, 0);

    /* 4. splash */
    save(dir, "mock_splash.bmp", &st, 1);
    return 0;
}
