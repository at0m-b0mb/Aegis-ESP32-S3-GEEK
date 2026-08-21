#include "ui.h"
#include <math.h>
#include <string.h>
#include <stdio.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

/* ---- layout constants for the 240x135 panel ---- */
#define UI_W        240
#define UI_H        135
#define HDR_H        16
#define RAD_CX       56
#define RAD_CY       80
#define RAD_R        44
#define ROWS_X      106
#define ROWS_W      130
#define ROW0_Y       20
#define ROW_H        22

static const char *slot_name(ui_slot_t s)
{
    switch (s) {
        case UI_SLOT_DEAUTH:   return "DEAUTH";
        case UI_SLOT_EVILTWIN: return "EVIL TWIN";
        case UI_SLOT_BEACON:   return "BEACON";
        case UI_SLOT_TRACKER:  return "BLE TAG";
        case UI_SLOT_SPAM:     return "BLE SPAM";
        default:               return "-";
    }
}

uint16_t ui_verdict_color(aegis_verdict_t v)
{
    switch (v) {
        case AEGIS_LIKELY:   return CV_LIKELY;
        case AEGIS_ELEVATED: return CV_ELEV;
        default:             return CV_CLEAR;
    }
}

aegis_verdict_t ui_worst(const ui_state_t *st)
{
    aegis_verdict_t w = AEGIS_CLEAR;
    for (int i = 0; i < UI_SLOT_COUNT; i++)
        if (st->f[i].verdict > w) w = st->f[i].verdict;
    return w;
}

/* A small shield glyph for the brand mark. */
static void draw_shield(canvas_t *cv, int x, int y, uint16_t color)
{
    /* 11 wide, 13 tall crest */
    for (int j = 0; j < 13; j++) {
        int half = (j < 8) ? 5 : 5 - (j - 7);          /* taper to a point */
        if (j < 2) half = 5;
        for (int i = -half; i <= half; i++)
            cv_pixel(cv, x + 5 + i, y + j, color);
    }
    cv_pixel(cv, x + 5, y + 4, CV_BG);                  /* tiny notch detail */
    cv_vline(cv, x + 5, y + 3, 6, CV_BG);
}

static void draw_header(canvas_t *cv, const ui_state_t *st)
{
    aegis_verdict_t worst = ui_worst(st);
    uint16_t tint = ui_verdict_color(worst);

    cv_fill_rect(cv, 0, 0, UI_W, HDR_H, CV_PANEL);
    draw_shield(cv, 3, 1, CV_ACCENT);
    cv_text(cv, 20, 1, "AEGIS", CV_INK, -1, 2);

    /* right side: worst-verdict word in its color, and the baseline state */
    const char *wv = aegis_verdict_str(worst);
    cv_text(cv, UI_W - cv_text_width(wv, 1) - 3, 1, wv, tint, -1, 1);
    const char *bl = st->baseline_locked ? "BASE:LOCK" : "BASE:LIVE";
    cv_text(cv, UI_W - cv_text_width(bl, 1) - 3, 9, bl,
            st->baseline_locked ? CV_ACCENT : CV_DIM, -1, 1);

    cv_hline(cv, 0, HDR_H, UI_W, tint);                 /* accent underline */
}

static void draw_radar(canvas_t *cv, const ui_state_t *st)
{
    cv_circle(cv, RAD_CX, RAD_CY, RAD_R, CV_DIM);
    cv_circle(cv, RAD_CX, RAD_CY, RAD_R * 2 / 3, cv_rgb(30, 44, 70));
    cv_circle(cv, RAD_CX, RAD_CY, RAD_R / 3, cv_rgb(30, 44, 70));
    cv_hline(cv, RAD_CX - RAD_R, RAD_CY, 2 * RAD_R + 1, cv_rgb(24, 36, 58));
    cv_vline(cv, RAD_CX, RAD_CY - RAD_R, 2 * RAD_R + 1, cv_rgb(24, 36, 58));

    /* sweep line */
    double a = st->sweep_deg * M_PI / 180.0;
    cv_line(cv, RAD_CX, RAD_CY,
            RAD_CX + (int)(cos(a) * RAD_R), RAD_CY + (int)(sin(a) * RAD_R), CV_ACCENT);

    /* one blip per active threat: angle spread by slot, radius by severity
     * (stronger = closer to the centre), colored by verdict. */
    for (int i = 0; i < UI_SLOT_COUNT; i++) {
        const aegis_finding_t *f = &st->f[i];
        if (f->verdict < AEGIS_ELEVATED) continue;
        double ang = (30 + i * 66) * M_PI / 180.0;
        double rr  = RAD_R * (1.0 - (double)f->score / AEGIS_SCORE_MAX * 0.72);
        int bx = RAD_CX + (int)(cos(ang) * rr);
        int by = RAD_CY + (int)(sin(ang) * rr);
        uint16_t c = ui_verdict_color(f->verdict);
        cv_fill_circle(cv, bx, by, f->verdict == AEGIS_LIKELY ? 3 : 2, c);
    }

    cv_text_center(cv, RAD_CX, RAD_CY + RAD_R + 3,
                   (st->wifi_ok && st->ble_ok) ? "WIFI+BLE" :
                   st->wifi_ok ? "WIFI" : st->ble_ok ? "BLE" : "IDLE", CV_DIM, -1, 1);
}

static void draw_rows(canvas_t *cv, const ui_state_t *st)
{
    for (int i = 0; i < UI_SLOT_COUNT; i++) {
        const aegis_finding_t *f = &st->f[i];
        int y = ROW0_Y + i * ROW_H;
        uint16_t vc = ui_verdict_color(f->verdict);

        cv_text(cv, ROWS_X, y, slot_name((ui_slot_t)i), CV_INK, -1, 1);
        const char *wv = aegis_verdict_str(f->verdict);
        cv_text(cv, ROWS_X + ROWS_W - cv_text_width(wv, 1), y, wv, vc, -1, 1);

        /* score bar */
        int bx = ROWS_X, by = y + 10, bw = ROWS_W, bh = 5;
        cv_rect(cv, bx, by, bw, bh, CV_DIM);
        int fillw = (int)((long)(bw - 2) * f->score / AEGIS_SCORE_MAX);
        if (fillw > 0) cv_fill_rect(cv, bx + 1, by + 1, fillw, bh - 2, vc);

        if (i < UI_SLOT_COUNT - 1)
            cv_hline(cv, ROWS_X, y + ROW_H - 3, ROWS_W, cv_rgb(20, 30, 48));
    }
}

void ui_render(canvas_t *cv, const ui_state_t *st)
{
    cv_clear(cv, CV_BG);
    draw_radar(cv, st);
    draw_rows(cv, st);
    draw_header(cv, st);   /* header last so it sits on top */

    /* thin divider between radar and rows */
    cv_vline(cv, ROWS_X - 5, HDR_H + 2, UI_H - HDR_H - 4, cv_rgb(20, 30, 48));
}

void ui_render_splash(canvas_t *cv)
{
    cv_clear(cv, CV_BG);
    draw_shield(cv, UI_W / 2 - 34, 38, CV_ACCENT);
    cv_text(cv, UI_W / 2 - 18, 40, "AEGIS", CV_INK, -1, 3);
    cv_text_center(cv, UI_W / 2, 78, "WIFI + BLE AIRSPACE GUARDIAN", CV_DIM, -1, 1);
    cv_text_center(cv, UI_W / 2, 96, "PASSIVE - LISTEN ONLY", CV_ACCENT, -1, 1);
}
