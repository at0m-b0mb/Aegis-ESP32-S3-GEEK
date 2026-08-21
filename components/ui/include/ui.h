/*
 * ui.h - compose the Aegis dashboard into a canvas. Pure C, host-testable.
 *
 * ui_render() paints one full frame: a brand header, a scanning radar on the
 * left with a blip per active threat, and five detector rows on the right (name,
 * verdict, score bar). The five findings are supplied in a FIXED order (see
 * ui_slot_t) so the layout is stable. Nothing here talks to hardware; the device
 * display module blits the finished canvas to the ST7789.
 */
#ifndef AEGIS_UI_H
#define AEGIS_UI_H

#include "canvas.h"
#include "aegis_threat.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    UI_SLOT_DEAUTH = 0,
    UI_SLOT_EVILTWIN,
    UI_SLOT_BEACON,
    UI_SLOT_TRACKER,
    UI_SLOT_SPAM,
    UI_SLOT_COUNT
} ui_slot_t;

typedef struct {
    aegis_finding_t f[UI_SLOT_COUNT]; /* one finding per slot, in ui_slot_t order */
    bool     baseline_locked;         /* evil-twin baseline armed?               */
    bool     wifi_ok;                 /* Wi-Fi sniffer running                   */
    bool     ble_ok;                  /* BLE observer running                    */
    uint16_t sweep_deg;               /* radar sweep animation phase, 0..359     */
    uint32_t uptime_s;                /* seconds since boot (footer)             */
} ui_state_t;

/* Returns the worst verdict across the five slots (also drives header tint). */
aegis_verdict_t ui_worst(const ui_state_t *st);

/* Map a verdict to its palette color. */
uint16_t ui_verdict_color(aegis_verdict_t v);

/* Paint one full dashboard frame into cv (expected 240x135). */
void ui_render(canvas_t *cv, const ui_state_t *st);

/* Paint the boot splash (brand + tagline). */
void ui_render_splash(canvas_t *cv);

#ifdef __cplusplus
}
#endif
#endif /* AEGIS_UI_H */
