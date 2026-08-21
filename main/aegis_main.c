/*
 * aegis_main.c - Aegis firmware entry for the Waveshare ESP32-S3-GEEK.
 *
 * BLUE-TEAM, listen-only. Aegis puts the Wi-Fi radio in promiscuous mode and
 * runs a NimBLE observer, feeds every frame/advert into the pure-C detection
 * engines (components/engine), paints a live dashboard on the 1.14" LCD
 * (components/ui), logs alerts to microSD, and lets the BOOT button arm the
 * evil-twin baseline. It never transmits a Wi-Fi frame and never advertises.
 *
 * Wi-Fi and BLE share the single 2.4GHz radio via software coexistence, so each
 * samples the band rather than capturing all of it.
 */
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "nvs_flash.h"
#include "driver/gpio.h"

#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/util/util.h"

#include "board.h"
#include "aegis_threat.h"
#include "aegis_wifi80211.h"
#include "deauth_detect.h"
#include "eviltwin_detect.h"
#include "beacon_flood.h"
#include "ble_threat.h"
#include "display.h"
#include "sdlog.h"
#include "ui.h"

static const char *TAG = "aegis";

static SemaphoreHandle_t     s_lock;
static deauth_engine_t       s_deauth;
static eviltwin_engine_t     s_eviltwin;
static beacon_flood_engine_t s_beacon;
static ble_engine_t          s_ble;
static bool                  s_baseline_locked;
static bool                  s_wifi_ok, s_ble_ok, s_disp_ok;

static uint32_t now_ms(void) { return (uint32_t)(esp_timer_get_time() / 1000); }

/* ---------------- Wi-Fi promiscuous path ---------------- */
static void wifi_rx_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_MGMT) return;
    const wifi_promiscuous_pkt_t *p = (const wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = p->payload;
    uint16_t len  = p->rx_ctrl.sig_len;
    int8_t   rssi = p->rx_ctrl.rssi;
    uint8_t  chan = p->rx_ctrl.channel;
    uint32_t t    = now_ms();

    wifi_mgmt_t m;
    if (!wifi_parse_mgmt(frame, len, &m)) return;
    if (xSemaphoreTake(s_lock, portMAX_DELAY) != pdTRUE) return;
    switch (m.subtype) {
        case WIFI_STYPE_DEAUTH:
        case WIFI_STYPE_DISASSOC:
            deauth_feed(&s_deauth, &m, wifi_reason_code(frame, len), rssi, chan, t);
            break;
        case WIFI_STYPE_BEACON:
            eviltwin_feed(&s_eviltwin, frame, len, rssi, t);
            beacon_flood_feed(&s_beacon, frame, len, t);
            break;
        case WIFI_STYPE_PROBE_RESP:
            eviltwin_feed(&s_eviltwin, frame, len, rssi, t);
            break;
        default: break;
    }
    xSemaphoreGive(s_lock);
}

static void channel_hop_task(void *arg)
{
    (void)arg;
    const uint8_t ch[] = {1, 6, 11, 2, 7, 12, 3, 8, 13, 4, 9, 5, 10};
    size_t i = 0;
    for (;;) {
        esp_wifi_set_channel(ch[i], WIFI_SECOND_CHAN_NONE);
        i = (i + 1) % sizeof(ch);
        vTaskDelay(pdMS_TO_TICKS(280));
    }
}

static void wifi_start_sniffer(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
    ESP_ERROR_CHECK(esp_wifi_start());
    wifi_promiscuous_filter_t filter = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(wifi_rx_cb));
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));
    xTaskCreate(channel_hop_task, "chan_hop", 2048, NULL, 4, NULL);
    s_wifi_ok = true;
    ESP_LOGI(TAG, "Wi-Fi sniffer up (promiscuous, mgmt-only, hopping)");
}

/* ---------------- BLE observer path ---------------- */
static int ble_gap_event(struct ble_gap_event *event, void *arg)
{
    (void)arg;
    if (event->type == BLE_GAP_EVENT_DISC) {
        const struct ble_gap_disc_desc *d = &event->disc;
        uint32_t t = now_ms();
        if (xSemaphoreTake(s_lock, portMAX_DELAY) == pdTRUE) {
            ble_feed(&s_ble, d->addr.val, d->rssi, d->data, d->length_data, t);
            xSemaphoreGive(s_lock);
        }
    }
    return 0;
}

static void ble_start_observer(void)
{
    uint8_t own_addr_type;
    if (ble_hs_util_ensure_addr(0) != 0) return;
    if (ble_hs_id_infer_auto(0, &own_addr_type) != 0) return;
    struct ble_gap_disc_params dp = { .passive = 1, .filter_duplicates = 0 };
    if (ble_gap_disc(own_addr_type, BLE_HS_FOREVER, &dp, ble_gap_event, NULL) == 0) {
        s_ble_ok = true;
        ESP_LOGI(TAG, "BLE observer up (passive scan)");
    }
}
static void ble_on_sync(void) { ble_start_observer(); }
static void ble_host_task(void *param) { (void)param; nimble_port_run(); nimble_port_freertos_deinit(); }

/* ---------------- button: BOOT toggles the evil-twin baseline ---------------- */
static void button_init(void)
{
    gpio_config_t io = { .pin_bit_mask = 1ULL << BOARD_BTN_PIN,
                         .mode = GPIO_MODE_INPUT, .pull_up_en = GPIO_PULLUP_ENABLE };
    gpio_config(&io);
}

static bool button_pressed_edge(void)
{
    static int prev = 1;
    int lvl = gpio_get_level(BOARD_BTN_PIN);   /* active low */
    bool edge = (prev == 1 && lvl == 0);
    prev = lvl;
    return edge;
}

static void toggle_baseline(void)
{
    if (xSemaphoreTake(s_lock, portMAX_DELAY) != pdTRUE) return;
    if (s_baseline_locked) { eviltwin_clear_baseline(&s_eviltwin); s_baseline_locked = false; }
    else                   { eviltwin_lock_baseline(&s_eviltwin);  s_baseline_locked = true;  }
    xSemaphoreGive(s_lock);
    ESP_LOGW(TAG, "evil-twin baseline %s", s_baseline_locked ? "LOCKED" : "cleared");
}

/* ---------------- main UI / detection loop ---------------- */
static void ui_task(void *arg)
{
    (void)arg;
    if (s_disp_ok) { ui_render_splash(display_canvas()); display_flush(); }
    vTaskDelay(pdMS_TO_TICKS(1500));

    bool was_likely[UI_SLOT_COUNT] = {0};
    uint32_t t0 = now_ms();
    ui_state_t st; memset(&st, 0, sizeof(st));

    for (;;) {
        if (button_pressed_edge()) toggle_baseline();

        uint32_t t = now_ms();
        if (xSemaphoreTake(s_lock, portMAX_DELAY) == pdTRUE) {
            deauth_eval(&s_deauth,   t, &st.f[UI_SLOT_DEAUTH]);
            eviltwin_eval(&s_eviltwin, t, &st.f[UI_SLOT_EVILTWIN]);
            beacon_flood_eval(&s_beacon, t, &st.f[UI_SLOT_BEACON]);
            ble_eval_tracker(&s_ble, t, &st.f[UI_SLOT_TRACKER]);
            ble_eval_spam(&s_ble,    t, &st.f[UI_SLOT_SPAM]);
            st.baseline_locked = s_baseline_locked;
            xSemaphoreGive(s_lock);
        }
        st.wifi_ok = s_wifi_ok; st.ble_ok = s_ble_ok;
        st.uptime_s = (t - t0) / 1000;
        st.sweep_deg = (uint16_t)((st.sweep_deg + 9) % 360);

        /* alert on the rising edge into LIKELY: serial + SD evidence */
        for (int i = 0; i < UI_SLOT_COUNT; i++) {
            bool lk = st.f[i].verdict == AEGIS_LIKELY;
            if (lk && !was_likely[i]) {
                ESP_LOGW(TAG, "ALERT %-12s score=%u %s (ch=%u hits=%lu)",
                         aegis_kind_str(st.f[i].kind), st.f[i].score, st.f[i].label,
                         st.f[i].channel, (unsigned long)st.f[i].hits);
                sdlog_alert(st.uptime_s, &st.f[i]);
            }
            was_likely[i] = lk;
        }

        if (s_disp_ok) { ui_render(display_canvas(), &st); display_flush(); }
        vTaskDelay(pdMS_TO_TICKS(120));
    }
}

/* ---------------- entry ---------------- */
void app_main(void)
{
    esp_err_t err = nvs_flash_init();
    if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ESP_ERROR_CHECK(nvs_flash_init());
    }

    s_lock = xSemaphoreCreateMutex();
    deauth_reset(&s_deauth);
    eviltwin_reset(&s_eviltwin);
    beacon_flood_reset(&s_beacon);
    ble_reset(&s_ble);

    ESP_LOGI(TAG, "Aegis blue-team monitor starting (Wi-Fi + BLE, listen-only)");

    s_disp_ok = display_init();
    button_init();
    sdlog_init();

    wifi_start_sniffer();
    ESP_ERROR_CHECK(nimble_port_init());
    ble_hs_cfg.sync_cb = ble_on_sync;
    nimble_port_freertos_init(ble_host_task);

    xTaskCreate(ui_task, "aegis_ui", 6144, NULL, 5, NULL);
}
