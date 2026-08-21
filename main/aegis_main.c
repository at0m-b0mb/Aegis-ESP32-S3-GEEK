/*
 * aegis_main.c - Aegis firmware entry for the Waveshare ESP32-S3-GEEK.
 *
 * BLUE-TEAM build. Aegis is a passive airspace guardian: it puts the Wi-Fi
 * radio into promiscuous mode and runs a NimBLE observer, feeds every frame /
 * advert into the pure-C detection engines (components/engine), and reports
 * findings. It never transmits Wi-Fi frames and never advertises over BLE.
 *
 * This release wires the engines to the radios and reports over the USB serial
 * console. The on-screen radar UI on the 1.14" LCD is the next milestone; the
 * pin map is already in board.h. Red-team features are intentionally NOT part
 * of this firmware and will be considered later.
 *
 * Wi-Fi and BLE share the single 2.4GHz radio via software coexistence, so
 * their airtime interleaves - expect each to sample, not to capture 100%.
 */
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_event.h"
#include "esp_wifi.h"
#include "esp_mac.h"
#include "nvs_flash.h"

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

static const char *TAG = "aegis";

/* All engine state lives behind one mutex: the Wi-Fi promiscuous callback and
 * the NimBLE observer callback both feed it, and the report task reads it. */
static SemaphoreHandle_t     s_lock;
static deauth_engine_t       s_deauth;
static eviltwin_engine_t     s_eviltwin;
static beacon_flood_engine_t s_beacon;
static ble_engine_t          s_ble;

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

    if (xSemaphoreTake(s_lock, portMAX_DELAY) == pdTRUE) {
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
}

/* Cycle the sniffer across the 2.4GHz channels so we hear every AP/attack. */
static void channel_hop_task(void *arg)
{
    (void)arg;
    const uint8_t channels[] = {1, 6, 11, 2, 7, 12, 3, 8, 13, 4, 9, 5, 10};
    size_t i = 0;
    for (;;) {
        esp_wifi_set_channel(channels[i], WIFI_SECOND_CHAN_NONE);
        i = (i + 1) % (sizeof(channels) / sizeof(channels[0]));
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
    if (ble_hs_util_ensure_addr(0) != 0) { ESP_LOGE(TAG, "no BLE addr"); return; }
    if (ble_hs_id_infer_auto(0, &own_addr_type) != 0) return;

    struct ble_gap_disc_params dp = {
        .passive = 1,            /* listen only, never send scan requests */
        .itvl = 0, .window = 0,  /* stack defaults                        */
        .filter_duplicates = 0,  /* we WANT repeats - that is the signal  */
        .limited = 0,
    };
    int rc = ble_gap_disc(own_addr_type, BLE_HS_FOREVER, &dp, ble_gap_event, NULL);
    if (rc != 0) ESP_LOGE(TAG, "ble_gap_disc rc=%d", rc);
    else         ESP_LOGI(TAG, "BLE observer up (passive scan)");
}

static void ble_on_sync(void) { ble_start_observer(); }
static void ble_host_task(void *param) { (void)param; nimble_port_run(); nimble_port_freertos_deinit(); }

/* ---------------- reporting ---------------- */

static void log_finding(const aegis_finding_t *f)
{
    if (f->verdict < AEGIS_ELEVATED) return;
    ESP_LOGW(TAG, "[%-8s] %-12s score=%2u  %s  (hits=%lu ch=%u rssi=%d)",
             aegis_verdict_str(f->verdict), aegis_kind_str(f->kind), f->score,
             f->label[0] ? f->label : "-", (unsigned long)f->hits,
             f->channel, f->rssi);
}

static void report_task(void *arg)
{
    (void)arg;
    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        aegis_finding_t fd, fe, fb, ft, fs;
        if (xSemaphoreTake(s_lock, portMAX_DELAY) != pdTRUE) continue;
        uint32_t t = now_ms();
        deauth_eval(&s_deauth, t, &fd);
        eviltwin_eval(&s_eviltwin, t, &fe);
        beacon_flood_eval(&s_beacon, t, &fb);
        ble_eval_tracker(&s_ble, t, &ft);
        ble_eval_spam(&s_ble, t, &fs);
        xSemaphoreGive(s_lock);

        aegis_verdict_t worst = fd.verdict;
        if (fe.verdict > worst) worst = fe.verdict;
        if (fb.verdict > worst) worst = fb.verdict;
        if (ft.verdict > worst) worst = ft.verdict;
        if (fs.verdict > worst) worst = fs.verdict;

        if (worst == AEGIS_CLEAR) {
            ESP_LOGI(TAG, "airspace CLEAR (no signature this window)");
        } else {
            log_finding(&fd); log_finding(&fe); log_finding(&fb);
            log_finding(&ft); log_finding(&fs);
        }
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

    ESP_LOGI(TAG, "Aegis blue-team monitor starting (Wi-Fi + BLE passive)");

    wifi_start_sniffer();

    ESP_ERROR_CHECK(nimble_port_init());
    ble_hs_cfg.sync_cb = ble_on_sync;
    nimble_port_freertos_init(ble_host_task);

    xTaskCreate(report_task, "report", 4096, NULL, 5, NULL);
}
