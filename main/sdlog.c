#include "sdlog.h"
#include "board.h"
#include <stdio.h>
#include "esp_log.h"
#include "esp_vfs_fat.h"
#include "sdmmc_cmd.h"
#include "driver/sdspi_host.h"
#include "driver/spi_common.h"

static const char *TAG = "sdlog";
static bool s_ok;
static sdmmc_card_t *s_card;
#define LOG_PATH "/sdcard/AEGIS.LOG"

bool sdlog_init(void)
{
    spi_bus_config_t bus = {
        .sclk_io_num = BOARD_SD_PIN_SCLK,
        .mosi_io_num = BOARD_SD_PIN_MOSI,
        .miso_io_num = BOARD_SD_PIN_MISO,
        .quadwp_io_num = -1, .quadhd_io_num = -1,
        .max_transfer_sz = 4000,
    };
    if (spi_bus_initialize(BOARD_SD_SPI_HOST, &bus, SPI_DMA_CH_AUTO) != ESP_OK) {
        ESP_LOGW(TAG, "SD SPI bus init failed"); return false;
    }
    sdmmc_host_t host = SDSPI_HOST_DEFAULT();
    host.slot = BOARD_SD_SPI_HOST;
    sdspi_device_config_t slot = SDSPI_DEVICE_CONFIG_DEFAULT();
    slot.gpio_cs = BOARD_SD_PIN_CS;
    slot.host_id = BOARD_SD_SPI_HOST;

    esp_vfs_fat_sdmmc_mount_config_t mcfg = {
        .format_if_mount_failed = false,
        .max_files = 3,
        .allocation_unit_size = 16 * 1024,
    };
    esp_err_t e = esp_vfs_fat_sdspi_mount("/sdcard", &host, &slot, &mcfg, &s_card);
    if (e != ESP_OK) { ESP_LOGW(TAG, "no SD card (%s)", esp_err_to_name(e)); return false; }

    s_ok = true;
    FILE *fp = fopen(LOG_PATH, "a");
    if (fp) { fprintf(fp, "# uptime_s,verdict,kind,score,mac,channel,hits,label\n"); fclose(fp); }
    ESP_LOGI(TAG, "SD evidence log ready at %s", LOG_PATH);
    return true;
}

bool sdlog_available(void) { return s_ok; }

void sdlog_alert(uint32_t uptime_s, const aegis_finding_t *f)
{
    if (!s_ok) return;
    FILE *fp = fopen(LOG_PATH, "a");
    if (!fp) return;
    fprintf(fp, "%lu,%s,%s,%u,%02X:%02X:%02X:%02X:%02X:%02X,%u,%lu,%s\n",
            (unsigned long)uptime_s, aegis_verdict_str(f->verdict), aegis_kind_str(f->kind),
            f->score, f->mac[0], f->mac[1], f->mac[2], f->mac[3], f->mac[4], f->mac[5],
            f->channel, (unsigned long)f->hits, f->label);
    fclose(fp);
}
