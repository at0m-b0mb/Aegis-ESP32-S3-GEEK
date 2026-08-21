idf_component_register(
    SRCS "aegis_main.c" "display.c" "sdlog.c"
    INCLUDE_DIRS "."
    REQUIRES engine ui esp_wifi esp_event nvs_flash esp_timer bt
             driver esp_lcd fatfs sdmmc esp_driver_sdspi esp_driver_spi esp_driver_gpio
)
