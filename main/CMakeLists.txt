idf_component_register(
    SRCS "aegis_main.c"
    INCLUDE_DIRS "."
    REQUIRES engine esp_wifi esp_event nvs_flash esp_timer bt driver
)
