# The detection engines are pure C with no ESP-IDF dependency (see test/host).
# On-device they are compiled as a plain component the firmware links against.
idf_component_register(
    SRCS "src/deauth_detect.c"
         "src/eviltwin_detect.c"
         "src/beacon_flood.c"
         "src/ble_threat.c"
    INCLUDE_DIRS "include"
)
