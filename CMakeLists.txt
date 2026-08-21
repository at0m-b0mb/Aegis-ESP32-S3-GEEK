# Aegis - Wi-Fi/BLE airspace guardian for the Waveshare ESP32-S3-GEEK.
#
# Target: ESP32-S3 (16MB flash, 2MB QUAD PSRAM). Build with ESP-IDF v5.5+:
#   . $IDF_PATH/export.sh
#   idf.py set-target esp32s3
#   idf.py build flash monitor
#
# The detection engines are also built and unit-tested with NO ESP-IDF at all -
# see test/host (make). Do that first; it is faster and catches more.
cmake_minimum_required(VERSION 3.16)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(aegis)
