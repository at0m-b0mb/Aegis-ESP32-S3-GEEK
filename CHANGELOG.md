# Changelog

## v0.2.0 — the screen, the log, and the button

Aegis is now a complete standalone instrument: it *shows* you the airspace,
*records* what it sees, and takes a control in the field. Still blue-team,
still listen-only.

### New — on-screen dashboard (`components/ui`, pure C)
- A software RGB565 **canvas** with primitives and a 5×8 ASCII font, plus a
  **dashboard composer** that paints the full 240×135 frame: brand header,
  scanning **radar** with a blip per live threat, and five detector rows
  (name · verdict · confidence bar). Header tints to the worst verdict.
- Rendered entirely off-device for the docs — the preview images are produced
  by the real UI code, not drawn by hand.
- **Host-tested layout:** every frame asserts an out-of-bounds-write count of
  **zero**, so a label can never spill off the panel (the guard Sibyl uses).

### New — microSD evidence log (`main/sdlog.c`)
- On each rising edge into **LIKELY**, appends a CSV line to `AEGIS.LOG`
  (uptime, verdict, kind, score, MAC, channel, hits, label). Mounts the TF card
  over SPI3; absent-card is a clean no-op.

### New — baseline-lock button (`main/aegis_main.c`)
- **BOOT** toggles the evil-twin baseline: lock marks every currently-heard AP
  as trusted so a later impostor BSSID for a trusted SSID goes straight to
  LIKELY. `eviltwin_clear_baseline()` added to disarm/re-learn. Header shows
  `BASE:LOCK` / `BASE:LIVE`.

### New — ST7789 display driver (`main/display.c`)
- `esp_lcd` bring-up for the GEEK panel (SPI2, 240×135 landscape, gap 52/40),
  owns the PSRAM framebuffer, blits the canvas each tick. Orientation / colour
  order are documented as the on-hardware tweak points.

### Changed
- `app_main` now runs a single detection+UI task: splash → per-tick engine eval
  → radar/rows render → serial + SD alerts, with the button polled inline.
- Build gains `esp_lcd`, `fatfs`, `sdmmc`, `esp_driver_sdspi` and the `ui`
  component. **Firmware builds clean** for esp32s3 (ESP-IDF v5.5, 0 warnings).
- Host suite grows to **37 checks** (added `test_canvas`, `test_ui`).

### Still pending
- Flash-testing and display bring-up on physical hardware.

## v0.1.0 — engine core + firmware skeleton

First public cut. Blue-team, listen-only.

### Detection engines (pure C, host-verified — 20 unit checks)
- **Deauth / disassoc flood** — sliding-window rate model with a roaming floor;
  broadcast frames and reason-code 7 weighted up.
- **Evil twin / rogue AP** — SSID→AP table; duplicate BSSID alone is only
  ELEVATED (legit roaming), while a security-class conflict or a locked-baseline
  violation reaches LIKELY.
- **Beacon flood** — scores the *arrival rate* of never-before-seen BSSIDs, so a
  dense-but-static environment stays CLEAR.
- **BLE tracker sweep** — dwell-span × sightings; a single glimpse is not a
  stalker. Honest about BLE address rotation hiding part of the truth.
- **BLE pairing-spam** — counts *distinct* advertiser addresses carrying a
  pairing advert in-window (Apple Continuity / Fast Pair / Swift Pair).

### Firmware (ESP-IDF v5.5, esp32s3 — builds clean)
- Wi-Fi promiscuous (mgmt-only) with 2.4 GHz channel hopping.
- NimBLE **observer-only** passive scan (broadcaster/peripheral roles disabled).
- Wi-Fi/BLE software coexistence on the single radio.
- Findings reported over the USB serial console.
