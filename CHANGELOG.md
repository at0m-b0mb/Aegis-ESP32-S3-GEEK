# Changelog

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

### Not yet
- On-screen LCD radar UI (pins wired in `board.h`).
- SD-card evidence logging.
- Hardware flash-testing.
