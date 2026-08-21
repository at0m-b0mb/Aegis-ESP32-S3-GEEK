# Aegis

**A pocket airspace guardian for the Waveshare ESP32-S3-GEEK.**

Aegis is a **blue-team** wireless threat monitor. Plug the GEEK into any USB
port for power and it listens — passively — to the 2.4 GHz band, watching for
the signatures of the most common wireless attacks and warning you when it hears
one. No laptop, no Flipper, no association with any network. It only ever
listens; it never transmits a Wi-Fi frame and never advertises over BLE.

> **Listen-only by design.** Aegis is built from receive/observer paths only.
> The BLE stack is compiled as a NimBLE *observer* with the broadcaster and
> peripheral roles switched off, and the Wi-Fi radio runs in promiscuous
> (monitor) mode. There is nothing in this firmware that emits.

## What it detects

| # | Detector | Band | The attack | What it actually keys on |
|---|----------|------|------------|--------------------------|
| 1 | **Deauth / disassoc flood** | Wi-Fi | Kicking clients offline (DoS, or the setup for an evil twin) | Sustained *rate* of deauth/disassoc frames in a sliding window, weighted for broadcast-addressed frames and reason-code 7 |
| 2 | **Evil twin / rogue AP** | Wi-Fi | A look-alike of a network you trust | One SSID advertised by *contradictory* APs — a security-class change (open clone of a WPA2 net), or a new BSSID impersonating your locked baseline |
| 3 | **Beacon flood** | Wi-Fi | Fake-AP storms (mdk3/mdk4) that drown recon | *Arrival rate* of never-before-seen BSSIDs, not the raw AP count (so a merely-busy office stays quiet) |
| 4 | **BLE tracker sweep** | BLE | An AirTag / Tile / SmartTag following you | A tag lingering across minutes with many repeat sightings — not one that merely passes by |
| 5 | **BLE pairing-spam** | BLE | Pop-up floods (Apple Continuity / Fast Pair / Swift Pair) | An explosion of *distinct* advertiser addresses all carrying a pairing advert in a short window |

## The honesty model

Aegis inherits one rule from the detector line it descends from: **a passive
listener can prove an attack is present; it can never prove one is absent.** So
there is no "SAFE" light. The verdicts are:

- **CLEAR** — no signature seen in this window (*not* "you are safe")
- **ELEVATED** — a signature is forming; watch it
- **LIKELY** — a structured attack signature is sustained

Every detector has a **floor** so ordinary life doesn't cry wolf: a few deauths
are normal roaming, one SSID from two APs is normal enterprise roaming, a
tracker glimpsed once is just someone walking past. Confidence is a curve with a
ceiling of 96 — never 100 — because a receiver alone never earns certainty.

## Hardware

[Waveshare ESP32-S3-GEEK](https://www.waveshare.com/wiki/ESP32-S3-GEEK) —
ESP32-S3 (16 MB flash, 2 MB PSRAM), 1.14" ST7789 LCD, microSD, USB-A. Pin map
lives in [`main/board.h`](main/board.h), taken from Waveshare's own demo source.

## Build & test

The detection engines are **pure C with zero ESP-IDF dependency**, so you can
build and run the entire test suite on your laptop in seconds — do this first:

```bash
make -C test/host
```

To build the firmware (ESP-IDF v5.5+):

```bash
. $IDF_PATH/export.sh
idf.py set-target esp32s3
idf.py build flash monitor
```

## Status

- **Detection engines** — complete and **host-verified** (20 unit checks across
  the five detectors; see [`test/host`](test/host) and the `host-tests` CI).
- **Firmware** — wires Wi-Fi promiscuous + the NimBLE observer into the engines
  and reports findings over the USB serial console. **Builds clean for the
  esp32s3 target** (ESP-IDF v5.5); not yet flash-tested on hardware. Wi-Fi and
  BLE share the one radio via software coexistence, so each samples the band
  rather than capturing all of it.
- **On-screen radar UI** on the 1.14" LCD — the next milestone. The panel pins
  and geometry are already wired in `board.h`.

## Roadmap

- On-device LCD dashboard (threat radar + per-detector verdict rows)
- SD-card evidence logging (timestamped alerts with MAC / channel)
- "Lock baseline" button gesture to arm the evil-twin baseline in the field

> Aegis is deliberately a defensive tool for now. If the project draws interest,
> a separate, clearly-gated **red-team** counterpart is planned down the line —
> but this repository stays blue-team, listen-only.

## Ethics

Aegis is for defending networks and people: spotting the deauth flood against
your own AP, the evil twin cloning your café's SSID, the tracker that followed
you home. It captures no payloads, cracks nothing, and transmits nothing. Use it
on airspace you are responsible for.
