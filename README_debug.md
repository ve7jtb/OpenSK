# OpenSK Debugging Guide

This guide explains how to **restart** the OpenSK firmware on an nRF52840 DK with the `debug` feature enabled, and how to view debug logs.

## Prerequisites
- The firmware must be built with the `debug` feature. This is already the case for the current build (`./flash.sh nrf52840dk` uses `--features debug`).
- nRF‑Connect command‑line tools (`nrfjprog`) are installed and available in your `PATH`.
- A UART/USB serial console (e.g., `/dev/ttyACM0`) is connected to the DK.

## 1. Flash the firmware (if not already flashed)
```bash
# From the OpenSK workspace directory
cd $(pwd)  # ensure you are in the OpenSK repo root
./flash.sh nrf52840dk
```
The script builds the firmware (release) and programs the device.

## 2. Reset / Restart the device
```bash
# Reset the nRF52840 DK to restart the firmware
nrfjprog --reset
```
The reset forces the device to reboot, picking up the freshly flashed binary.

## 3. Enable verbose DEFMT logging (optional)
The firmware uses the `defmt` crate for logging. You can control the log level via the `DEFMT_LOG` environment variable **before flashing**:
```bash
export DEFMT_LOG=debug   # or "info", "trace" as needed
./flash.sh nrf52840dk
```
If you only want to change the log level after flashing, you can re‑flash with a different `DEFMT_LOG` value or use `DEFMT_RTT_BUFFER_SIZE` adjustments.

## 4. View the debug output
Open a serial terminal to the DK (the device appears as `/dev/ttyACM0` on macOS). Example using `screen`:
```bash
screen /dev/ttyACM0 115200
```
You should see `defmt` log lines such as:
```
[INFO] OpenSK::main: initializing...
[DEBUG] ctap2::make_credential: received request ...
```
Press `Ctrl‑A` then `Ctrl‑\` to exit `screen`.

## 5. Quick restart shortcut (one‑liner)
You can combine flashing and resetting in a single command:
```bash
./flash.sh nrf52840dk && nrfjprog --reset
```
This will program the device and immediately reboot it.

---
**Tip:** Keep this README in the `scratch/OpenSK` directory for future reference. Feel free to modify the commands if you use a different serial terminal (e.g., `minicom` or `picocom`).
