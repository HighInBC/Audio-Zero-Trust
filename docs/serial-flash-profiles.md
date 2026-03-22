# Serial Flash Profiles

This document defines deterministic serial flashing contracts used by `azt_tool.py flash-device --from-ota`.

## Profile: v1 (ESP32 / M5Stack ATOM Echo)

`flash-device --from-ota` uses a fixed full-layout write sequence:

- `0x1000` → `bootloader.bin`
- `0x8000` → `partitions.bin`
- `0xE000` → `boot_app0.bin`
- `0x10000` → OTA payload app image (`firmware.bin` extracted from bundle)

Write command class: `esptool write_flash -z` with source-compatible flash options (`dio`, `40m`, `4MB`).

## Artifact sources

For v1 profile artifacts:

1. Preferred: `firmware/releases/flash-profile-v1/bootloader.bin` and `partitions.bin`
2. Fallback: local PlatformIO build artifacts for selected env:
   - `firmware/audio_zero_trust/.pio/build/<env>/bootloader.bin`
   - `firmware/audio_zero_trust/.pio/build/<env>/partitions.bin`
3. `boot_app0.bin` from PlatformIO framework package path.

## OTA policy apply after flash

After successful serial write and reboot, tool applies OTA controls via serial command:

- `ota_signer_public_key_pem`
- `ota_version_code`
- `ota_min_allowed_version_code` (when provided by bundle or CLI override)

This is done through `AZT_OTA_APPLY <json>`.

## Versioning rule

Profile `v1` is a layout contract. Any bootloader/partition/layout change requires a new profile (for example `v2`) and corresponding tooling update.

Do not silently change layout assumptions within the same profile.
