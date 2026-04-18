# Firmware Signing Quickstart (ESP32-S3 / atom-echos3r)

This performs steps 1-3 safely (no eFuse changes):

1) Generate signing key + local backup bundle
```bash
cd firmware/audio_zero_trust
./scripts/generate_firmware_signing_key.sh
```

2) Build and sign firmware artifacts
```bash
cd firmware/audio_zero_trust
KEY=$(ls -1 ../.secrets/firmware-signing/esp32s3-secureboot-v2-rsa3072-*.pem | tail -1)
./scripts/build_signed_firmware.sh atom-echos3r "$KEY"
```

Outputs:
- `firmware/releases/atom-echos3r/bootloader.signed.bin`
- `firmware/releases/atom-echos3r/firmware.signed.bin`
- `firmware/releases/atom-echos3r/partitions.bin`
- `firmware/releases/atom-echos3r/SHA256SUMS.txt`

3) Flash signed firmware (no fuses burned)
```bash
cd firmware/audio_zero_trust
./scripts/flash_signed_firmware.sh /dev/ttyACM0 ../releases/atom-echos3r
```

## Important
- These steps **do not** burn secure boot eFuses.
- Move `../.secrets/firmware-signing/*.backup.tgz` to offline storage before any irreversible operations.
