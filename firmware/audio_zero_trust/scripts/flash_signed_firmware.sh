#!/usr/bin/env bash
set -euo pipefail

# Flash pre-signed artifacts. Does NOT burn eFuses.

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <serial-port> <release-dir> [baud=460800]" >&2
  exit 2
fi

PORT="$1"
RELEASE_DIR="$2"
BAUD="${3:-460800}"
ESPTOOL="/home/openclaw/.platformio/penv/bin/esptool.py"
BOOT_APP0="/home/openclaw/.platformio/packages/framework-arduinoespressif32/tools/partitions/boot_app0.bin"

BOOTLOADER="${RELEASE_DIR}/bootloader.signed.bin"
PARTITIONS="${RELEASE_DIR}/partitions.bin"
APP="${RELEASE_DIR}/firmware.signed.bin"

for f in "${BOOTLOADER}" "${PARTITIONS}" "${APP}" "${BOOT_APP0}"; do
  [[ -f "$f" ]] || { echo "ERROR: missing file: $f" >&2; exit 1; }
done

echo "Flashing signed firmware to ${PORT} @ ${BAUD}"
"${ESPTOOL}" --chip esp32s3 --port "${PORT}" --baud "${BAUD}" --before default_reset --after hard_reset \
  write_flash -z \
  0x0000 "${BOOTLOADER}" \
  0x8000 "${PARTITIONS}" \
  0xe000 "${BOOT_APP0}" \
  0x10000 "${APP}"

echo "OK: flashed signed image set (no fuse changes performed)"
