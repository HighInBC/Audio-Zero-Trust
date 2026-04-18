#!/usr/bin/env bash
set -euo pipefail

# Build + sign AtomS3R firmware artifacts (no fuse operations).

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_NAME="${1:-atom-echos3r}"
KEY_PATH="${2:-}"
PIO="/home/openclaw/.openclaw/workspace/Audio-Zero-Trust/.venv/bin/pio"
ESPSECURE="/home/openclaw/.platformio/penv/bin/espsecure.py"

if [[ -z "${KEY_PATH}" ]]; then
  echo "Usage: $0 <env> <signing-key.pem>" >&2
  exit 2
fi

if [[ ! -f "${KEY_PATH}" ]]; then
  echo "ERROR: key not found: ${KEY_PATH}" >&2
  exit 1
fi

cd "${ROOT_DIR}"
"${PIO}" run -e "${ENV_NAME}"

BUILD_DIR="${ROOT_DIR}/.pio/build/${ENV_NAME}"
OUT_DIR="${ROOT_DIR}/../releases/${ENV_NAME}"
mkdir -p "${OUT_DIR}"

BOOTLOADER_BIN="${BUILD_DIR}/bootloader.bin"
PARTITIONS_BIN="${BUILD_DIR}/partitions.bin"
APP_BIN="${BUILD_DIR}/firmware.bin"

[[ -f "${BOOTLOADER_BIN}" && -f "${PARTITIONS_BIN}" && -f "${APP_BIN}" ]] || {
  echo "ERROR: expected build artifacts missing in ${BUILD_DIR}" >&2
  exit 1
}

cp -f "${BOOTLOADER_BIN}" "${OUT_DIR}/bootloader.bin"
cp -f "${APP_BIN}" "${OUT_DIR}/firmware.bin"
cp -f "${PARTITIONS_BIN}" "${OUT_DIR}/partitions.bin"

"${ESPSECURE}" sign_data --version 2 --keyfile "${KEY_PATH}" --output "${OUT_DIR}/bootloader.signed.bin" "${OUT_DIR}/bootloader.bin"
"${ESPSECURE}" sign_data --version 2 --keyfile "${KEY_PATH}" --output "${OUT_DIR}/firmware.signed.bin" "${OUT_DIR}/firmware.bin"

sha256sum "${OUT_DIR}/bootloader.signed.bin" "${OUT_DIR}/firmware.signed.bin" "${OUT_DIR}/partitions.bin" > "${OUT_DIR}/SHA256SUMS.txt"

cat <<EOF
OK
SIGNED_BOOTLOADER=${OUT_DIR}/bootloader.signed.bin
SIGNED_FIRMWARE=${OUT_DIR}/firmware.signed.bin
PARTITIONS=${OUT_DIR}/partitions.bin
CHECKSUMS=${OUT_DIR}/SHA256SUMS.txt
EOF
