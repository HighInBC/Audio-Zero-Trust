#!/usr/bin/env bash
set -euo pipefail

# Generates ESP32 Secure Boot V2 signing key material for AtomS3R builds.
# Output is written to repo-local .secrets (gitignored) with strict perms.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECRETS_DIR="${ROOT_DIR}/../.secrets/firmware-signing"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
KEY_BASENAME="esp32s3-secureboot-v2-rsa3072-${STAMP}"
KEY_PATH="${SECRETS_DIR}/${KEY_BASENAME}.pem"
MANIFEST_PATH="${SECRETS_DIR}/${KEY_BASENAME}.manifest.txt"
BACKUP_TGZ="${SECRETS_DIR}/${KEY_BASENAME}.backup.tgz"
ESPSECURE="/home/openclaw/.platformio/penv/bin/espsecure.py"

mkdir -p "${SECRETS_DIR}"
umask 077

if [[ ! -x "${ESPSECURE}" ]]; then
  echo "ERROR: espsecure.py not found at ${ESPSECURE}" >&2
  exit 1
fi

"${ESPSECURE}" generate_signing_key --version 2 --scheme rsa3072 "${KEY_PATH}"

# Record fingerprints/digests for inventory.
{
  echo "generated_utc=${STAMP}"
  echo "key_path=${KEY_PATH}"
  echo "sha256_pem=$(sha256sum "${KEY_PATH}" | awk '{print $1}')"
} > "${MANIFEST_PATH}"

# Backup bundle (still local; move this to offline/HSM-backed storage).
tar -C "${SECRETS_DIR}" -czf "${BACKUP_TGZ}" \
  "$(basename "${KEY_PATH}")" \
  "$(basename "${MANIFEST_PATH}")"

chmod 600 "${KEY_PATH}" "${MANIFEST_PATH}" "${BACKUP_TGZ}"

echo "OK"
echo "KEY=${KEY_PATH}"
echo "MANIFEST=${MANIFEST_PATH}"
echo "BACKUP=${BACKUP_TGZ}"
echo "NEXT: move ${BACKUP_TGZ} to offline backup before any eFuse changes"
