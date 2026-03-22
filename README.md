# Audio-Zero-Trust

Audio-Zero-Trust is an ESP32-based secure audio transport project for environments where stream confidentiality and tamper evidence matter.

It exists to provide:

- **Confidentiality**: audio is encrypted so passive listeners cannot decode content.
- **Integrity & chain-of-custody**: stream/container structures are signed and hash-linked to make tampering detectable.
- **Practical deployability**: device firmware + host tooling + tests in one repo.

> ⚠️ **Security notice:** This project is actively under development and is **not yet security hardened**. Do not treat it as production-safe for high-risk environments.

If you just want to install and run, jump to **[Install](#install)**.

---

## Table of contents

- [What this repository contains](#what-this-repository-contains)
- [Deep dive](#deep-dive)
  - [Feature set](#feature-set)
  - [Security model (current)](#security-model-current)
  - [Threat model / non-goals](#threat-model--non-goals)
  - [Crypto primitives](#crypto-primitives)
- [Install](#install)
- [Client CLI command reference](#client-cli-command-reference)
- [Troubleshooting and recovery playbooks](#troubleshooting-and-recovery-playbooks)
- [Tests](#tests)
- [SDK documentation](#sdk-documentation)

---

## What this repository contains

- `firmware/` — firmware projects (canonical app: `firmware/audio_zero_trust/`)
- `client/` — host tooling (`azt_tool.py`), SDK code, and tests
- `recorder/` — recorder-side implementation and tests
- `spec/` — protocol/container/spec references
- `docs/` — operational documentation (including serial flash profile contracts)

Current hardware target: **M5Stack ATOM Echo Smart Speaker Dev Kit**.

---

## Deep dive

### Feature set (with plain-language context)

#### 1) Recording files are tamper-evident

**What this means:** if someone modifies a recording file after capture, validation should fail.

**How it works:** file content is cryptographically signed by the device and structured so integrity checks break when bytes are altered.

#### 2) Files remain verifiable in both encrypted and unlocked workflows

**What this means:** you can validate that a file is structurally/authentically correct before and after unlock/decode steps.

**How it works:** validation tools check signed headers + integrity fields in both protected and decoded forms.

#### 3) Device identity is carried with recordings

**What this means:** a recording can include evidence of *which device* produced it, not just raw audio bytes.

**How it works:** device certificate/certificate serial and signing identity fields are embedded and cross-checked during validation.

#### 4) Self-describing format

**What this means:** files describe their own schema/version/algorithms so validators know how to parse and verify them.

**How it works:** versioned header fields and explicit algorithm/fingerprint metadata are stored in-band.

#### 5) Certificate-based recording trust path

**What this means:** trust in a recording can be rooted in certificate workflows, not just ad-hoc keys.

**How it works:** certificate issue/post/verify flows bind device identity and signing trust to recording validation.

#### 6) Recorder-side auto-validation

**What this means:** recorder workflows can automatically check provenance/integrity before treating data as valid.

**How it works:** tooling validates signatures, certificate linkage, and header consistency in one pipeline.

#### 7) OTA safety controls (beyond just “update works”)

**What this means:** updates can be restricted to trusted signers and newer versions.

**How it works:** OTA bundles carry signed metadata, signer trust is enforced, and anti-rollback version floors are tracked/applied.

#### 8) Deterministic serial install path for release OTA bundles

**What this means:** users can flash official OTA releases over serial without compiling source locally.

**How it works:** `flash-device --from-ota` uses a deterministic full-layout profile and then applies OTA signer/version/floor state.
(Details: `docs/serial-flash-profiles.md`.)

#### 9) Secure provisioning boundaries

**What this means:** sensitive low-level operations are intentionally separated by trust boundary.

**How it works:** signed HTTP config path is distinct from privileged serial-only controls for bootstrap-level state changes.

#### 10) Discovery with follow-up identity verification

**What this means:** finding a device on the network is not treated as proof of trust by itself.

**How it works:** discovery is followed by cryptographic identity/certificate checks before trust decisions.

#### 11) Time/timestamp awareness

**What this means:** tooling surfaces whether device time is synced or stale, which matters for evidence quality.

**How it works:** device state exposes sync status/timestamps; validators and operators can factor that into trust decisions.

### Security model (current)

At a high level, Audio-Zero-Trust combines:

- **Identity** (device/admin/recorder credentials)
- **Authenticity** (digital signatures)
- **Integrity** (hash/fingerprint checks)
- **Operational controls** (OTA signer/version policy + serial trust boundary)

The system is designed so trust decisions are based on verifiable cryptographic evidence rather than network location or naming alone.

### Threat model / non-goals

Current design intent:

- Make passive interception and silent file tampering difficult/detectable in normal operation.
- Preserve signed control boundaries for config/certificate/OTA workflows.

Current non-goals / caveats:

- Not hardened for advanced physical attack scenarios.
- Not finalized for strong anti-tamper guarantees under full physical access.
- Not audited as a production security product yet.

### Crypto primitives

- **Ed25519**: signing for config/cert/OTA metadata and trust workflows
- **RSA OAEP (SHA-256)**: recorder decoding key workflow
- **SHA-256**: fingerprints/hashes for integrity checks and identity binding

---

## Install

### 1) Prerequisites

```bash
sudo apt update
sudo apt install -y \
  git python3 python3-venv python3-pip \
  build-essential python3-serial
```

### 2) Serial permissions (one-time)

```bash
sudo usermod -aG dialout $USER
```

Then log out/login (or reboot).

### 3) Clone

```bash
git clone https://github.com/HighInBC/Audio-Zero-Trust.git Audio-Zero-Trust
cd Audio-Zero-Trust
```

### 4) Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip setuptools wheel
python3 -m pip install platformio cryptography pyserial requests intelhex
```

### 5) Optional clean slate

```bash
python3 client/tools/azt_tool.py erase-device --port /dev/ttyUSB0
```

### 6) Flash firmware

From source (developer path):

```bash
python3 client/tools/azt_tool.py flash-device --from-source --port /dev/ttyUSB0
```

From release OTA bundle (user/release path):

```bash
python3 client/tools/azt_tool.py flash-device --from-ota firmware/releases/<release>.otabundle --port /dev/ttyUSB0
```

Push a release OTA bundle over the network OTA endpoint:

```bash
python3 client/tools/azt_tool.py ota-bundle-post \
  --host <Host or IP> \
  --in firmware/releases/OTA-Audio-Zero-Trust-20260322.otabundle
```

`--from-ota` validates signed OTA metadata by default and applies OTA signer/version/floor state over serial after flash.

### 7) Create credentials

```bash
python3 client/tools/azt_tool.py create-signing-credentials --identity admin-main
python3 client/tools/azt_tool.py create-decoding-credentials --identity recorder-main
```

### 8) Configure device

```bash
python3 client/tools/azt_tool.py configure-device \
  --admin-creds-dir client/tools/provisioned/admin-main \
  --recorder-creds-dir client/tools/provisioned/recorder-main \
  --identity livingroom \
  --wifi-ssid "<YOUR_WIFI_SSID>" \
  --wifi-password "<YOUR_WIFI_PASSWORD>" \
  --port /dev/ttyUSB0 \
  --mdns-enabled \
  --mdns-hostname azt-mic \
  --allow-serial-bootstrap
```

### 9) Quick validation

```bash
python3 client/tools/azt_tool.py state-get --host azt-mic.local
python3 client/tools/azt_tool.py stream-read --host azt-mic.local --seconds 2
```

---

## Client CLI command reference

Use command help for complete flags:

```bash
python3 client/tools/azt_tool.py --help
python3 client/tools/azt_tool.py <command> --help
```

Major command groups:

- **Flashing / provisioning**
  - `erase-device`
  - `flash-device`
  - `configure-device`
  - `provision-unit`
  - `ip-detect`
- **Credentials / config**
  - `create-signing-credentials`
  - `create-decoding-credentials`
  - `sign-config`
  - `apply-config`
  - `config-patch`
- **State / identity checks**
  - `state-get`
  - `key-match-check`
  - `signing-key-check`
  - `mdns-fqdn-get`
- **Attestation / certificates**
  - `attestation-get`
  - `attestation-verify`
  - `certificate-get`
  - `certificate-issue`
  - `certificate-post`
  - `reboot-device`
- **OTA**
  - `ota-bundle-create`
  - `ota-bundle-post`
  - `flash-device --from-ota ...`
- **Stream tooling**
  - `stream-read`
  - `stream-probe`
  - `stream-redirect-check`
  - `stream-validate`
  - `stream-decode`
- **Detached header workflows**
  - `detached-headers-export`
  - `detached-headers-decode`
  - `detached-headers-combine`
- **Certification utilities**
  - `certify-issue`
  - `verify-certification`

---

## Troubleshooting and recovery playbooks

### Serial permission denied

- Ensure user is in `dialout` group
- Re-login after group change

### mDNS (`.local`) is flaky

- Use direct device IP for OTA/config commands
- Verify with `state-get --host <ip>`

### OTA post times out

- Retry with IP instead of `.local`
- Increase timeout:

```bash
python3 client/tools/azt_tool.py ota-bundle-post --host <ip> --in <bundle> --timeout 180
```

### Device boot loop after bad flash (`flash read err, 1000`)

Recovery:

```bash
python3 client/tools/azt_tool.py erase-device --port /dev/ttyUSB0
python3 client/tools/azt_tool.py flash-device --from-source --port /dev/ttyUSB0
```

Then re-run `configure-device`.

### Validate deterministic OTA serial path

```bash
python3 client/test/hil/flash_from_ota_smoke.py \
  --bundle <bundle.otabundle> \
  --port /dev/ttyUSB0 \
  --firmware-key <signer_private_key.pem> \
  --host <device_ip>
```

---

## Tests

- `client/test/unit/` — client/tooling unit tests
- `client/test/hil/` — host-in-the-loop integration tests (including `flash_from_ota_smoke.py`)
- `firmware/test/audio_zero_trust_tests/` — firmware-targeted tests
- `recorder/test/` — recorder tests (scaffold)

---

## SDK documentation

SDK docs will be split into dedicated docs pages. For now, see:

- `client/tools/azt_sdk/`
- `spec/`
- `docs/serial-flash-profiles.md`
