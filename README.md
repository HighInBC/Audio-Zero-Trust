# Audio-Zero-Trust

Audio-Zero-Trust is an ESP32-based secure audio transport project for environments where stream confidentiality and tamper evidence matter.

It exists to provide:

- **Confidentiality**: audio is encrypted so passive listeners cannot decode content.
- **Integrity & chain-of-custody**: stream/container structures are signed and hash-linked to make tampering detectable.
- **Practical deployability**: device firmware + host tooling + tests in one repo.

> ⚠️ **Security notice:** This project is actively under development and is **not yet security hardened**. Do not treat it as production-safe for high-risk environments.

## Contributing

This project is in an early stage and has not been audited. It likely contains bugs, edge cases, and incomplete areas.

Additional eyes are extremely valuable—especially around:
- correctness and edge cases
- security assumptions and failure modes
- protocol and format design
- tooling and usability

If you find issues, please open an issue. Pull requests and design discussions are very welcome.

---

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
- `recorder/` — recorder daemon implementation and tests
- `spec/` — protocol/container/spec references
- `docs/` — operational documentation (including serial flash profile contracts)

Recommended hardware target: **M5Stack ATOM EchoS3R** ([official docs](https://docs.m5stack.com/en/core/Atom_EchoS3R)).
Legacy/alternate target: **M5Stack ATOM Echo Smart Speaker Dev Kit**.

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

#### 6) Listener-side auto-validation

**What this means:** listener workflows can automatically check provenance/integrity before treating data as valid.

**How it works:** tooling validates signatures, certificate linkage, and header consistency in one pipeline.

#### 7) OTA safety controls

**What this means:** updates can be restricted to trusted signers and newer versions.

**How it works:** OTA bundles carry signed metadata, signer trust is enforced, and anti-rollback version floors are tracked/applied.

#### 8) Deterministic serial install path for release OTA bundles

**What this means:** users can flash official OTA releases over serial without compiling source locally.

**How it works:** `flash-device --from-ota` uses a deterministic full-layout profile and then applies OTA signer/version/floor state.
(Details: `docs/serial-flash-profiles.md`.)

#### 9) Bring-your-own OTA signer key (custom release authority)

**What this means:** you can replace the default embedded OTA signer trust with your own firmware signing key.

**How it works:**

- you sign OTA bundles with your private key,
- devices are configured (serial-privileged path) to trust the matching public key,
- OTA verification accepts only bundles from trusted signer keys.

If you control the signer key, you control what firmware the device will accept via OTA.

#### 10) Secure provisioning boundaries

**What this means:** sensitive low-level operations are intentionally separated by trust boundary.

**How it works:** signed HTTP config path is distinct from privileged serial-only controls for bootstrap-level state changes.

#### 11) Discovery with follow-up identity verification

**What this means:** finding a device on the network is not treated as proof of trust by itself.

**How it works:** discovery is followed by cryptographic identity/certificate checks before trust decisions.

#### 12) Time/timestamp awareness

**What this means:** Recording tool create's third party timstamp certificates on finished recording, establishing a no-later-than date for the recording.

**How it works:** When the listener finishes a file it immediately sends a hash of it to the digicert TSA RFC 3161 server. The server responds with a signed timestamp of the hash which is then stored with the recording.

### Security model (current)

At a high level, Audio-Zero-Trust combines:

- **Identity** (device/admin/listener credentials)
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
- **RSA OAEP (SHA-256)**: listener decoding key workflow
- **SHA-256**: fingerprints/hashes for integrity checks and identity binding

---

## Install

> **Hardware recommendation:** Use **M5Stack ATOM EchoS3R** for new installs (`--target atom-echos3r`). Hardware page: <https://docs.m5stack.com/en/core/Atom_EchoS3R>.

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
python3 -m pip install -r requirements.txt
```

`requirements.txt` includes runtime CLI deps like `PyYAML` and `pyserial`.

### 5) Optional clean slate

```bash
python3 client/tools/azt_tool.py erase-device --port /dev/ttyUSB0 --target atom-echos3r
# legacy: --target atom-echo
```

### 6) Flash firmware

From source (developer path):

```bash
python3 client/tools/azt_tool.py flash-device --from-source --port /dev/ttyUSB0 --target atom-echos3r
# legacy: --target atom-echo
```

From release OTA bundle (user/release path):

```bash
python3 client/tools/azt_tool.py flash-device --from-ota firmware/releases/<release>.otabundle --port /dev/ttyUSB0 --target atom-echos3r
# legacy: --target atom-echo
```

**First-flash / bring-up notes (Atom EchoS3R):**

- A brand-new device may need to be placed into programming mode manually:
  - Hold the **side** button
  - Press the **top** button
  - Release the **side** button
- After the first successful flash, press the **side** button once again before running `configure-device`.

Push a release OTA bundle over the network OTA endpoint:

```bash
python3 client/tools/azt_tool.py ota-bundle-post \
  --host <Host or IP> \
  --in firmware/releases/OTA-Audio-Zero-Trust-20260322.otabundle \
  --admin-key client/tools/provisioned/admin-main/private_key.pem
```

`--from-ota` validates signed OTA metadata by default and applies OTA signer/version/floor state over serial after flash.

### 6b) Use your own firmware signer key (custom OTA authority)

Generate a firmware signing keypair:

```bash
python3 client/tools/azt_tool.py create-signing-credentials --identity firmware-master
```

Configure device trust to that signer using serial-privileged config path:

```bash
python3 client/tools/azt_tool.py configure-device \
  --admin-creds-dir client/tools/provisioned/admin-main \
  --listener-creds-dir client/tools/provisioned/listener-main \
  --identity livingroom \
  --wifi-ssid "<YOUR_WIFI_SSID>" \
  --wifi-password "<YOUR_WIFI_PASSWORD>" \
  --port /dev/ttyUSB0 \
  --allow-serial-bootstrap \
  --ota-signer-public-key-pem client/tools/provisioned/firmware-master/public_key_b64.txt
```

Compile current source, sign OTA metadata with your firmware key, and output bundle in one command:

```bash
python3 client/tools/azt_tool.py ota-bundle-create \
  --firmware-key client/tools/provisioned/firmware-master/private_key.pem \
  --target atom-echos3r \
  --version-code timestamp \
  --rollback-floor-code same \
  --out firmware/releases/OTA-Audio-Zero-Trust-$(date -u +%Y%m%d).otabundle
# legacy: --target atom-echo
```

You can use `--post --host <device> --admin-key <admin_private_key.pem>` instead of `--out` to create and immediately post upgrade payload.

High-level flow:

1. Serial-configure device trust to your signer key.
2. Build + sign release OTA bundle with your private key.
3. Install via OTA endpoint (`ota-bundle-post`) or serial (`flash-device --from-ota`).

### 7) Create credentials

```bash
python3 client/tools/azt_tool.py create-signing-credentials --identity admin-main
python3 client/tools/azt_tool.py create-decoding-credentials --identity listener-main
```

### 8) Configure device (TLS bootstrap included by default)

```bash
python3 client/tools/azt_tool.py configure-device \
  --admin-creds-dir client/tools/provisioned/admin-main \
  --listener-creds-dir client/tools/provisioned/listener-main \
  --recorder-auth-creds-dir client/tools/provisioned/recorder-main \
  --identity livingroom \
  --wifi-ssid "<YOUR_WIFI_SSID>" \
  --wifi-password "<YOUR_WIFI_PASSWORD>" \
  --port /dev/ttyUSB0 \
  --mdns-enabled \
  --mdns-hostname azt-mic \
  --allow-serial-bootstrap
```

By default, `configure-device` now auto-runs TLS bootstrap **only when TLS is not already configured** on the device.

Optional controls:
- `--no-tls-bootstrap` to disable auto TLS bootstrap
- `--tls-valid-days <days>` to set issued cert validity
- `--tls-reboot-wait-seconds <seconds>` to control post-reboot verification wait

Patch recorder auth key without serial reflash:

```bash
python3 client/tools/azt_tool.py config-patch \
  --host azt-mic.local \
  --recorder-auth-key client/tools/provisioned/recorder-main \
  --json
```

### 9) Manual one-command TLS bootstrap (when needed)

If you want to run TLS setup explicitly (outside `configure-device`):

```bash
python3 client/tools/azt_tool.py tls-bootstrap \
  --host azt-mic.local \
  --key client/tools/provisioned/admin-main/private_key.pem
```

What `tls-bootstrap` does:
- creates local CA material if missing (or uses provided `--ca-key/--ca-cert`)
- issues + installs device TLS cert over HTTP bootstrap path
- verifies HTTPS on `8443`
- reboots and re-checks only if HTTPS is not initially reachable

Export/import CA public cert for verifier-only clients:

```bash
python3 client/tools/azt_tool.py tls-ca-export --out ca_public.pem
# on another client:
python3 client/tools/azt_tool.py tls-ca-import --in ca_public.pem
```

Port behavior:
- API/control plaintext HTTP: `8080` (bootstrap/fallback)
- API/control HTTPS: `8443` (primary after TLS bootstrap)
- Stream endpoint remains plain HTTP: `8081`

### 10) Quick validation

```bash
# API/control over HTTPS (CA is auto-discovered from client/tools/pki by default)
python3 client/tools/azt_tool.py state-get --host azt-mic.local --port 8443

# stream remains plain HTTP, but is nonce-gated.
# if recorder_auth_key is configured on device, --key must be provided.
python3 client/tools/azt_tool.py stream-read --host azt-mic.local --seconds 2 --key client/tools/provisioned/admin-main/private_key.pem
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
- **TLS (minimal CA workflow)**
  - `tls-bootstrap` (preferred one-command flow)
  - `tls-ca-init`
  - `tls-ca-status`
  - `tls-ca-export`
  - `tls-ca-import`
  - `tls-cert-issue` (advanced/manual)
  - `tls-status`
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

### OTA post times out

- Retry with IP instead of `.local`
- Increase timeout:

```bash
python3 client/tools/azt_tool.py ota-bundle-post --host <ip> --in <bundle> --timeout 180
```

### Device boot loop after bad flash (`flash read err, 1000`)

Recovery:

```bash
python3 client/tools/azt_tool.py erase-device --port /dev/ttyUSB0 --target atom-echos3r
python3 client/tools/azt_tool.py flash-device --from-source --port /dev/ttyUSB0 --target atom-echos3r
# legacy: use --target atom-echo for Atom Echo hardware
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

- `client/test/unit_sdk/` — Python SDK unit test suite (service-level unit tests with mocks)
- `client/test/hil/` — host-side SDK/CLI integration tests (including `flash_from_ota_smoke.py`)
- `firmware/test/unit/` — C++ unit test suites for shared/firmware libraries
- `firmware/test/audio_zero_trust_tests/` — firmware unit-test runner project (PlatformIO)

Run SDK unit tests:

```bash
cd Audio-Zero-Trust
./.venv/bin/python -m pytest client/test/unit_sdk -q
```
- `recorder/tests/` — recorder daemon tests

---

## SDK documentation

SDK docs will be split into dedicated docs pages. For now, see:

- `client/tools/azt_sdk/`
- `spec/`
- `docs/serial-flash-profiles.md`
