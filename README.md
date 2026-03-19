# Audio-Zero-Trust

ESP32 firmware and host tooling for asymmetrically encrypted, integrity-chained live audio streaming.

> ⚠️ **Security notice:** This project is actively under development and is **not yet security hardened**. It may contain security flaws or implementation weaknesses. Do not treat it as production-safe for high-risk environments.

## Canonical firmware app

- `firmware/audio_zero_trust/`
  - main entrypoint: `src/main.cpp`

Current hardware target: **M5Stack ATOM Echo Smart Speaker Dev Kit**.

## Repository scope (publishable)

This repo is kept focused on code, tooling, and specs needed to build, flash, provision, stream, and validate.

- `firmware/` — firmware projects (canonical app is `audio_zero_trust`)
- `client/` — host-side client tooling, SDK, and client tests
- `recorder/` — recorder implementation, tests, and recorder-specific docs
- `spec/` — format/spec documents used by implementations (including `spec/compatibility-policy.md`)

## Quick setup (fresh Linux host)

This flow matches the discrete CLI steps used by E2E.

### 1) Install prerequisites

```bash
sudo apt update
sudo apt install -y \
  git python3 python3-venv python3-pip \
  build-essential python3-serial
```

### 2) Enable serial access (one-time)

```bash
sudo usermod -aG dialout $USER
```

Then log out/login (or reboot) so group membership is applied.

### 3) Clone repository

HTTPS:

```bash
git clone https://github.com/HighInBC/Audio-Zero-Trust.git Audio-Zero-Trust
cd Audio-Zero-Trust
```

SSH:

```bash
git clone git@github.com:HighInBC/Audio-Zero-Trust.git Audio-Zero-Trust
cd Audio-Zero-Trust
```

### 4) Create and activate virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip setuptools wheel
python3 -m pip install platformio cryptography pyserial requests intelhex
```

### 5) Clean device state (recommended for first install / repeatable tests)

```bash
python3 client/tools/azt_tool.py erase-device --port /dev/ttyUSB0
```

### 6) Flash firmware

```bash
python3 client/tools/azt_tool.py flash-device --port /dev/ttyUSB0
```

### 7) Create credentials

Create admin credentials:

```bash
python3 client/tools/azt_tool.py create-signing-credentials --identity admin-main
```

Create recorder credentials (required, RSA decoding keypair):

```bash
python3 client/tools/azt_tool.py create-decoding-credentials --identity recorder-main
```

### 8) Configure device (Wi-Fi + signed config)

Use admin and recorder credentials from step 7:

```bash
python3 client/tools/azt_tool.py configure-device \
  --admin-creds-dir client/tools/provisioned/admin-main \
  --recorder-creds-dir client/tools/provisioned/recorder-main \
  --identity livingroom \
  --wifi-ssid "<YOUR_WIFI_SSID>" \
  --wifi-password "<YOUR_WIFI_PASSWORD>" \
  --port /dev/ttyUSB0 \
  --allow-serial-bootstrap
```

`--recorder-creds-dir` is required: admin signing keys (Ed25519) and recorder decoding keys (RSA) are intentionally different key types.

Set your device IP once for copy/paste-friendly commands:

```bash
export DEVICE_IP="<DEVICE_IP>"
```

### 9) Optional: issue a device certificate from your admin key

```bash
python3 client/tools/azt_tool.py certificate-issue \
  --host "$DEVICE_IP" \
  --key client/tools/provisioned/admin-main/private_key.pem \
  --cert-serial cert-$(date -u +%Y-%m-%dT%H:%M:%SZ)
```

### 10) Validate quickly

```bash
python3 client/tools/azt_tool.py state-get --host "$DEVICE_IP"
python3 client/tools/azt_tool.py stream-probe --host "$DEVICE_IP" --seconds 2
python3 client/tools/azt_tool.py stream-validate --in client/test/hil/sample.bin --key client/tools/provisioned/admin-main/private_key.pem
```

## Test layout

- `client/test/unit/` — client/tooling unit tests
- `client/test/hil/` — host-in-the-loop integration tests
- `firmware/test/audio_zero_trust_tests/` — firmware-targeted tests
- `recorder/test/` — recorder tests (scaffold)

## HTTP ports (stream/API split)

- Control/API endpoints are served on `:8080`.
- Streaming is served on `:8081` (`GET /stream?...`).
- Backward compatibility: `GET /stream` on `:8080` returns `307 Temporary Redirect` to `:8081`.
