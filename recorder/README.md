# azt-recorder

Discovery + trust-decision + recording daemon for Audio-Zero-Trust devices.

## Current behavior

- Loads YAML config
- Listens for UDP discovery packets on port `33333`
- Applies trust policy:
  - device fingerprint allowlist
  - admin fingerprint allowlist (certificate required)
- Verifies admin-signed device certificates before recording
- Starts per-device recording workers for authorized devices
- Pulls `/stream` continuously with hourly rollover
- Uses stream challenge nonce flow (`/api/v0/device/stream/challenge`)
- If device has `recorder_auth_key` configured, signs stream start with recorder Ed25519 key
- Writes `.azt` files under configured output path
- Auto-timestamps completed recordings via TSA (`.timestamp.tar`)
- Writes `manifest.json` inside each `.timestamp.tar` (JSON hashes for all archive members)
- Supports OTS sidecar workflow (`.azt.ots`) and embedding upgraded proofs into `.timestamp.tar`

## Run (dev)

```bash
cd recorder
python3 -m pip install -e .
azt-recorder --config config/recorder.yaml
```

## Config notes

- `recording.output_dir`: recording destination inside container/runtime
- `recording.recorder_auth_private_key_path`: optional Ed25519 private key used for stream-start auth signatures
- Keep runtime config/secrets outside git in deployment environments.
