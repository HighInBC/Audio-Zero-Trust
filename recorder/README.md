# azt-recorder (iteration 1)

Discovery + trust-decision daemon for Audio Zero Trust microphones.

This is NOT yet ready for consumption!

## What this iteration does

- Loads YAML config
- Listens for UDP discovery packets on port 33333
- Parses/validates discovery JSON v1
- Applies trust policy:
  - device fingerprint allowlist
  - admin fingerprint allowlist (certificate required)
- Verifies admin-signed certificate cryptographically before authorizing admin-path devices
- Starts continuous recording workers for authorized devices
- Writes files as: `<CommonName>-<ZuluTime>.azt` (example: `Livingroom-2026-03-13T23:37:39Z.azt`)
- Auto timestamps each completed recording via TSA, producing `<file>.timestamp.tar` (contains tsq/tsr + README)
- Background backfill stamps any `.azt` older than 60s that lacks `.timestamp.tar` and is not currently open by any process
- Reconnects with backoff and rolls over hourly

## Run

```bash
cd projects/azt-recorder
python3 -m pip install -e .
azt-recorder --config config/recorder.yaml
```

## Next iteration

- Add per-device stream workers (`/stream` pull)
- 24/7 auto-restart + hourly rollover
- Persist recorder state/checkpoints
- Dockerfile + compose
