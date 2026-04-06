from __future__ import annotations

import argparse
import asyncio
import hashlib
from datetime import datetime, UTC
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from .config import load_config
from .discovery import listen_discovery
from .supervisor import Supervisor
from .recorder import find_untimestamped_azt_files, timestamp_recording
from .trust import evaluate_discovery_ad
from .verifier import TrustVerifier


async def run(config_path: str) -> None:
    cfg = load_config(config_path)
    sup = Supervisor(cfg.recording)
    verifier = TrustVerifier(cfg.trust)

    health_file = Path(cfg.recording.output_dir) / ".azt-recorder-heartbeat"
    health_file.parent.mkdir(parents=True, exist_ok=True)

    recorder_auth_fp = ""
    key_path = (cfg.recording.recorder_auth_private_key_path or "").strip()
    if key_path:
        try:
            pem = Path(key_path).read_bytes()
            priv = serialization.load_pem_private_key(pem, password=None)
            pub = priv.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw,
            )
            recorder_auth_fp = hashlib.sha256(pub).hexdigest()
        except Exception as e:
            print(f"[startup] recorder_auth key_load_error path={key_path} err={e}")

    print(f"[startup] discovery udp_port={cfg.discovery.udp_port}")
    print(f"[startup] trust allow_devices={len(cfg.trust.allow_device_fingerprints)} allow_admins={len(cfg.trust.allow_admin_fingerprints)}")
    if recorder_auth_fp:
        print(f"[startup] recorder_auth signer_fp={recorder_auth_fp}")

    async def heartbeat_task() -> None:
        while True:
            ts = datetime.now(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')
            msg = f"[heartbeat] utc={ts} workers={sup.worker_count()}"
            print(msg)
            health_file.write_text(msg + "\n")
            await asyncio.sleep(30)

    async def timestamp_backfill_task() -> None:
        while True:
            await asyncio.sleep(10)
            if not cfg.recording.auto_timestamp_on_complete:
                continue
            out_root = Path(cfg.recording.output_dir)
            candidates = await asyncio.to_thread(find_untimestamped_azt_files, out_root, older_than_seconds=10)
            for p in candidates:
                try:
                    _, _, tar_path = await asyncio.to_thread(timestamp_recording, p, cfg.recording.timestamp_tsa_url)
                    print(f"[timestamp-backfill] file={p} tar={tar_path}")
                except Exception as e:
                    print(f"[timestamp-backfill] ERROR file={p} err={e}")

    hb = asyncio.create_task(heartbeat_task(), name="heartbeat")
    backfill = asyncio.create_task(timestamp_backfill_task(), name="timestamp-backfill")

    try:
        async for ad in listen_discovery(cfg.discovery.udp_port):
            decision = evaluate_discovery_ad(ad, cfg.trust)
            if decision.authorized:
                # Early prefilter from discovery advertisement
                if not ad.cert_auto_record:
                    decision = type(decision)(authorized=False, reason="discovery_cert_missing_auto_record")
                elif (
                    ad.recorder_auth_fingerprint_hex
                    and len(ad.recorder_auth_fingerprint_hex) == 64
                    and recorder_auth_fp
                    and ad.recorder_auth_fingerprint_hex != recorder_auth_fp
                ):
                    decision = type(decision)(authorized=False, reason="discovery_recorder_auth_fp_mismatch")
                else:
                    v = await verifier.verify_admin_certificate(ad)
                    if not v.ok:
                        decision = type(decision)(authorized=False, reason=v.reason)
                    elif "auto-record" not in set(v.authorized_consumers):
                        decision = type(decision)(authorized=False, reason="certificate_missing_auto_record")
                    else:
                        decision = type(decision)(authorized=True, reason="certificate_verified_auto_record_authorized")

            print(
                f"[discovery] ip={ad.source_ip} name={ad.device_name!r} fp={ad.device_key_fingerprint_hex[:12]}.. "
                f"admin={ad.admin_key_fingerprint_hex[:12] if ad.admin_key_fingerprint_hex else '-'} "
                f"cert={ad.certificate_serial or '-'} auto_record={ad.cert_auto_record} auto_decode={ad.cert_auto_decode} "
                f"rec_auth_fp={(ad.recorder_auth_fingerprint_hex[:12] + '..') if ad.recorder_auth_fingerprint_hex else '-'} "
                f"decision={decision.authorized} reason={decision.reason}"
            )
            if decision.authorized:
                await sup.ensure_worker(ad)
    finally:
        hb.cancel()
        backfill.cancel()
        await sup.shutdown()



def main() -> None:
    ap = argparse.ArgumentParser(description="AZT listener daemon (iteration 1)")
    ap.add_argument("--config", default="config/recorder.yaml", help="Path to recorder config yaml")
    args = ap.parse_args()
    asyncio.run(run(args.config))


if __name__ == "__main__":
    main()
