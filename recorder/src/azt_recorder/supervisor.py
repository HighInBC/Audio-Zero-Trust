from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, UTC

from .config import RecordingConfig
from .models import DiscoveryAd
from .recorder import RecordingSession


@dataclass
class DeviceWorkerState:
    device_fp: str
    source_ip: str
    name: str
    started_at: datetime
    task: asyncio.Task
    admin_fp: str
    cert_serial: str


class Supervisor:
    def __init__(self, recording_cfg: RecordingConfig) -> None:
        self._workers: dict[str, DeviceWorkerState] = {}
        self._recording_cfg = recording_cfg

    def worker_count(self) -> int:
        return len(self._workers)

    async def ensure_worker(self, ad: DiscoveryAd) -> None:
        fp = ad.device_key_fingerprint_hex
        admin_fp = ad.admin_key_fingerprint_hex.lower().strip()
        cert_serial = ad.certificate_serial.strip()

        if fp in self._workers:
            st = self._workers[fp]
            st.source_ip = ad.source_ip

            # If worker is still active, keep it.
            if not st.task.done():
                return

            # If worker stopped, only allow restart on re-authorization material change.
            if st.admin_fp == admin_fp and st.cert_serial == cert_serial:
                return

        session = RecordingSession(ad=ad, cfg=self._recording_cfg)
        task = asyncio.create_task(session.run_forever(), name=f"rec-{fp[:12]}")
        self._workers[fp] = DeviceWorkerState(
            device_fp=fp,
            source_ip=ad.source_ip,
            name=ad.device_name,
            started_at=datetime.now(UTC),
            task=task,
            admin_fp=admin_fp,
            cert_serial=cert_serial,
        )
        print(f"[worker] START device={ad.device_name} fp={fp[:12]}.. ip={ad.source_ip}")

    async def shutdown(self) -> None:
        for st in self._workers.values():
            st.task.cancel()
        await asyncio.sleep(0)
