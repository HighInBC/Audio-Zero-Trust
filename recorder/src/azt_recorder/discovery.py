from __future__ import annotations

import asyncio
import json
from typing import AsyncIterator

from .models import DiscoveryAd


class DiscoveryProtocol(asyncio.DatagramProtocol):
    def __init__(self, queue: asyncio.Queue[DiscoveryAd]) -> None:
        self.queue = queue

    def datagram_received(self, data: bytes, addr):
        ip, port = addr
        try:
            d = json.loads(data.decode("utf-8", errors="strict"))
        except Exception:
            return

        try:
            ad = DiscoveryAd(
                source_ip=ip,
                source_port=port,
                discovery_version=int(d.get("discovery_version", 0)),
                device_type=str(d.get("device_type", "")),
                device_key_fingerprint_hex=str(d.get("device_key_fingerprint_hex", "")).lower(),
                admin_key_fingerprint_hex=str(d.get("admin_key_fingerprint_hex", "")).lower(),
                device_name=str(d.get("device_name", "")),
                http_port=int(d.get("http_port", 0)),
                certificate_serial=str(d.get("certificate_serial", "")),
                recorder_auth_fingerprint_hex=str(d.get("recorder_auth_fingerprint_hex", "")).lower(),
                cert_auto_record=bool(d.get("cert_auto_record", False)),
                cert_auto_decode=bool(d.get("cert_auto_decode", False)),
                raw=d,
            )
        except Exception:
            return

        if ad.discovery_version != 1:
            return
        if ad.device_type != "audio-zero-trust-microphone":
            return
        if len(ad.device_key_fingerprint_hex) != 64:
            return
        if ad.http_port <= 0:
            return

        self.queue.put_nowait(ad)


async def listen_discovery(udp_port: int) -> AsyncIterator[DiscoveryAd]:
    queue: asyncio.Queue[DiscoveryAd] = asyncio.Queue()
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(
        lambda: DiscoveryProtocol(queue),
        local_addr=("0.0.0.0", udp_port),
    )
    try:
        while True:
            yield await queue.get()
    finally:
        transport.close()
