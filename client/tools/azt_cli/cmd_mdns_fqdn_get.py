from __future__ import annotations

import argparse

from tools.azt_cli.output import emit_envelope
from tools.azt_sdk.services.device_service import mdns_fqdn_get


def run(args: argparse.Namespace) -> int:
    ok, payload = mdns_fqdn_get(host=args.host, port=int(args.port), timeout=int(args.timeout))
    as_json = bool(getattr(args, "as_json", False))
    if as_json:
        emit_envelope(
            command="mdns-fqdn-get",
            ok=ok,
            payload=payload,
            error=None if ok else "MDNS_FQDN_GET_FAILED",
            as_json=True,
        )
        return 0 if ok else 1

    if ok:
        print(str(payload.get("mdns_fqdn") or ""))
        return 0

    emit_envelope(
        command="mdns-fqdn-get",
        ok=False,
        payload=payload,
        error="MDNS_FQDN_GET_FAILED",
        as_json=False,
    )
    return 1
