from __future__ import annotations

import argparse


def build_forwarded_provision_args(args: argparse.Namespace) -> list[str]:
    forwarded: list[str] = []
    if args.port is not None:
        forwarded += ["--port", args.port]
    if args.ip is not None:
        forwarded += ["--ip", args.ip]
    if args.baud is not None:
        forwarded += ["--baud", str(args.baud)]
    if args.ip_timeout is not None:
        forwarded += ["--ip-timeout", str(args.ip_timeout)]
    if args.no_auto_ip:
        forwarded += ["--no-auto-ip"]
    if args.identity is not None:
        forwarded += ["--identity", args.identity]
    if args.wifi_ssid is not None:
        forwarded += ["--wifi-ssid", args.wifi_ssid]
    if args.wifi_password is not None:
        forwarded += ["--wifi-password", args.wifi_password]
    if args.skip_flash:
        forwarded += ["--skip-flash"]
    if args.artifact_dir is not None:
        forwarded += ["--artifact-dir", args.artifact_dir]
    if args.allow_serial_bootstrap:
        forwarded += ["--allow-serial-bootstrap"]
    return forwarded
