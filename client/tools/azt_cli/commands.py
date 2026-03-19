from __future__ import annotations

import argparse
from pathlib import Path

from tools.azt_cli.provision_args import build_forwarded_provision_args
from tools.azt_cli.runner import normalize_passthrough, run_module

REPO_ROOT = Path(__file__).resolve().parents[2]


def cmd_provision_unit(args: argparse.Namespace) -> int:
    forwarded = build_forwarded_provision_args(args)
    forwarded += normalize_passthrough(args.passthrough)
    return run_module("tools.provision_unit", forwarded, REPO_ROOT)

