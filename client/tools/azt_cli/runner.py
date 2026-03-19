from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def run_module(module_name: str, args: list[str], repo_root: Path) -> int:
    cmd = [sys.executable, "-m", module_name, *args]
    p = subprocess.run(cmd, cwd=str(repo_root))
    return int(p.returncode)


def normalize_passthrough(argv: list[str]) -> list[str]:
    if argv and argv[0] == "--":
        return argv[1:]
    return argv
