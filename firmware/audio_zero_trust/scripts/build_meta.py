import os
import subprocess
from datetime import datetime, timezone

Import("env")


def _safe_git_short() -> str:
    try:
        out = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"], stderr=subprocess.DEVNULL, text=True).strip()
        return out or "nogit"
    except Exception:
        return "nogit"


build_number = os.getenv("AZT_BUILD_NUMBER", "dev")
build_id = os.getenv("AZT_BUILD_ID", f"{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{_safe_git_short()}")

# Define as C string literals.
env.Append(
    CPPDEFINES=[
        ("AZT_BUILD_NUMBER", f"{build_number}"),
        ("AZT_BUILD_ID", f"{build_id}"),
    ]
)

print(f"[build_meta] AZT_BUILD_NUMBER={build_number} AZT_BUILD_ID={build_id}")
