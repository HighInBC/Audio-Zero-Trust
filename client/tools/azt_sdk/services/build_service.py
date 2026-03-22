from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
FW_DIR = REPO_ROOT / "firmware" / "audio_zero_trust"


def resolve_platformio() -> str:
    candidates = [
        REPO_ROOT / ".venv" / "bin" / "platformio",
        Path(sys.executable).resolve().parent / "platformio",
    ]
    for c in candidates:
        if c.exists() and c.is_file():
            return str(c)
    pio = shutil.which("platformio")
    if pio:
        return pio
    raise FileNotFoundError("platformio not found (install in .venv or ensure it is on PATH)")


def _run_pio(*, env: str, port: str, target: str, stream: bool) -> tuple[int, dict, str]:
    pio = resolve_platformio()
    cmd = [pio, "run", "-e", env, "-t", target, "--upload-port", port]

    if not stream:
        p = subprocess.run(cmd, cwd=str(FW_DIR), text=True, capture_output=True)
        out = (p.stdout or "") + (p.stderr or "")
        return p.returncode, {"run": cmd, "cwd": str(FW_DIR)}, out

    proc = subprocess.Popen(
        cmd,
        cwd=str(FW_DIR),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
    )
    chunks: list[str] = []
    assert proc.stdout is not None
    for line in proc.stdout:
        print(line, end="")
        chunks.append(line)
    proc.wait()
    out = "".join(chunks)
    return int(proc.returncode or 0), {"run": cmd, "cwd": str(FW_DIR)}, out


def erase_device(*, env: str, port: str, stream: bool = False) -> tuple[int, dict, str]:
    return _run_pio(env=env, port=port, target="erase", stream=stream)


def flash_device(*, env: str, port: str, stream: bool = False) -> tuple[int, dict, str]:
    return _run_pio(env=env, port=port, target="upload", stream=stream)


def resolve_esptool() -> str:
    # Prefer repo/platformio managed tools before host-global installs.
    # Some distro-packaged /usr/bin/esptool installs are incomplete (missing stubs).
    candidates = [
        REPO_ROOT / ".venv" / "bin" / "esptool.py",
        Path.home() / ".platformio" / "penv" / "bin" / "esptool.py",
        Path.home() / ".platformio" / "penv" / "bin" / "esptool",
        Path(sys.executable).resolve().parent / "esptool.py",
        Path(sys.executable).resolve().parent / "esptool",
    ]
    for c in candidates:
        if c.exists() and c.is_file():
            return str(c)

    esp_py = shutil.which("esptool.py")
    if esp_py and not esp_py.startswith("/usr/bin/"):
        return esp_py
    esp = shutil.which("esptool")
    if esp and not esp.startswith("/usr/bin/"):
        return esp

    if esp_py:
        return esp_py
    if esp:
        return esp
    raise FileNotFoundError("esptool not found (install via platformio penv or PATH)")


def flash_firmware_bin(*, env: str, port: str, firmware_bin: str, stream: bool = False) -> tuple[int, dict, str]:
    """Flash a specific app firmware.bin deterministically via esptool.

    OTA-bundle serial install should only replace the app partition payload
    (offset 0x10000 on this board profile), leaving bootloader/partitions intact.
    """
    _ = env  # kept for callsite compatibility and payload traceability.
    fw_src = Path(firmware_bin)
    if not fw_src.exists():
        raise FileNotFoundError(f"firmware bin not found: {fw_src}")

    esptool = resolve_esptool()
    cmd = [
        esptool,
        "--chip",
        "esp32",
        "--port",
        port,
        "--baud",
        "115200",
        "--no-stub",
        "write_flash",
        "-z",
        "0x10000",
        str(fw_src),
    ]

    if not stream:
        p = subprocess.run(cmd, cwd=str(FW_DIR), text=True, capture_output=True)
        out = (p.stdout or "") + (p.stderr or "")
        return p.returncode, {
            "run": cmd,
            "cwd": str(FW_DIR),
            "firmware_bin": str(fw_src),
            "flash_method": "esptool_write_flash_app",
            "app_offset": "0x10000",
        }, out

    proc = subprocess.Popen(
        cmd,
        cwd=str(FW_DIR),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
    )
    chunks: list[str] = []
    assert proc.stdout is not None
    for line in proc.stdout:
        print(line, end="")
        chunks.append(line)
    proc.wait()
    out = "".join(chunks)
    return int(proc.returncode or 0), {
        "run": cmd,
        "cwd": str(FW_DIR),
        "firmware_bin": str(fw_src),
        "flash_method": "esptool_write_flash_app",
        "app_offset": "0x10000",
    }, out
