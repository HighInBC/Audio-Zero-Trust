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


def flash_firmware_bin(*, env: str, port: str, firmware_bin: str, stream: bool = False) -> tuple[int, dict, str]:
    """Flash a specific firmware.bin while reusing PlatformIO upload settings.

    Strategy:
    - ensure build dir exists for env (creates upload metadata)
    - overwrite .pio/build/<env>/firmware.bin with requested binary
    - run upload in nobuild mode
    """
    pio = resolve_platformio()
    fw_src = Path(firmware_bin)
    if not fw_src.exists():
        raise FileNotFoundError(f"firmware bin not found: {fw_src}")

    prep = subprocess.run(
        [pio, "run", "-e", env],
        cwd=str(FW_DIR),
        text=True,
        capture_output=True,
    )
    prep_out = (prep.stdout or "") + (prep.stderr or "")
    if prep.returncode != 0:
        return prep.returncode, {"run": [pio, "run", "-e", env], "cwd": str(FW_DIR)}, prep_out

    build_fw = FW_DIR / ".pio" / "build" / env / "firmware.bin"
    build_fw.parent.mkdir(parents=True, exist_ok=True)
    build_fw.write_bytes(fw_src.read_bytes())

    cmd = [pio, "run", "-e", env, "-t", "nobuild", "-t", "upload", "--upload-port", port]
    if not stream:
        p = subprocess.run(cmd, cwd=str(FW_DIR), text=True, capture_output=True)
        out = prep_out + (p.stdout or "") + (p.stderr or "")
        return p.returncode, {
            "run": cmd,
            "cwd": str(FW_DIR),
            "firmware_bin": str(fw_src),
            "replaced_build_firmware": str(build_fw),
        }, out

    proc = subprocess.Popen(
        cmd,
        cwd=str(FW_DIR),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        bufsize=1,
    )
    chunks: list[str] = [prep_out]
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
        "replaced_build_firmware": str(build_fw),
    }, out
