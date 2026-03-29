from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[4]
FW_DIR = REPO_ROOT / "firmware" / "audio_zero_trust"


def resolve_platformio() -> str:
    pio = shutil.which("platformio")
    if pio:
        return pio
    pio = shutil.which("pio")
    if pio:
        return pio

    candidates = [
        Path.home() / ".local" / "bin" / "pio",
        Path.home() / ".local" / "bin" / "platformio",
        REPO_ROOT / ".venv" / "bin" / "platformio",
        Path(sys.executable).resolve().parent / "platformio",
    ]
    for c in candidates:
        try:
            if c.exists() and c.is_file() and c.resolve().exists():
                return str(c)
        except OSError:
            pass
    raise FileNotFoundError("platformio not found (install in .venv or ensure platformio/pio is on PATH)")


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
        REPO_ROOT / ".venv" / "bin" / "esptool",
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
    """Flash OTA payload with deterministic full image layout (v1 profile).

    Uses the same offsets/segments as source upload for ESP32:
      0x1000  bootloader.bin
      0x8000  partitions.bin
      0xe000  boot_app0.bin
      0x10000 <OTA payload firmware.bin>

    Bootloader/partitions are taken from release flash profile when present,
    else from local .pio build artifacts for the selected env.
    """
    fw_src = Path(firmware_bin)
    if not fw_src.exists():
        raise FileNotFoundError(f"firmware bin not found: {fw_src}")

    prof_dir = REPO_ROOT / "firmware" / "releases" / "flash-profile-v1"
    pio_build = FW_DIR / ".pio" / "build" / env

    bootloader = prof_dir / "bootloader.bin"
    partitions = prof_dir / "partitions.bin"
    if not bootloader.exists():
        bootloader = pio_build / "bootloader.bin"
    if not partitions.exists():
        partitions = pio_build / "partitions.bin"

    if not bootloader.exists() or not partitions.exists():
        missing = []
        if not bootloader.exists():
            missing.append(str(bootloader))
        if not partitions.exists():
            missing.append(str(partitions))
        raise FileNotFoundError(
            "missing deterministic flash-profile artifacts. "
            "Provide firmware/releases/flash-profile-v1/{bootloader.bin,partitions.bin} "
            "or ensure local .pio build artifacts exist for env. Missing: " + ", ".join(missing)
        )

    boot_app0 = Path.home() / ".platformio" / "packages" / "framework-arduinoespressif32" / "tools" / "partitions" / "boot_app0.bin"
    if not boot_app0.exists():
        raise FileNotFoundError(f"boot_app0.bin not found: {boot_app0}")

    # Prefer tool-esptoolpy from PlatformIO package set to match source upload path.
    esptool = Path.home() / ".platformio" / "packages" / "tool-esptoolpy" / "esptool.py"
    if not esptool.exists():
        esptool = Path(resolve_esptool())

    esptool_cmd = [str(esptool)]
    if str(esptool).endswith('.py'):
        py = sys.executable
        pio_penv_py = Path.home() / '.platformio' / 'penv' / 'bin' / 'python'
        if str(esptool).startswith(str(Path.home() / '.platformio' / 'packages')) and pio_penv_py.exists():
            py = str(pio_penv_py)
        esptool_cmd = [py, str(esptool)]

    chip = "esp32s3" if env == "atom-echos3r" else "esp32"
    flash_size = "8MB" if env == "atom-echos3r" else "4MB"

    cmd = [
        *esptool_cmd,
        "--chip",
        chip,
        "--port",
        port,
        "--baud",
        "115200",
        "--before",
        "default_reset",
        "--after",
        "hard_reset",
        "write_flash",
        "-z",
        "--flash_mode",
        "dio",
        "--flash_freq",
        "40m",
        "--flash_size",
        flash_size,
        "0x1000",
        str(bootloader),
        "0x8000",
        str(partitions),
        "0xe000",
        str(boot_app0),
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
            "flash_method": "esptool_deterministic_v1_full_layout",
            "bootloader_bin": str(bootloader),
            "partitions_bin": str(partitions),
            "boot_app0_bin": str(boot_app0),
            "app_offset": "0x10000",
            "chip": chip,
            "flash_size": flash_size,
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
        "flash_method": "esptool_deterministic_v1_full_layout",
        "bootloader_bin": str(bootloader),
        "partitions_bin": str(partitions),
        "boot_app0_bin": str(boot_app0),
        "app_offset": "0x10000",
        "chip": chip,
        "flash_size": flash_size,
    }, out
