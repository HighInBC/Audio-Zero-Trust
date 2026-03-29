from __future__ import annotations

from pathlib import Path

import pytest

from tools.azt_sdk.services import build_service


class _ProcDone:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class _ProcStream:
    def __init__(self, lines: list[str], returncode: int = 0):
        self.stdout = iter(lines)
        self.returncode = returncode

    def wait(self):
        return None


def _patch_repo(monkeypatch, tmp_path: Path):
    repo_root = tmp_path / "repo"
    fw_dir = repo_root / "firmware" / "audio_zero_trust"
    fw_dir.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(build_service, "REPO_ROOT", repo_root)
    monkeypatch.setattr(build_service, "FW_DIR", fw_dir)
    return repo_root, fw_dir


def test_resolve_platformio_prefers_platformio_on_path(monkeypatch):
    monkeypatch.setattr(build_service.shutil, "which", lambda name: "/usr/bin/platformio" if name == "platformio" else None)
    assert build_service.resolve_platformio() == "/usr/bin/platformio"


def test_resolve_platformio_uses_pio_when_platformio_missing(monkeypatch):
    monkeypatch.setattr(build_service.shutil, "which", lambda name: "/usr/bin/pio" if name == "pio" else None)
    assert build_service.resolve_platformio() == "/usr/bin/pio"


def test_resolve_platformio_candidate_fallback(monkeypatch, tmp_path):
    monkeypatch.setattr(build_service.shutil, "which", lambda name: None)
    monkeypatch.setattr(build_service.Path, "home", lambda: tmp_path)

    candidate = tmp_path / ".local" / "bin" / "pio"
    candidate.parent.mkdir(parents=True, exist_ok=True)
    candidate.write_text("#!/bin/sh\n")

    assert build_service.resolve_platformio() == str(candidate)


def test_resolve_platformio_not_found(monkeypatch, tmp_path):
    monkeypatch.setattr(build_service.shutil, "which", lambda name: None)
    monkeypatch.setattr(build_service.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(build_service, "REPO_ROOT", tmp_path / "repo")
    with pytest.raises(FileNotFoundError):
        build_service.resolve_platformio()


def test_run_pio_non_stream(monkeypatch, tmp_path):
    _, fw_dir = _patch_repo(monkeypatch, tmp_path)
    monkeypatch.setattr(build_service, "resolve_platformio", lambda: "pio")
    monkeypatch.setattr(build_service.subprocess, "run", lambda *a, **k: _ProcDone(returncode=2, stdout="o", stderr="e"))

    code, meta, out = build_service._run_pio(env="atom-echo", port="/dev/ttyUSB0", target="upload", stream=False)
    assert code == 2
    assert meta["cwd"] == str(fw_dir)
    assert "upload" in meta["run"]
    assert out == "oe"


def test_run_pio_stream(monkeypatch, tmp_path):
    _, fw_dir = _patch_repo(monkeypatch, tmp_path)
    monkeypatch.setattr(build_service, "resolve_platformio", lambda: "pio")
    monkeypatch.setattr(build_service.subprocess, "Popen", lambda *a, **k: _ProcStream(["a\n", "b\n"], returncode=0))

    code, meta, out = build_service._run_pio(env="atom-echo", port="/dev/ttyUSB0", target="erase", stream=True)
    assert code == 0
    assert meta["cwd"] == str(fw_dir)
    assert out == "a\nb\n"


def test_erase_and_flash_device_wrappers(monkeypatch):
    monkeypatch.setattr(build_service, "_run_pio", lambda **k: (0, {"target": k["target"]}, "ok"))
    assert build_service.erase_device(env="x", port="p")[1]["target"] == "erase"
    assert build_service.flash_device(env="x", port="p")[1]["target"] == "upload"


def test_resolve_esptool_prefers_candidate(monkeypatch, tmp_path):
    repo_root, _ = _patch_repo(monkeypatch, tmp_path)
    monkeypatch.setattr(build_service.Path, "home", lambda: tmp_path)

    candidate = repo_root / ".venv" / "bin" / "esptool.py"
    candidate.parent.mkdir(parents=True, exist_ok=True)
    candidate.write_text("#!/usr/bin/env python\n")

    assert build_service.resolve_esptool() == str(candidate)


def test_resolve_esptool_prefers_non_usr_bin(monkeypatch, tmp_path):
    _patch_repo(monkeypatch, tmp_path)
    monkeypatch.setattr(build_service.Path, "home", lambda: tmp_path)
    monkeypatch.setattr(build_service.shutil, "which", lambda n: "/opt/bin/esptool.py" if n == "esptool.py" else None)
    assert build_service.resolve_esptool() == "/opt/bin/esptool.py"


def test_resolve_esptool_fallback_usr_bin(monkeypatch, tmp_path):
    _patch_repo(monkeypatch, tmp_path)
    monkeypatch.setattr(build_service.Path, "home", lambda: tmp_path)

    def fake_which(name):
        if name == "esptool.py":
            return "/usr/bin/esptool.py"
        if name == "esptool":
            return None
        return None

    monkeypatch.setattr(build_service.shutil, "which", fake_which)
    assert build_service.resolve_esptool() == "/usr/bin/esptool.py"


def test_flash_firmware_bin_missing_firmware(monkeypatch, tmp_path):
    _patch_repo(monkeypatch, tmp_path)
    with pytest.raises(FileNotFoundError, match="firmware bin not found"):
        build_service.flash_firmware_bin(env="atom-echo", port="/dev/ttyUSB0", firmware_bin=str(tmp_path / "missing.bin"))


def test_flash_firmware_bin_missing_profile_artifacts(monkeypatch, tmp_path):
    _patch_repo(monkeypatch, tmp_path)
    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"x")
    with pytest.raises(FileNotFoundError, match="missing deterministic flash-profile artifacts"):
        build_service.flash_firmware_bin(env="atom-echo", port="/dev/ttyUSB0", firmware_bin=str(fw))


def test_flash_firmware_bin_missing_boot_app0(monkeypatch, tmp_path):
    repo_root, fw_dir = _patch_repo(monkeypatch, tmp_path)
    monkeypatch.setattr(build_service.Path, "home", lambda: tmp_path)

    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"x")

    prof = repo_root / "firmware" / "releases" / "flash-profile-v1"
    prof.mkdir(parents=True, exist_ok=True)
    (prof / "bootloader.bin").write_bytes(b"b")
    (prof / "partitions.bin").write_bytes(b"p")

    with pytest.raises(FileNotFoundError, match="boot_app0.bin not found"):
        build_service.flash_firmware_bin(env="atom-echo", port="/dev/ttyUSB0", firmware_bin=str(fw))


def test_flash_firmware_bin_non_stream_success(monkeypatch, tmp_path):
    repo_root, fw_dir = _patch_repo(monkeypatch, tmp_path)
    monkeypatch.setattr(build_service.Path, "home", lambda: tmp_path)

    fw = tmp_path / "fw.bin"
    fw.write_bytes(b"x")

    prof = repo_root / "firmware" / "releases" / "flash-profile-v1"
    prof.mkdir(parents=True, exist_ok=True)
    (prof / "bootloader.bin").write_bytes(b"b")
    (prof / "partitions.bin").write_bytes(b"p")

    boot_app0 = tmp_path / ".platformio" / "packages" / "framework-arduinoespressif32" / "tools" / "partitions" / "boot_app0.bin"
    boot_app0.parent.mkdir(parents=True, exist_ok=True)
    boot_app0.write_bytes(b"a")

    esptool = tmp_path / ".platformio" / "packages" / "tool-esptoolpy" / "esptool.py"
    esptool.parent.mkdir(parents=True, exist_ok=True)
    esptool.write_text("#!/usr/bin/env python\n")

    monkeypatch.setattr(build_service.subprocess, "run", lambda *a, **k: _ProcDone(returncode=0, stdout="ok", stderr=""))

    code, meta, out = build_service.flash_firmware_bin(env="atom-echos3r", port="/dev/ttyUSB0", firmware_bin=str(fw), stream=False)
    assert code == 0
    assert meta["cwd"] == str(fw_dir)
    assert meta["chip"] == "esp32s3"
    assert meta["flash_size"] == "8MB"
    assert out == "ok"
