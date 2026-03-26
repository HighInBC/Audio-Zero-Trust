from __future__ import annotations

import asyncio
import base64
import json
import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
import io
import os
import re
import subprocess
import tarfile
import time
import urllib.request

from cryptography.hazmat.primitives.asymmetric import ed25519

from .config import RecordingConfig
from .models import DiscoveryAd


def _sanitize_common_name(name: str) -> str:
    s = name.strip() or "Unknown"
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", s)
    return s[:80]


def make_azt_filename(common_name: str, ts: datetime) -> str:
    # <commonname>-<zulu time>.azt
    # Example: Livingroom-2026-03-13T13:56:02Z.azt
    return f"{_sanitize_common_name(common_name)}-{ts.astimezone(UTC).strftime('%Y-%m-%dT%H:%M:%SZ')}.azt"


class AuthorizationError(RuntimeError):
    pass


def _readline_limited(resp, max_len: int = 1 << 20) -> bytes:
    line = resp.readline(max_len + 1)
    if not line or not line.endswith(b"\n") or len(line) > max_len:
        raise AuthorizationError("stream_header_line_invalid")
    return line


def _preflight_stream_header(resp, expected_device_fp_hex: str) -> bytes:
    prefix = bytearray()

    magic = _readline_limited(resp, max_len=16)
    prefix.extend(magic)
    if magic != b"AZT1\n":
        raise AuthorizationError("stream_magic_invalid")

    header_line = _readline_limited(resp)
    sig_line = _readline_limited(resp)
    prefix.extend(header_line)
    prefix.extend(sig_line)

    header_raw = header_line[:-1]  # remove trailing LF
    try:
        plain = json.loads(header_raw.decode("utf-8"))
    except Exception as e:
        raise AuthorizationError("stream_header_json_invalid") from e

    pub_b64 = str(plain.get("this_header_signing_key_b64") or "")
    fp_hex = str(plain.get("this_header_signing_key_fingerprint_hex") or "").lower().strip()
    if not pub_b64 or len(fp_hex) != 64:
        raise AuthorizationError("stream_header_signing_key_missing")

    try:
        pub_raw = base64.b64decode(pub_b64)
    except Exception as e:
        raise AuthorizationError("stream_header_signing_key_b64_invalid") from e
    calc_fp = hashlib.sha256(pub_raw).hexdigest()
    if calc_fp != fp_hex:
        raise AuthorizationError("stream_header_signing_key_fp_mismatch")

    expected = expected_device_fp_hex.lower().strip()
    if fp_hex != expected:
        raise AuthorizationError("stream_header_signing_key_not_authorized")

    try:
        sig_raw = base64.b64decode(sig_line.strip())
        ed25519.Ed25519PublicKey.from_public_bytes(pub_raw).verify(sig_raw, header_raw)
    except Exception as e:
        raise AuthorizationError("stream_header_signature_invalid") from e

    len_bytes = resp.read(2)
    if len(len_bytes) != 2:
        raise AuthorizationError("stream_next_header_len_missing")
    prefix.extend(len_bytes)
    n = int.from_bytes(len_bytes, "big")
    if n == 0xFFFF:
        dec_line = _readline_limited(resp)
        prefix.extend(dec_line)
    else:
        enc = resp.read(n)
        if len(enc) != n:
            raise AuthorizationError("stream_next_header_bytes_missing")
        prefix.extend(enc)

    return bytes(prefix)


def _run_checked(cmd: list[str], *, err_code: str) -> None:
    p = subprocess.run(cmd, text=True, capture_output=True)
    if p.returncode != 0:
        raise RuntimeError(f"{err_code}: {' '.join(cmd)}\n{p.stdout}\n{p.stderr}")


def timestamp_tar_path(file_path: Path) -> Path:
    return Path(str(file_path) + ".timestamp.tar")


def is_file_in_use(file_path: Path) -> bool:
    # Best-effort open-file check without external dependencies.
    # Compare several path forms because /proc fd symlinks can vary by namespace
    # and may include a trailing " (deleted)" marker.
    candidates = {str(file_path), str(file_path.absolute())}
    try:
        candidates.add(str(file_path.resolve()))
    except Exception:
        pass

    proc_root = Path("/proc")
    for proc_entry in proc_root.iterdir():
        if not proc_entry.name.isdigit():
            continue
        fd_dir = proc_entry / "fd"
        if not fd_dir.exists():
            continue
        try:
            for fd in fd_dir.iterdir():
                try:
                    link = os.readlink(fd)
                except Exception:
                    continue
                for target in candidates:
                    if link == target or link.startswith(target + " ") or link == (target + " (deleted)"):
                        return True
        except Exception:
            continue
    return False


def find_untimestamped_azt_files(output_dir: Path, *, older_than_seconds: int = 10) -> list[Path]:
    # Scale-aware scan:
    # - scope to recent date partitions (today + yesterday), where new rollovers occur
    # - pair files by basename in one pass (.azt vs .azt.timestamp.tar)
    # - run expensive checks (stat/in-use) only on unresolved candidates
    if not output_dir.exists():
        return []

    now = time.time()
    days = [datetime.now(UTC).date(), (datetime.now(UTC) - timedelta(days=1)).date()]

    out: list[Path] = []
    for day in days:
        day_dir = output_dir / day.strftime("%Y") / day.strftime("%m") / day.strftime("%d")
        if not day_dir.exists():
            continue

        azt_files: dict[str, Path] = {}
        ts_done: set[str] = set()

        for p in day_dir.rglob("*"):
            if not p.is_file():
                continue
            name = p.name
            if name.endswith(".azt"):
                azt_files[name] = p
            elif name.endswith(".azt.timestamp.tar"):
                ts_done.add(name[: -len(".timestamp.tar")])

        for name, p in azt_files.items():
            if name in ts_done:
                continue
            try:
                st = p.stat()
            except FileNotFoundError:
                continue
            if (now - st.st_mtime) < older_than_seconds:
                continue
            if is_file_in_use(p):
                continue
            out.append(p)

    out.sort(key=lambda x: x.stat().st_mtime)
    return out


def should_timestamp_file(file_path: Path, *, older_than_seconds: int = 10) -> bool:
    if not file_path.exists() or file_path.stat().st_size <= 0:
        return False
    if timestamp_tar_path(file_path).exists():
        return False
    age = time.time() - file_path.stat().st_mtime
    if age < float(max(0, older_than_seconds)):
        return False
    if is_file_in_use(file_path):
        return False
    return True


def timestamp_recording(file_path: Path, tsa_url: str) -> tuple[Path, Path, Path]:
    tsq_path = Path(str(file_path) + ".tsq")
    tsr_path = Path(str(file_path) + ".tsr")
    tar_path = timestamp_tar_path(file_path)

    _run_checked(
        [
            "openssl",
            "ts",
            "-query",
            "-data",
            str(file_path),
            "-sha256",
            "-cert",
            "-no_nonce",
            "-out",
            str(tsq_path),
        ],
        err_code="ERR_TIMESTAMP_QUERY",
    )

    try:
        req = urllib.request.Request(
            tsa_url,
            data=tsq_path.read_bytes(),
            method="POST",
            headers={"Content-Type": "application/timestamp-query"},
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            tsr_path.write_bytes(resp.read())
    except Exception as e:
        raise RuntimeError(f"ERR_TIMESTAMP_REPLY: {e}") from e

    readme = (
        "AZT Recorder Timestamp Evidence Bundle\n"
        "====================================\n\n"
        "This archive contains RFC 3161 Time-Stamp Protocol artifacts for a recording file.\n\n"
        f"Target recording file: {file_path.name}\n"
        f"TSQ (query) file: {tsq_path.name}\n"
        f"TSR (response token) file: {tsr_path.name}\n"
        f"TSA URL used: {tsa_url}\n\n"
        "Verification example:\n"
        "  openssl ts -verify \\\n"
        f"    -in {tsr_path.name} \\\n"
        f"    -data {file_path.name} \\\n"
        "    -CAfile /etc/ssl/certs/ca-certificates.crt\n\n"
        "If verification returns 'Verification: OK', the TSR matches the target file\n"
        "digest and chains to a trusted certificate authority in your CA bundle.\n"
    ).encode("utf-8")

    with tarfile.open(tar_path, "w") as tf:
        tf.add(tsq_path, arcname=tsq_path.name)
        tf.add(tsr_path, arcname=tsr_path.name)

        info = tarfile.TarInfo(name="README.txt")
        info.size = len(readme)
        tf.addfile(info, fileobj=io.BytesIO(readme))

    # Retain only the combined artifact after successful archive creation.
    tsq_path.unlink(missing_ok=True)
    tsr_path.unlink(missing_ok=True)

    return tsq_path, tsr_path, tar_path


@dataclass
class RecordingSession:
    ad: DiscoveryAd
    cfg: RecordingConfig

    async def run_forever(self) -> None:
        base_out_dir = Path(self.cfg.output_dir)
        base_out_dir.mkdir(parents=True, exist_ok=True)

        while True:
            for backoff in self.cfg.reconnect_backoff_seconds:
                try:
                    await self._run_single_rollover(base_out_dir)
                    # normal rollover => immediate next file
                    break
                except AuthorizationError as e:
                    print(f"[record] AUTH_FAIL device={self.ad.device_name} ip={self.ad.source_ip} err={e}; worker halted pending re-authorization")
                    return
                except Exception as e:
                    print(f"[record] error device={self.ad.device_name} ip={self.ad.source_ip} err={e} backoff={backoff}s")
                    await asyncio.sleep(backoff)
            else:
                await asyncio.sleep(5)

    async def _run_single_rollover(self, base_out_dir: Path) -> None:
        started = datetime.now(UTC)
        date_out_dir = base_out_dir / started.strftime("%Y") / started.strftime("%m") / started.strftime("%d")
        date_out_dir.mkdir(parents=True, exist_ok=True)

        filename = make_azt_filename(self.ad.device_name, started)
        out_path = date_out_dir / filename
        print(f"[record] START device={self.ad.device_name} file={out_path}")

        # Hourly rollover by wall-clock hour; if disabled, use 24h chunk.
        max_seconds = 3600 if self.cfg.hourly_rollover else 86400
        deadline = time.monotonic() + max_seconds

        url = f"{self.ad.base_url}/stream"
        req = urllib.request.Request(url, method="GET")

        stream_err: Exception | None = None
        try:
            # Run blocking network+file write in thread to keep event loop responsive.
            await asyncio.to_thread(self._stream_to_file, req, out_path, deadline)
        except Exception as e:
            stream_err = e
        finally:
            # Do not timestamp immediately on stream end.
            # Timestamping is gated by filesystem-observable completion:
            #   - no .timestamp.tar yet
            #   - mtime older than threshold
            #   - file not open by any process
            # This avoids false-finalization when writer/runtime state is ambiguous
            # (e.g., resets/interruption around rollover).
            if self.cfg.auto_timestamp_on_complete and should_timestamp_file(out_path, older_than_seconds=10):
                try:
                    tsq_path, tsr_path, tar_path = await asyncio.to_thread(
                        timestamp_recording,
                        out_path,
                        self.cfg.timestamp_tsa_url,
                    )
                    print(
                        f"[record] TIMESTAMP device={self.ad.device_name} file={out_path} "
                        f"tsq={tsq_path} tsr={tsr_path} tar={tar_path}"
                    )
                except Exception as e:
                    print(
                        f"[record] TIMESTAMP_ERROR device={self.ad.device_name} file={out_path} "
                        f"tsa={self.cfg.timestamp_tsa_url} err={e}"
                    )

        if stream_err is not None:
            raise stream_err

        print(f"[record] ROLLOVER device={self.ad.device_name} file={out_path}")

    def _stream_to_file(self, req: urllib.request.Request, out_path: Path, deadline_monotonic: float) -> None:
        with urllib.request.urlopen(req, timeout=30) as resp:
            # Enforce authorization at stream start by verifying outer-header signature
            # and binding to the already authorized device signing fingerprint.
            prefix = _preflight_stream_header(resp, self.ad.device_key_fingerprint_hex)

            # RAM-gate file creation: do not create a recording file until we know
            # the stream has produced at least one payload chunk to keep.
            if time.monotonic() >= deadline_monotonic:
                return
            first_chunk = resp.read(4096)
            if not first_chunk:
                return

            with open(out_path, "wb") as f:
                f.write(prefix)
                f.write(first_chunk)

                while True:
                    if time.monotonic() >= deadline_monotonic:
                        return
                    chunk = resp.read(4096)
                    if not chunk:
                        return
                    f.write(chunk)
