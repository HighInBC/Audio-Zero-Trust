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
import tempfile
import time
import shutil
import urllib.request
import urllib.parse
import urllib.error
import ssl

from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.primitives.asymmetric import ed25519

from .config import RecordingConfig
from .models import DiscoveryAd


def _sanitize_common_name(name: str) -> str:
    s = name.strip() or "Unknown"
    s = re.sub(r"[^A-Za-z0-9._-]+", "_", s)
    return s[:80]


def make_azt_filename(common_name: str, ts_local: datetime, device_id: str = "") -> str:
    # <commonname>-<deviceid>-<local time>-<tz>.azt
    # Example: Livingroom-726244c8de53-2026-03-25T17:56:02-PDT.azt
    ts_local = ts_local.astimezone()
    tz_abbr = ts_local.tzname() or "LOCAL"
    device_id_short = re.sub(r"[^0-9a-fA-F]", "", (device_id or "").strip())[:12].lower()
    if device_id_short:
        return f"{_sanitize_common_name(common_name)}-{device_id_short}-{ts_local.strftime('%Y-%m-%dT%H:%M:%S')}-{tz_abbr}.azt"
    return f"{_sanitize_common_name(common_name)}-{ts_local.strftime('%Y-%m-%dT%H:%M:%S')}-{tz_abbr}.azt"


class AuthorizationError(RuntimeError):
    pass


def _format_runtime_error(e: Exception) -> str:
    if isinstance(e, urllib.error.HTTPError):
        status = getattr(e, "code", "?")
        try:
            body_raw = e.read().decode("utf-8", errors="replace")
        except Exception:
            body_raw = ""
        if body_raw:
            try:
                parsed = json.loads(body_raw)
                if isinstance(parsed, dict):
                    code = parsed.get("error")
                    detail = parsed.get("detail")
                    if code or detail:
                        return f"HTTP {status} error={code} detail={detail}"
            except Exception:
                pass
            return f"HTTP {status} body={body_raw[:240]}"
        return f"HTTP {status}"
    return str(e)


def _readline_limited(resp, max_len: int = 1 << 20) -> bytes:
    line = resp.readline(max_len + 1)
    if not line or not line.endswith(b"\n") or len(line) > max_len:
        raise AuthorizationError("stream_header_line_invalid")
    return line


def _extract_cert_authorized_consumers_from_plain_header(plain: dict) -> set[str]:
    cert_doc = plain.get("device_certificate")
    if not isinstance(cert_doc, dict):
        raise AuthorizationError("stream_header_device_certificate_missing")

    payload_b64 = cert_doc.get("certificate_payload_b64")
    if not isinstance(payload_b64, str) or not payload_b64:
        raise AuthorizationError("stream_header_device_certificate_payload_missing")

    try:
        payload_raw = base64.b64decode(payload_b64)
        payload = json.loads(payload_raw.decode("utf-8"))
    except Exception as e:
        raise AuthorizationError("stream_header_device_certificate_payload_invalid") from e

    consumers = payload.get("authorized_consumers")
    if not isinstance(consumers, list):
        return set()

    out: set[str] = set()
    for item in consumers:
        if isinstance(item, str):
            tok = item.strip()
            if tok:
                out.add(tok)
    return out


def _preflight_stream_header(resp, expected_device_fp_hex: str) -> tuple[bytes, dict]:
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

    cert_consumers = _extract_cert_authorized_consumers_from_plain_header(plain)
    cert_auto_record = "auto-record" in cert_consumers
    header_auto_record = bool(plain.get("stream_header_auto_record") is True)
    if not cert_auto_record:
        raise AuthorizationError("stream_header_cert_missing_auto_record")
    if not header_auto_record:
        raise AuthorizationError("stream_header_missing_auto_record")

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

    return bytes(prefix), plain


def _run_checked(cmd: list[str], *, err_code: str) -> None:
    p = subprocess.run(cmd, text=True, capture_output=True)
    if p.returncode != 0:
        raise RuntimeError(f"{err_code}: {' '.join(cmd)}\n{p.stdout}\n{p.stderr}")


def timestamp_tar_path(file_path: Path) -> Path:
    return Path(str(file_path) + ".timestamp.tar")


def ots_sidecar_path(file_path: Path) -> Path:
    return Path(str(file_path) + ".ots")


def _sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()


def _build_tar_manifest(*, recording_path: Path, members: list[tuple[str, bytes]]) -> bytes:
    generated_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    manifest = {
        "schema": "azt.timestamp.manifest/v1",
        "generated_at_utc": generated_at,
        "recording_file": {
            "name": recording_path.name,
            "sha256": _sha256_bytes(recording_path.read_bytes()),
            "size_bytes": recording_path.stat().st_size,
        },
        "entries": [
            {
                "path": name,
                "sha256": _sha256_bytes(data),
                "size_bytes": len(data),
            }
            for name, data in sorted(members, key=lambda item: item[0])
        ],
    }
    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _write_manifested_timestamp_tar(*, tar_path: Path, recording_path: Path, members: list[tuple[str, bytes]]) -> None:
    manifest_bytes = _build_tar_manifest(recording_path=recording_path, members=members)
    final_members = [*members, ("manifest.json", manifest_bytes)]

    tmp_fd, tmp_name = tempfile.mkstemp(prefix=tar_path.name + ".", suffix=".tmp", dir=str(tar_path.parent))
    os.close(tmp_fd)
    tmp_path = Path(tmp_name)
    try:
        with tarfile.open(tmp_path, "w") as tf:
            for name, data in final_members:
                info = tarfile.TarInfo(name=name)
                info.size = len(data)
                tf.addfile(info, fileobj=io.BytesIO(data))
        tmp_path.replace(tar_path)
    finally:
        tmp_path.unlink(missing_ok=True)


def _read_timestamp_tar_members(tar_path: Path) -> list[tuple[str, bytes]]:
    members: list[tuple[str, bytes]] = []
    with tarfile.open(tar_path, "r") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            if member.name == "manifest.json":
                continue
            extracted = tf.extractfile(member)
            if extracted is None:
                continue
            members.append((member.name, extracted.read()))
    return members


def ots_status_for_recording(file_path: Path) -> str:
    tar_path = timestamp_tar_path(file_path)
    sidecar = ots_sidecar_path(file_path)

    if tar_path.exists():
        try:
            with tarfile.open(tar_path, "r") as tf:
                if any(m.isfile() and m.name.endswith(".ots") for m in tf.getmembers()):
                    return "embedded"
        except Exception:
            # Fall through to sidecar check for recovery workflows.
            pass

    if sidecar.exists():
        return "sidecar"
    return "missing"


def embed_ots_sidecar_into_timestamp_tar(file_path: Path, *, remove_sidecar: bool = True) -> Path:
    tar_path = timestamp_tar_path(file_path)
    sidecar = ots_sidecar_path(file_path)
    if not tar_path.exists():
        raise FileNotFoundError(f"timestamp tar missing: {tar_path}")
    if not sidecar.exists():
        raise FileNotFoundError(f"ots sidecar missing: {sidecar}")

    members = _read_timestamp_tar_members(tar_path)
    ots_arcname = sidecar.name
    ots_data = sidecar.read_bytes()

    replaced = False
    out_members: list[tuple[str, bytes]] = []
    for name, data in members:
        if name == ots_arcname:
            out_members.append((name, ots_data))
            replaced = True
        else:
            out_members.append((name, data))
    if not replaced:
        out_members.append((ots_arcname, ots_data))

    _write_manifested_timestamp_tar(tar_path=tar_path, recording_path=file_path, members=out_members)

    if remove_sidecar:
        sidecar.unlink(missing_ok=True)

    return tar_path


def recording_path_for_timestamp_tar(tar_path: Path) -> Path:
    suffix = ".timestamp.tar"
    name = tar_path.name
    if not name.endswith(suffix):
        raise ValueError(f"not a timestamp tar path: {tar_path}")
    return tar_path.with_name(name[: -len(suffix)])


def _extract_tsr_member_from_tar(tar_path: Path) -> tuple[str, bytes]:
    with tarfile.open(tar_path, "r") as tf:
        for member in tf.getmembers():
            if member.isfile() and member.name.endswith(".tsr"):
                f = tf.extractfile(member)
                if f is None:
                    continue
                return member.name, f.read()
    raise RuntimeError(f"ERR_OTS_NO_TSR_IN_TAR: {tar_path}")


def _run_ots(args: list[str], *, ots_client_cmd: str) -> subprocess.CompletedProcess[str]:
    cmd = [ots_client_cmd, *args]
    return subprocess.run(cmd, text=True, capture_output=True)


def _ots_verify_sidecar_with_tsr(sidecar_path: Path, tsr_bytes: bytes, *, ots_client_cmd: str) -> bool:
    with tempfile.TemporaryDirectory(prefix="azt-ots-verify-") as td:
        tsr_path = Path(td) / "verify_target.tsr"
        tsr_path.write_bytes(tsr_bytes)
        p = _run_ots(["verify", str(sidecar_path), "-f", str(tsr_path)], ots_client_cmd=ots_client_cmd)
        return p.returncode == 0


def _stamp_sidecar_from_tsr_bytes(sidecar_path: Path, tsr_name: str, tsr_bytes: bytes, *, ots_client_cmd: str) -> None:
    with tempfile.TemporaryDirectory(prefix="azt-ots-stamp-") as td:
        target_name = Path(tsr_name).name or "timestamp-response.tsr"
        target_path = Path(td) / target_name
        target_path.write_bytes(tsr_bytes)

        p = _run_ots(["stamp", str(target_path)], ots_client_cmd=ots_client_cmd)
        if p.returncode != 0:
            raise RuntimeError(f"ERR_OTS_STAMP: {p.stdout}\n{p.stderr}".strip())

        stamped_path = Path(str(target_path) + ".ots")
        if not stamped_path.exists():
            raise RuntimeError(f"ERR_OTS_STAMP_NO_OUTPUT: {stamped_path}")
        sidecar_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(stamped_path), str(sidecar_path))


def process_timestamp_tar_ots(tar_path: Path, *, ots_client_cmd: str = "ots") -> str:
    if not tar_path.exists():
        return "missing_tar"

    recording_path = recording_path_for_timestamp_tar(tar_path)
    status = ots_status_for_recording(recording_path)
    if status == "embedded":
        return "already_embedded"

    tsr_name, tsr_bytes = _extract_tsr_member_from_tar(tar_path)
    sidecar = ots_sidecar_path(recording_path)

    if not sidecar.exists():
        _stamp_sidecar_from_tsr_bytes(sidecar, tsr_name, tsr_bytes, ots_client_cmd=ots_client_cmd)

    upgrade_result = _run_ots(["upgrade", str(sidecar)], ots_client_cmd=ots_client_cmd)
    if upgrade_result.returncode != 0:
        return "pending_upgrade"

    if not _ots_verify_sidecar_with_tsr(sidecar, tsr_bytes, ots_client_cmd=ots_client_cmd):
        return "pending_verify"

    embed_ots_sidecar_into_timestamp_tar(recording_path, remove_sidecar=True)
    return "embedded"


def find_timestamp_tars_needing_ots(output_dir: Path, *, older_than_seconds: int = 30) -> list[Path]:
    if not output_dir.exists():
        return []

    now = time.time()
    out: list[Path] = []
    for tar_path in output_dir.rglob("*.azt.timestamp.tar"):
        try:
            st = tar_path.stat()
        except FileNotFoundError:
            continue
        if (now - st.st_mtime) < older_than_seconds:
            continue

        try:
            rec = recording_path_for_timestamp_tar(tar_path)
        except ValueError:
            continue
        if ots_status_for_recording(rec) == "embedded":
            continue
        out.append(tar_path)

    out.sort(key=lambda x: x.stat().st_mtime)
    return out


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
        "AZT Listener Timestamp Evidence Bundle\n"
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

    _write_manifested_timestamp_tar(
        tar_path=tar_path,
        recording_path=file_path,
        members=[
            (tsq_path.name, tsq_path.read_bytes()),
            (tsr_path.name, tsr_path.read_bytes()),
            ("README.txt", readme),
        ],
    )

    # Retain only the combined artifact after successful archive creation.
    tsq_path.unlink(missing_ok=True)
    tsr_path.unlink(missing_ok=True)

    return tsq_path, tsr_path, tar_path


@dataclass
class RecordingSession:
    ad: DiscoveryAd
    cfg: RecordingConfig

    def _build_stream_request(self) -> tuple[urllib.request.Request, str]:
        challenge_url = f"{self.ad.api_https_url}/api/v0/device/stream/challenge"
        # Device TLS is private PKI today; recorder performs application-layer auth checks
        # and uses an unverified TLS context for API bootstrap/challenge fetch.
        insecure_tls = ssl._create_unverified_context()
        with urllib.request.urlopen(challenge_url, timeout=8, context=insecure_tls) as resp:
            ch = json.loads(resp.read().decode("utf-8"))
        if not isinstance(ch, dict) or not ch.get("ok"):
            raise AuthorizationError("stream_challenge_failed")
        nonce = str(ch.get("nonce") or "").strip()
        if not nonce:
            raise AuthorizationError("stream_challenge_missing_nonce")

        params = {"nonce": nonce}
        require_auth = bool(ch.get("recorder_auth_required"))
        key_path = str(self.cfg.recorder_auth_private_key_path or "").strip()
        if require_auth:
            if not key_path:
                raise AuthorizationError("stream_auth_key_required")
            pem = Path(key_path).read_bytes()
            priv = serialization.load_pem_private_key(pem, password=None)
            if not isinstance(priv, ed25519.Ed25519PrivateKey):
                raise AuthorizationError("stream_auth_key_not_ed25519")
            device_fp = str(ch.get("device_sign_fingerprint_hex") or self.ad.device_key_fingerprint_hex).strip().lower()
            msg = f"stream:{nonce}:{device_fp}".encode("utf-8")
            sig_b64 = base64.b64encode(priv.sign(msg)).decode("ascii")
            signer_fp = hashlib.sha256(
                priv.public_key().public_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PublicFormat.Raw,
                )
            ).hexdigest()
            params["sig_alg"] = "ed25519"
            params["sig"] = sig_b64
            params["signer_fp"] = signer_fp
            print(f"[record] stream_auth device={self.ad.device_name} signer_fp={signer_fp} expected_device_fp={device_fp}")

        url = f"{self.ad.stream_http_url}/stream?" + urllib.parse.urlencode(params)
        return urllib.request.Request(url, method="GET"), nonce

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
                    print(f"[record] error device={self.ad.device_name} ip={self.ad.source_ip} err={_format_runtime_error(e)} backoff={backoff}s")
                    await asyncio.sleep(backoff)
            else:
                await asyncio.sleep(5)

    async def _run_single_rollover(self, base_out_dir: Path) -> None:
        pending_dir = base_out_dir / ".pending"
        pending_dir.mkdir(parents=True, exist_ok=True)

        out_path = pending_dir / (f"{_sanitize_common_name(self.ad.device_name)}-pending.azt")
        print(f"[record] START device={self.ad.device_name} file={out_path}")

        # Hourly rollover by wall-clock hour; if disabled, use 24h chunk.
        max_seconds = 3600 if self.cfg.hourly_rollover else 86400
        deadline = time.monotonic() + max_seconds

        req, expected_nonce = self._build_stream_request()

        stream_err: Exception | None = None
        try:
            # Run blocking network+file write in thread to keep event loop responsive.
            out_path = await asyncio.to_thread(self._stream_to_file, req, expected_nonce, base_out_dir, out_path, deadline)
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

    def _stream_to_file(self, req: urllib.request.Request, expected_nonce: str, base_out_dir: Path, out_path: Path, deadline_monotonic: float) -> Path:
        with urllib.request.urlopen(req, timeout=30) as resp:
            # Enforce authorization at stream start by verifying outer-header signature
            # and binding to the already authorized device signing fingerprint.
            prefix, plain_header = _preflight_stream_header(resp, self.ad.device_key_fingerprint_hex)
            header_nonce = str(plain_header.get("stream_auth_nonce") or "").strip()
            if not header_nonce or header_nonce != expected_nonce:
                raise AuthorizationError("stream_auth_nonce_mismatch")

            # Use signed device recording start time as filename basis (local timezone).
            recording_started_utc = str(plain_header.get("recording_started_utc") or "").strip()
            started_local = datetime.now().astimezone()
            if recording_started_utc:
                try:
                    started_utc = datetime.fromisoformat(recording_started_utc.replace("Z", "+00:00"))
                    started_local = started_utc.astimezone()
                except Exception:
                    pass

            final_dir = base_out_dir / started_local.strftime("%Y") / started_local.strftime("%m") / started_local.strftime("%d")
            final_dir.mkdir(parents=True, exist_ok=True)
            final_path = final_dir / make_azt_filename(self.ad.device_name, started_local, self.ad.device_key_fingerprint_hex)

            # RAM-gate file creation: do not create a recording file until we know
            # the stream has produced at least one payload chunk to keep.
            if time.monotonic() >= deadline_monotonic:
                return final_path
            first_chunk = resp.read(4096)
            if not first_chunk:
                return final_path

            with open(final_path, "wb") as f:
                f.write(prefix)
                f.write(first_chunk)

                while True:
                    if time.monotonic() >= deadline_monotonic:
                        return final_path
                    chunk = resp.read(4096)
                    if not chunk:
                        return final_path
                    f.write(chunk)
