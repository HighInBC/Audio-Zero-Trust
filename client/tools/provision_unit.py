#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
import re
import subprocess
import sys
import time
import shutil
from pathlib import Path


CLIENT_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[2]
if str(CLIENT_ROOT) not in sys.path:
    sys.path.insert(0, str(CLIENT_ROOT))

from tools.azt_client.http import http_json
from tools.azt_client.crypto import gen_rsa_keypair_with_fingerprint
from cryptography.hazmat.primitives import serialization
import hashlib
from tools.azt_client.config import make_unsigned_config, make_signed_config

FW_DIR = REPO_ROOT / 'firmware' / 'audio_zero_trust'


def _resolve_platformio() -> str:
    candidates = [
        REPO_ROOT / '.venv' / 'bin' / 'platformio',
        Path(sys.executable).resolve().parent / 'platformio',
    ]
    for c in candidates:
        if c.exists() and c.is_file():
            return str(c)
    pio = shutil.which('platformio')
    if pio:
        return pio
    raise FileNotFoundError('platformio not found (install in .venv or ensure it is on PATH)')


def run(cmd: list[str], cwd: Path | None = None):
    print({'run': cmd, 'cwd': str(cwd) if cwd else None})
    subprocess.run(cmd, cwd=str(cwd) if cwd else None, check=True)


def gen_keypair(out_dir: Path):
    pub_pem, fp, _ = gen_rsa_keypair_with_fingerprint(out_dir)
    return pub_pem, fp


def _pub_and_fp_from_public_key_obj(pub) -> tuple[str, str]:
    pub_pem = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    pub_der = pub.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    fp = hashlib.sha256(pub_der).hexdigest()
    return pub_pem, fp


def _pub_and_fp_from_private_key_path(priv_path: Path) -> tuple[str, str]:
    priv = serialization.load_pem_private_key(priv_path.read_bytes(), password=None)
    return _pub_and_fp_from_public_key_obj(priv.public_key())


def _pub_and_fp_from_public_key_path(pub_path: Path) -> tuple[str, str]:
    pub = serialization.load_pem_public_key(pub_path.read_bytes())
    return _pub_and_fp_from_public_key_obj(pub)


def _pub_and_fp_from_key_file(key_path: Path) -> tuple[str, str]:
    data = key_path.read_bytes()
    # Try private key first (admin flow), then public key (recorder flow).
    try:
        priv = serialization.load_pem_private_key(data, password=None)
        return _pub_and_fp_from_public_key_obj(priv.public_key())
    except Exception:
        pub = serialization.load_pem_public_key(data)
        return _pub_and_fp_from_public_key_obj(pub)


def load_keypair_from_artifact_dir(artifact_dir: Path) -> tuple[str, str]:
    # Backward-compatible behavior:
    # - preferred: credentials directory containing public_key.pem + fingerprint.txt
    # - also accepted: private/public key PEM path (fingerprint/public key are derived)
    # - also accepted: directory containing only private/public key PEM (derived)
    if artifact_dir.is_file():
        return _pub_and_fp_from_key_file(artifact_dir)

    pub_path = artifact_dir / 'public_key.pem'
    if not pub_path.exists():
        pub_path = artifact_dir / 'admin_public_key.pem'
    fp_path = artifact_dir / 'fingerprint.txt'

    if pub_path.exists() and fp_path.exists():
        pub_pem = pub_path.read_text()
        fp = fp_path.read_text().strip()
        if len(fp) != 64:
            raise ValueError(f'invalid fingerprint in {fp_path}')
        return pub_pem, fp

    if pub_path.exists():
        return _pub_and_fp_from_public_key_path(pub_path)

    priv_path = artifact_dir / 'private_key.pem'
    if not priv_path.exists():
        priv_path = artifact_dir / 'admin_private_key.pem'
    if priv_path.exists():
        return _pub_and_fp_from_private_key_path(priv_path)

    raise FileNotFoundError(
        f'missing key artifacts in {artifact_dir} (expected public/private PEM, optionally with fingerprint.txt)'
    )


def find_artifacts_for_fingerprint(fp_hex: str) -> list[Path]:
    out: list[Path] = []
    prov = CLIENT_ROOT / 'tools' / 'provisioned'
    if not prov.exists():
        return out
    for d in prov.iterdir():
        if not d.is_dir():
            continue
        f = d / 'fingerprint.txt'
        if not f.exists():
            continue
        try:
            if f.read_text().strip() == fp_hex:
                out.append(d)
        except Exception:
            pass
    return sorted(out)


def make_bootstrap(identity: str, pub_pem: str, fp: str, wifi_ssid: str, wifi_password: str) -> dict:
    return make_unsigned_config(identity, pub_pem, fp, wifi_ssid, wifi_password)


def detect_device_ip_from_serial(port: str, baud: int = 115200, timeout_s: int = 20) -> str | None:
    try:
        import serial  # type: ignore
    except Exception:
        print({'warn': 'pyserial not available; cannot auto-detect IP from serial'})
        return None

    ip_re = re.compile(r'AZT_IP=(\d+\.\d+\.\d+\.\d+)')
    generic_ip_re = re.compile(r'\b(\d+\.\d+\.\d+\.\d+)\b')

    end = time.time() + timeout_s
    with serial.Serial(port, baudrate=baud, timeout=0.25) as ser:
        # Nudge board; many ESP32 boards print boot/Wi-Fi lines after DTR reset.
        ser.dtr = False
        ser.rts = False
        time.sleep(0.05)
        ser.reset_input_buffer()
        while time.time() < end:
            line = ser.readline().decode('utf-8', errors='replace').strip()
            if not line:
                continue
            print({'serial': line})

            m = ip_re.search(line)
            if m:
                return m.group(1)

            # Fallback for older firmware if it prints just an IP line.
            m2 = generic_ip_re.search(line)
            if m2 and not line.startswith('E ('):
                return m2.group(1)

    return None


def serial_apply_signed_config(port: str, signed_payload: dict, baud: int = 115200, timeout_s: int = 75) -> tuple[bool, str | None]:
    try:
        import serial  # type: ignore
    except Exception:
        print({'ok': False, 'error': 'PYSERIAL_MISSING', 'detail': 'install pyserial in venv'})
        return False, None

    blob = json.dumps(signed_payload, separators=(",", ":")).encode('utf-8')
    ip_re = re.compile(r'AZT_IP=(\d+\.\d+\.\d+\.\d+)')
    wifi_ip_re = re.compile(r'AZT_WIFI_CONNECTED.*\bip=(\d+\.\d+\.\d+\.\d+)')

    with serial.Serial(port, baudrate=baud, timeout=0.25) as ser:
        # Reset + settle.
        ser.dtr = False
        ser.rts = True
        time.sleep(0.12)
        ser.rts = False
        time.sleep(0.6)
        ser.reset_input_buffer()

        ser.write(f'AZT_CONFIG_BEGIN_LEN {len(blob)}\n'.encode('utf-8'))

        begin_ok = False
        t_begin = time.time() + 5
        while time.time() < t_begin:
            line = ser.readline().decode('utf-8', errors='replace').strip()
            if not line:
                continue
            print({'serial': line})
            if line.startswith('AZT_CONFIG_BEGIN_LEN OK'):
                begin_ok = True
                break
            if line.startswith('AZT_CONFIG_BEGIN_LEN ERR'):
                return False, None

        if not begin_ok:
            return False, None

        step = 128
        for i in range(0, len(blob), step):
            ser.write(blob[i:i + step])
            time.sleep(0.002)

        apply_ok = False
        device_ip: str | None = None
        deadline = time.time() + timeout_s
        while time.time() < deadline:
            line = ser.readline().decode('utf-8', errors='replace').strip()
            if not line:
                continue
            print({'serial': line})
            if 'AZT_CONFIG_APPLY code=200' in line:
                apply_ok = True
            m = ip_re.search(line)
            if m:
                device_ip = m.group(1)
            m2 = wifi_ip_re.search(line)
            if m2:
                device_ip = m2.group(1)
            if apply_ok and device_ip:
                break

        return apply_ok, device_ip


def main() -> int:
    ap = argparse.ArgumentParser(description='Flash + keygen + provision one Audio-Zero-Trust unit')
    ap.add_argument('--port', default='/dev/ttyUSB0')
    ap.add_argument('--ip', default=None)
    ap.add_argument('--baud', type=int, default=115200)
    ap.add_argument('--ip-timeout', type=int, default=20)
    ap.add_argument('--no-auto-ip', action='store_true', help='Disable serial IP autodetect and use --ip directly')
    ap.add_argument('--identity', default=None)
    ap.add_argument('--wifi-ssid', default=None)
    ap.add_argument('--wifi-password', default=None)
    ap.add_argument('--skip-flash', action='store_true')
    ap.add_argument('--artifact-dir', default=None, help='Existing client/tools/provisioned/<identity-ts> directory to reuse keys')
    ap.add_argument('--allow-serial-bootstrap', action='store_true', help='Allow privileged serial bootstrap when HTTP is unreachable (explicit opt-in)')
    args = ap.parse_args()

    identity = args.identity or input('Device identity label (e.g. Livingroom): ').strip()
    if not identity:
        print('identity required', file=sys.stderr)
        return 2

    wifi_ssid = args.wifi_ssid or input('Wi-Fi SSID: ').strip()
    wifi_password = args.wifi_password or input('Wi-Fi password: ').strip()
    if not wifi_ssid or not wifi_password:
        print('wifi ssid/password required', file=sys.stderr)
        return 2

    stamp = time.strftime('%Y%m%d-%H%M%S')
    safe_name = ''.join(c if c.isalnum() or c in ('-', '_') else '_' for c in identity)
    out_dir = CLIENT_ROOT / 'tools' / 'provisioned' / f'{safe_name}-{stamp}'

    if not args.skip_flash:
        pio = _resolve_platformio()
        run([pio, 'run', '-e', 'm5stack-atom-m4-2-native', '-t', 'upload', '--upload-port', args.port], cwd=FW_DIR)

    device_ip = args.ip
    if not args.no_auto_ip:
        detected_ip = detect_device_ip_from_serial(args.port, baud=args.baud, timeout_s=args.ip_timeout)
        if detected_ip:
            device_ip = detected_ip
            print({'ip_detected': device_ip})
        else:
            print({'warn': 'failed to detect device IP from serial; falling back to --ip', 'ip_fallback': device_ip})

    # Prepare key material/config now so we can use HTTP path (and optional serial bootstrap path).
    if args.artifact_dir:
        pub_pem, fp = load_keypair_from_artifact_dir(Path(args.artifact_dir))
        out_dir = Path(args.artifact_dir)
    else:
        pub_pem, fp = gen_keypair(out_dir)

    unsigned_cfg = make_bootstrap(identity, pub_pem, fp, wifi_ssid, wifi_password)
    priv_path = out_dir / 'private_key.pem'
    if not priv_path.exists():
        priv_path = out_dir / 'admin_private_key.pem'
    priv_pem = priv_path.read_bytes()
    signed = make_signed_config(unsigned_cfg, priv_pem, fp)

    (out_dir / 'config_bootstrap.json').write_text(json.dumps(unsigned_cfg, indent=2))
    (out_dir / 'config_signed.json').write_text(json.dumps(signed, indent=2))

    base = f'http://{device_ip}:8080'
    state0 = None
    try:
        state0 = http_json('GET', base + '/api/v1/config/state')
        print({'state_before': state0})
    except Exception as e:
        print({'warn': 'http_state_unreachable', 'ip': device_ip, 'detail': str(e)})

    if state0 is None:
        if not args.allow_serial_bootstrap:
            print({
                'ok': False,
                'error': 'HTTP_UNREACHABLE',
                'detail': 'device HTTP is unreachable; serial bootstrap is disabled by default',
                'next_step': 'rerun with --allow-serial-bootstrap to perform privileged serial config bootstrap',
            })
            return 9

        print({'info': 'attempting serial bootstrap via AZT_CONFIG_BEGIN_LEN'})
        ok_serial, ip_from_serial = serial_apply_signed_config(args.port, signed, baud=args.baud)
        if not ok_serial:
            print({'ok': False, 'error': 'SERIAL_BOOTSTRAP_FAILED', 'detail': 'serial config apply did not complete'})
            return 7
        if ip_from_serial:
            device_ip = ip_from_serial
            print({'ip_detected_after_serial_bootstrap': device_ip})
        base = f'http://{device_ip}:8080'
        time.sleep(1.5)
        try:
            state1 = http_json('GET', base + '/api/v1/config/state')
            print({'state_after': state1})
        except Exception as e:
            print({'ok': False, 'error': 'HTTP_UNREACHABLE_AFTER_SERIAL_BOOTSTRAP', 'ip': device_ip, 'detail': str(e)})
            return 8

        if state1.get('admin_fingerprint_hex') != fp:
            print({'ok': False, 'error': 'POSTCHECK_FP_MISMATCH', 'expected_fp': fp, 'device_fp': state1.get('admin_fingerprint_hex')})
            return 6

        print({'ok': True, 'identity': identity, 'fingerprint': fp, 'ip': device_ip, 'artifacts': str(out_dir), 'path': 'serial-bootstrap'})
        return 0

    state_name = state0.get('state')
    state_fp = str(state0.get('admin_fingerprint_hex') or '')

    if state_name != 'UNSET_ADMIN':
      matches = find_artifacts_for_fingerprint(state_fp) if len(state_fp) == 64 else []
      artifact_info = [str(p) for p in matches]
      if args.artifact_dir:
          art = Path(args.artifact_dir)
          _, fp_art = load_keypair_from_artifact_dir(art)
          if fp_art != state_fp:
              print({'ok': False, 'error': 'FINGERPRINT_MISMATCH', 'device_fp': state_fp, 'artifact_fp': fp_art, 'artifact_dir': str(art)})
              return 4
          print({'ok': True, 'state': state_name, 'detail': 'managed device matches provided artifact', 'artifact_dir': str(art), 'ip': device_ip})
          return 0

      if matches:
          print({'ok': True, 'state': state_name, 'detail': 'managed device; matching artifacts found', 'fingerprint': state_fp, 'artifact_matches': artifact_info, 'ip': device_ip})
          return 0

      print({'ok': False, 'error': 'MISSING_ADMIN_KEY_ARTIFACT', 'detail': f'device is {state_name} with unknown admin fingerprint; cannot safely update signed config', 'fingerprint': state_fp, 'ip': device_ip})
      return 5

    r1 = http_json('POST', base + '/api/v1/config', signed)
    print({'initial_signed_result': r1})

    r2 = http_json('POST', base + '/api/v1/config', signed)
    print({'signed_result': r2})

    state1 = http_json('GET', base + '/api/v1/config/state')
    print({'state_after': state1})

    if state1.get('admin_fingerprint_hex') != fp:
        print({'ok': False, 'error': 'POSTCHECK_FP_MISMATCH', 'expected_fp': fp, 'device_fp': state1.get('admin_fingerprint_hex')})
        return 6

    print({'ok': True, 'identity': identity, 'fingerprint': fp, 'ip': device_ip, 'artifacts': str(out_dir), 'path': 'http'})
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
