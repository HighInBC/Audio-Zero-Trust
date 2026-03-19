#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tarfile
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.request import urlopen


@dataclass
class CmdResult:
    code: int
    out: str
    err: str


def run(cmd: list[str]) -> CmdResult:
    p = subprocess.run(cmd, text=True, capture_output=True)
    return CmdResult(code=p.returncode, out=p.stdout, err=p.stderr)


def must(cmd: list[str], *, step: str) -> str:
    r = run(cmd)
    if r.code != 0:
        raise RuntimeError(f"{step} failed: {' '.join(cmd)}\nSTDOUT:\n{r.out}\nSTDERR:\n{r.err}")
    return r.out


def split_pem_chain(pem_text: str, out_dir: Path) -> list[Path]:
    certs = re.findall(r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----", pem_text)
    out: list[Path] = []
    for i, c in enumerate(certs):
        p = out_dir / f"cert_{i:02d}.pem"
        p.write_text(c + "\n", encoding="utf-8")
        out.append(p)
    return out


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        while True:
            b = f.read(1024 * 1024)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def download(url: str, out_path: Path) -> dict:
    try:
        with urlopen(url, timeout=30) as r:
            data = r.read()
            out_path.write_bytes(data)
        return {"ok": True, "url": url, "path": str(out_path), "size": len(data)}
    except Exception as e:
        return {"ok": False, "url": url, "error": str(e)}


def _extract_urls_from_x509_text(text: str, header: str) -> list[str]:
    lines = text.splitlines()
    urls: list[str] = []
    in_block = False
    base_indent = None
    for line in lines:
        if not in_block:
            if header in line:
                in_block = True
                base_indent = len(line) - len(line.lstrip(" "))
            continue
        # stop when indentation returns to same/higher-level extension line
        indent = len(line) - len(line.lstrip(" "))
        if line.strip() and base_indent is not None and indent <= base_indent and header not in line:
            break
        for m in re.findall(r"URI:(http[^\s,]+)", line):
            urls.append(m)
    # dedupe preserve order
    return list(dict.fromkeys(urls))


def _extract_aia_urls(text: str) -> tuple[list[str], list[str]]:
    lines = text.splitlines()
    in_block = False
    base_indent = None
    ocsp_urls: list[str] = []
    ca_issuers_urls: list[str] = []

    for line in lines:
        if not in_block:
            if "Authority Information Access" in line:
                in_block = True
                base_indent = len(line) - len(line.lstrip(" "))
            continue

        indent = len(line) - len(line.lstrip(" "))
        if line.strip() and base_indent is not None and indent <= base_indent and "Authority Information Access" not in line:
            break

        if "OCSP - URI:" in line:
            ocsp_urls.extend(re.findall(r"URI:(http[^\s,]+)", line))
        if "CA Issuers - URI:" in line:
            ca_issuers_urls.extend(re.findall(r"URI:(http[^\s,]+)", line))

    return list(dict.fromkeys(ocsp_urls)), list(dict.fromkeys(ca_issuers_urls))


def main() -> int:
    ap = argparse.ArgumentParser(description="Capture TSA LTV-oriented evidence from an .azt and .timestamp.tar")
    ap.add_argument("--recording", required=True, help="Path to .azt recording file")
    ap.add_argument("--timestamp-tar", required=True, help="Path to .timestamp.tar")
    ap.add_argument("--out", default="", help="Output .ltv.tar path (default: <recording>.ltv.tar)")
    args = ap.parse_args()

    recording = Path(args.recording)
    ts_tar = Path(args.timestamp_tar)
    if not recording.exists():
        raise SystemExit(f"recording missing: {recording}")
    if not ts_tar.exists():
        raise SystemExit(f"timestamp tar missing: {ts_tar}")

    out_tar = Path(args.out) if args.out else Path(str(recording) + ".ltv.tar")

    with tempfile.TemporaryDirectory(prefix="tsa-ltv-") as td:
        work = Path(td)
        extracted = work / "extracted"
        extracted.mkdir(parents=True, exist_ok=True)
        with tarfile.open(ts_tar, "r") as tf:
            tf.extractall(extracted)

        tsq_list = sorted(extracted.glob("*.tsq"))
        tsr_list = sorted(extracted.glob("*.tsr"))
        if not tsq_list or not tsr_list:
            raise SystemExit("timestamp tar does not contain both .tsq and .tsr")
        tsq = tsq_list[0]
        tsr = tsr_list[0]

        verify = run([
            "openssl", "ts", "-verify",
            "-in", str(tsr),
            "-data", str(recording),
            "-CAfile", "/etc/ssl/certs/ca-certificates.crt",
        ])

        token_der = work / "token.der"
        must([
            "openssl", "ts", "-reply", "-in", str(tsr), "-token_out", "-out", str(token_der)
        ], step="token_out")

        certs_pem = work / "certs.pem"
        must([
            "openssl", "pkcs7", "-inform", "DER", "-in", str(token_der), "-print_certs", "-out", str(certs_pem)
        ], step="extract_certs")

        certs_dir = work / "certs"
        certs_dir.mkdir(exist_ok=True)
        cert_paths = split_pem_chain(certs_pem.read_text(encoding="utf-8"), certs_dir)

        cert_infos = []
        for p in cert_paths:
            subj = run(["openssl", "x509", "-in", str(p), "-noout", "-subject"]).out.strip()
            issuer = run(["openssl", "x509", "-in", str(p), "-noout", "-issuer"]).out.strip()
            fp = run(["openssl", "x509", "-in", str(p), "-noout", "-fingerprint", "-sha256"]).out.strip()
            txt = run(["openssl", "x509", "-in", str(p), "-noout", "-text"]).out
            txt_path = p.with_suffix(".txt")
            txt_path.write_text(txt, encoding="utf-8")
            cert_infos.append({
                "path": str(p.name),
                "subject": subj,
                "issuer": issuer,
                "sha256_fingerprint": fp,
                "text_path": str(txt_path.name),
            })

        signer = cert_paths[0] if cert_paths else None
        issuer = cert_paths[1] if len(cert_paths) > 1 else None

        ocsp_url = ""
        signer_aia_ocsp_urls: list[str] = []
        signer_aia_ca_issuers_urls: list[str] = []
        crl_urls: list[str] = []
        if signer is not None:
            signer_text = run(["openssl", "x509", "-in", str(signer), "-noout", "-text"]).out
            signer_aia_ocsp_urls, signer_aia_ca_issuers_urls = _extract_aia_urls(signer_text)
            # keep a primary OCSP URL for direct ocsp command usage
            ocsp_url = signer_aia_ocsp_urls[0] if signer_aia_ocsp_urls else run(["openssl", "x509", "-in", str(signer), "-noout", "-ocsp_uri"]).out.strip()
            crl_urls = _extract_urls_from_x509_text(signer_text, "X509v3 CRL Distribution Points")

        rev_dir = work / "revocation"
        rev_dir.mkdir(exist_ok=True)

        aia_ca_issuers_downloads = []
        for i, u in enumerate(signer_aia_ca_issuers_urls):
            out = rev_dir / f"aia_ca_issuer_{i:02d}.der"
            aia_ca_issuers_downloads.append(download(u, out))

        crl_results = []
        for i, u in enumerate(crl_urls):
            out = rev_dir / f"crl_{i:02d}.crl"
            crl_results.append(download(u, out))

        ocsp_capture = {"attempted": False}
        if signer is not None and issuer is not None and ocsp_url:
            ocsp_capture = {"attempted": True, "url": ocsp_url}
            ocsp_der = rev_dir / "ocsp.der"
            ocsp_cmd = [
                "openssl", "ocsp",
                "-issuer", str(issuer),
                "-cert", str(signer),
                "-url", ocsp_url,
                "-respout", str(ocsp_der),
                "-noverify",
            ]
            r = run(ocsp_cmd)
            ocsp_capture.update({"code": r.code, "stdout": r.out, "stderr": r.err, "path": str(ocsp_der.name) if ocsp_der.exists() else None})

        manifest = {
            "recording": str(recording),
            "recording_sha256": sha256_file(recording),
            "timestamp_tar": str(ts_tar),
            "tsq": tsq.name,
            "tsr": tsr.name,
            "verify_cmd": "openssl ts -verify -in <tsr> -data <recording> -CAfile /etc/ssl/certs/ca-certificates.crt",
            "verify_ok": (verify.code == 0),
            "verify_stdout": verify.out,
            "verify_stderr": verify.err,
            "token_der": token_der.name,
            "cert_chain": cert_infos,
            "signer_ocsp_url": ocsp_url,
            "signer_aia_ocsp_urls": signer_aia_ocsp_urls,
            "signer_aia_ca_issuers_urls": signer_aia_ca_issuers_urls,
            "signer_crl_urls": crl_urls,
            "aia_ca_issuers_downloads": aia_ca_issuers_downloads,
            "crl_downloads": crl_results,
            "ocsp_capture": ocsp_capture,
        }

        manifest_path = work / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

        with tarfile.open(out_tar, "w") as tf:
            tf.add(tsq, arcname=tsq.name)
            tf.add(tsr, arcname=tsr.name)
            tf.add(token_der, arcname=token_der.name)
            tf.add(certs_pem, arcname=certs_pem.name)
            tf.add(manifest_path, arcname=manifest_path.name)
            for p in sorted(certs_dir.glob("*")):
                tf.add(p, arcname=f"certs/{p.name}")
            for p in sorted(rev_dir.glob("*")):
                tf.add(p, arcname=f"revocation/{p.name}")

        print(json.dumps({"ok": True, "out": str(out_tar), "manifest": manifest}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
