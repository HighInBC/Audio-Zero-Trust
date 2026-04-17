from __future__ import annotations

import json
import tarfile
from pathlib import Path

from azt_recorder.recorder import (
    _write_manifested_timestamp_tar,
    embed_ots_sidecar_into_timestamp_tar,
    ots_sidecar_path,
    ots_status_for_recording,
    ots_tsr_sidecar_path,
    prune_ots_upgrade_backups_for_recording,
    timestamp_tar_path,
)


def test_ots_sidecar_embedding_and_manifest(tmp_path: Path) -> None:
    recording = tmp_path / "sample.azt"
    recording.write_bytes(b"sample-audio-bytes")

    tar_path = timestamp_tar_path(recording)
    _write_manifested_timestamp_tar(
        tar_path=tar_path,
        recording_path=recording,
        members=[("sample.azt.tsq", b"tsq"), ("sample.azt.tsr", b"tsr")],
    )

    assert ots_status_for_recording(recording) == "missing"

    azt_sidecar = ots_sidecar_path(recording)
    tsr_sidecar = ots_tsr_sidecar_path(recording)
    azt_sidecar.write_bytes(b"pending-ots-proof-azt")
    tsr_sidecar.write_bytes(b"pending-ots-proof-tsr")
    assert ots_status_for_recording(recording) == "sidecar"

    embed_ots_sidecar_into_timestamp_tar(recording, remove_sidecar=True)

    assert not azt_sidecar.exists()
    assert not tsr_sidecar.exists()
    assert ots_status_for_recording(recording) == "embedded"

    with tarfile.open(tar_path, "r") as tf:
        names = {m.name for m in tf.getmembers() if m.isfile()}
        assert "manifest.json" in names
        assert azt_sidecar.name in names
        assert tsr_sidecar.name in names

        manifest_raw = tf.extractfile("manifest.json").read()
        manifest = json.loads(manifest_raw.decode("utf-8"))
        manifest_paths = {entry["path"] for entry in manifest["entries"]}
        assert azt_sidecar.name in manifest_paths
        assert tsr_sidecar.name in manifest_paths


def test_prune_ots_upgrade_backups_only_when_embedded(tmp_path: Path) -> None:
    recording = tmp_path / "sample.azt"
    recording.write_bytes(b"sample-audio-bytes")

    # Create .bak files as produced by `ots upgrade`.
    azt_bak = Path(str(ots_sidecar_path(recording)) + ".bak")
    tsr_bak = Path(str(ots_tsr_sidecar_path(recording)) + ".bak")
    azt_bak.write_bytes(b"old-proof")
    tsr_bak.write_bytes(b"old-proof")

    # Without embedded sidecars in tar, cleanup must not delete anything.
    removed = prune_ots_upgrade_backups_for_recording(recording)
    assert removed == 0
    assert azt_bak.exists()
    assert tsr_bak.exists()

    tar_path = timestamp_tar_path(recording)
    _write_manifested_timestamp_tar(
        tar_path=tar_path,
        recording_path=recording,
        members=[
            (ots_sidecar_path(recording).name, b"embedded-azt-proof"),
            (ots_tsr_sidecar_path(recording).name, b"embedded-tsr-proof"),
            ("sample.azt.tsq", b"tsq"),
            ("sample.azt.tsr", b"tsr"),
        ],
    )

    assert ots_status_for_recording(recording) == "embedded"
    removed = prune_ots_upgrade_backups_for_recording(recording)
    assert removed == 2
    assert not azt_bak.exists()
    assert not tsr_bak.exists()
