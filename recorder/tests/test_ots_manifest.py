from __future__ import annotations

import json
import tarfile
from pathlib import Path

from azt_recorder.recorder import (
    _write_manifested_timestamp_tar,
    embed_ots_sidecar_into_timestamp_tar,
    ots_sidecar_path,
    ots_status_for_recording,
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

    sidecar = ots_sidecar_path(recording)
    sidecar.write_bytes(b"pending-ots-proof")
    assert ots_status_for_recording(recording) == "sidecar"

    embed_ots_sidecar_into_timestamp_tar(recording, remove_sidecar=True)

    assert not sidecar.exists()
    assert ots_status_for_recording(recording) == "embedded"

    with tarfile.open(tar_path, "r") as tf:
        names = {m.name for m in tf.getmembers() if m.isfile()}
        assert "manifest.json" in names
        assert sidecar.name in names

        manifest_raw = tf.extractfile("manifest.json").read()
        manifest = json.loads(manifest_raw.decode("utf-8"))
        manifest_paths = {entry["path"] for entry in manifest["entries"]}
        assert sidecar.name in manifest_paths
