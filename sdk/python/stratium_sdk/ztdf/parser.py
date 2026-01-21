"""
Utilities for parsing ZTDF payloads.
"""

from __future__ import annotations

import io
import zipfile

from .manifest import Manifest, ZtdfFile


def load_ztdf(blob: bytes) -> ZtdfFile:
    manifest_bytes: bytes | None = None
    payload_bytes: bytes | None = None

    with zipfile.ZipFile(io.BytesIO(blob), "r") as archive:
        for entry in archive.infolist():
            if entry.filename == "manifest.json":
                manifest_bytes = archive.read(entry)
            elif entry.filename.endswith(".payload"):
                payload_bytes = archive.read(entry)

    if manifest_bytes is None or payload_bytes is None:
        raise ValueError("ZTDF archive missing manifest or payload entries")

    manifest = Manifest.from_json(manifest_bytes)
    return ZtdfFile(manifest=manifest, payload=payload_bytes)
