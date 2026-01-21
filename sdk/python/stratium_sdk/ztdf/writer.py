"""
Manifest building helpers shared by the high-level client.
"""

from __future__ import annotations

import base64
import io
import json
import zipfile
from typing import Dict, Optional

from ..grpc_clients.key_access import WrapDEKResponse


def build_manifest_dict(
    *,
    filename: str,
    content_type: str,
    iv: bytes,
    key_access_result: WrapDEKResponse,
    payload_hash: Optional[bytes],
    policy_binding: Optional[bytes],
    policy_base64: Optional[str],
    key_access_url: str,
) -> Dict[str, object]:
    encryption_info: Dict[str, object] = {
        "type": "split",
        "keyAccess": [
            _build_key_access_entry(
                iv=iv,
                result=key_access_result,
                policy_binding=policy_binding,
                policy_base64=policy_base64,
                key_access_url=key_access_url,
            )
        ],
        "method": {
            "algorithm": "AES-256-GCM",
            "isStreamable": False,
            "iv": base64.b64encode(iv).decode("ascii"),
        },
    }
    if policy_base64:
        encryption_info["policy"] = policy_base64

    manifest: Dict[str, object] = {
        "filename": filename,
        "contentType": content_type,
        "encryptionInformation": encryption_info,
    }
    if payload_hash:
        manifest["payloadHash"] = base64.b64encode(payload_hash).decode("ascii")
    return manifest


def package_ztdf(manifest: Dict[str, object], payload: bytes) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w") as archive:
        archive.writestr("manifest.json", json.dumps(manifest, separators=(",", ":")).encode("utf-8"))
        archive.writestr("0.payload", payload)
    return buffer.getvalue()


def _build_key_access_entry(
    *,
    iv: bytes,
    result: WrapDEKResponse,
    policy_binding: Optional[bytes],
    policy_base64: Optional[str],
    key_access_url: str,
) -> Dict[str, object]:
    entry: Dict[str, object] = {
        "type": "wrapped",
        "kid": result.key_id,
        "wrappedKey": base64.b64encode(result.wrapped_dek).decode("ascii"),
        "url": key_access_url,
        "protocol": "kas",
    }
    if policy_binding and policy_base64:
        entry["policyBinding"] = {
            "alg": "HS256",
            "hash": base64.b64encode(policy_binding).decode("ascii"),
        }
    return entry
