"""
Typed representation of ZTDF manifest files.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PolicyBinding:
    alg: str
    hash: str


@dataclass
class KeyAccessEntry:
    type: str
    kid: str
    wrapped_key: str
    policy_binding: Optional[PolicyBinding]
    url: str
    protocol: str


@dataclass
class Method:
    algorithm: str
    is_streamable: bool
    iv: str


@dataclass
class IntegritySegment:
    hash: Optional[str]
    segment_size: int
    encrypted_segment_size: int

    def hash_bytes(self) -> Optional[bytes]:
        if not self.hash:
            return None
        return base64.b64decode(self.hash)


@dataclass
class RootSignature:
    alg: str
    sig: str

    def digest(self) -> bytes:
        return base64.b64decode(self.sig)


@dataclass
class IntegrityInformation:
    segments: List[IntegritySegment] = field(default_factory=list)
    root_signature: Optional[RootSignature] = None


@dataclass
class EncryptionInformation:
    type: str
    key_access: List[KeyAccessEntry]
    method: Method
    integrity_information: Optional[IntegrityInformation]
    policy: Optional[str]


@dataclass
class Manifest:
    filename: str
    content_type: str
    payload_hash: Optional[str]
    encryption_information: EncryptionInformation

    @staticmethod
    def from_json(data: bytes) -> "Manifest":
        parsed = json.loads(data.decode("utf-8"))
        return Manifest.from_dict(parsed)

    @staticmethod
    def from_dict(data: Dict[str, Any]) -> "Manifest":
        enc = data["encryptionInformation"]
        method = Method(
            algorithm=enc["method"]["algorithm"],
            is_streamable=bool(enc["method"].get("isStreamable")),
            iv=enc["method"]["iv"],
        )
        key_access = []
        for entry in enc.get("keyAccess", []):
            policy_binding = None
            if entry.get("policyBinding"):
                policy_binding = PolicyBinding(
                    alg=entry["policyBinding"].get("alg", ""),
                    hash=entry["policyBinding"].get("hash", ""),
                )
            key_access.append(
                KeyAccessEntry(
                    type=entry.get("type", ""),
                    kid=entry.get("kid", ""),
                    wrapped_key=entry.get("wrappedKey", ""),
                    policy_binding=policy_binding,
                    url=entry.get("url", ""),
                    protocol=entry.get("protocol", ""),
                )
            )
        integrity = None
        integrity_dict = enc.get("integrityInformation")
        if integrity_dict:
            root_sig = None
            if integrity_dict.get("rootSignature"):
                root_sig = RootSignature(
                    alg=integrity_dict["rootSignature"].get("alg", ""),
                    sig=integrity_dict["rootSignature"].get("sig", ""),
                )
            segments = [
                IntegritySegment(
                    hash=item.get("hash"),
                    segment_size=int(item.get("segmentSize", 0)),
                    encrypted_segment_size=int(item.get("encryptedSegmentSize", 0)),
                )
                for item in integrity_dict.get("segments", [])
            ]
            integrity = IntegrityInformation(segments=segments, root_signature=root_sig)

        encryption_information = EncryptionInformation(
            type=enc.get("type", ""),
            key_access=key_access,
            method=method,
            integrity_information=integrity,
            policy=enc.get("policy"),
        )

        return Manifest(
            filename=data.get("filename", ""),
            content_type=data.get("contentType", "application/octet-stream"),
            payload_hash=data.get("payloadHash"),
            encryption_information=encryption_information,
        )


@dataclass
class ZtdfFile:
    manifest: Manifest
    payload: bytes
