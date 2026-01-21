"""
Storage abstractions used by the Stratium client for persisting client keys.
"""

from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Protocol

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


@dataclass
class KeyMetadata:
    key_id: str
    created_at: datetime
    expires_at: datetime

    @property
    def expired(self) -> bool:
        return datetime.now(timezone.utc) >= self.expires_at


@dataclass
class StoredKeyPair:
    metadata: KeyMetadata
    public_key: rsa.RSAPublicKey
    private_key: rsa.RSAPrivateKey


class KeyStore(Protocol):
    def save_key_pair(self, key_pair: StoredKeyPair) -> None:
        ...

    def get_latest_key(self) -> Optional[StoredKeyPair]:
        ...

    def delete(self, key_id: str) -> None:
        ...


class FileKeyStore(KeyStore):
    """
    File-system backed key store mirroring the behavior of the Go and Java SDKs.
    Keys are stored under ``<root>/<key_id>/`` with PEM-encoded files.
    """

    def __init__(self, root: Path) -> None:
        self._root = Path(root)
        self._root.mkdir(parents=True, exist_ok=True)

    def save_key_pair(self, key_pair: StoredKeyPair) -> None:
        directory = self._root / key_pair.metadata.key_id
        directory.mkdir(parents=True, exist_ok=True)
        metadata_path = directory / "metadata.json"
        metadata_path.write_text(
            json.dumps(
                {
                    "key_id": key_pair.metadata.key_id,
                    "created_at": key_pair.metadata.created_at.isoformat(),
                    "expires_at": key_pair.metadata.expires_at.isoformat(),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        (directory / "public.pem").write_bytes(
            key_pair.public_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        (directory / "private.pem").write_bytes(
            key_pair.private_key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )

    def get_latest_key(self) -> Optional[StoredKeyPair]:
        if not self._root.exists():
            return None
        candidates = []
        for child in self._root.iterdir():
            if not child.is_dir():
                continue
            loaded = self._load_key_pair(child)
            if loaded:
                candidates.append(loaded)
        candidates = [c for c in candidates if not c.metadata.expired]
        return max(candidates, key=lambda pair: pair.metadata.created_at, default=None)

    def delete(self, key_id: str) -> None:
        directory = self._root / key_id
        if directory.exists():
            shutil.rmtree(directory)

    def _load_key_pair(self, directory: Path) -> Optional[StoredKeyPair]:
        try:
            metadata_path = directory / "metadata.json"
            private_path = directory / "private.pem"
            public_path = directory / "public.pem"
            if not (metadata_path.exists() and private_path.exists() and public_path.exists()):
                return None
            data = json.loads(metadata_path.read_text(encoding="utf-8"))
            metadata = KeyMetadata(
                key_id=data["key_id"],
                created_at=datetime.fromisoformat(data["created_at"]).astimezone(timezone.utc),
                expires_at=datetime.fromisoformat(data["expires_at"]).astimezone(timezone.utc),
            )
            private_key = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
            public_key = serialization.load_pem_public_key(public_path.read_bytes())
            if not isinstance(private_key, rsa.RSAPrivateKey) or not isinstance(public_key, rsa.RSAPublicKey):
                return None
            return StoredKeyPair(metadata=metadata, public_key=public_key, private_key=private_key)
        except Exception:
            return None
