"""
High-level Stratium client that mirrors the Go/JS/Java SDK ergonomics.
"""

from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

import grpc
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from .auth import TokenProvider, build_token_provider
from .config import StratiumConfig
from .crypto import (
    IntegritySegment as CryptoIntegritySegment,
    PayloadEncryptionResult,
    calculate_payload_hash,
    calculate_policy_binding,
    decrypt_dek,
    decrypt_payload,
    decrypt_segmented_payload,
    encrypt_payload,
    generate_dek,
    generate_iv,
    verify_payload_hash,
    verify_policy_binding,
    wrap_dek_with_private_key,
)
from .errors import APIError, EncryptionError, ValidationError
from .grpc_clients import KeyAccessClient, KeyManagerClient, PlatformClient
from .grpc_clients.base import create_channel
from .grpc_clients.key_access import WrapDEKRequest
from .keystore import FileKeyStore, KeyMetadata, KeyStore, StoredKeyPair
from .types import WrapOptions, WrapResult
from .ztdf import build_manifest_dict, load_ztdf, package_ztdf


class StratiumClient:
    """
    Facade that coordinates gRPC clients, key storage, and ZTDF packaging helpers.
    """

    def __init__(
        self,
        config: StratiumConfig,
        key_store: Optional[KeyStore] = None,
        token_provider: Optional[TokenProvider] = None,
    ) -> None:
        self._config = config
        self._config.validate()
        self._key_store = key_store or FileKeyStore(Path(".stratium-keys"))
        self._token_provider = token_provider or build_token_provider(config)
        if not self._token_provider:
            raise ValidationError(
                "authentication is required for Key Access/Manager calls; set bearer_token or oidc in StratiumConfig"
            )

        self.key_access: Optional[KeyAccessClient] = None
        self.key_manager: Optional[KeyManagerClient] = None
        self.platform: Optional[PlatformClient] = None

        self._channels: List[grpc.Channel] = []
        self._initialized = False
        self._current_key_pair: Optional[StoredKeyPair] = None

    def initialize(self) -> None:
        if self._initialized:
            return

        if self._config.key_access_address:
            channel = create_channel(self._config.key_access_address, self._config.use_tls)
            self._channels.append(channel)
            self.key_access = KeyAccessClient(channel, self._token_provider)
        if self._config.key_manager_address:
            channel = create_channel(self._config.key_manager_address, self._config.use_tls)
            self._channels.append(channel)
            self.key_manager = KeyManagerClient(channel, self._token_provider)
        if self._config.platform_address:
            channel = create_channel(self._config.platform_address, self._config.use_tls)
            self._channels.append(channel)
            self.platform = PlatformClient(channel, self._token_provider)

        if not self.key_access:
            raise ValidationError("Key Access service must be configured to use the Stratium client")
        if not self.key_manager:
            raise ValidationError("Key Manager service must be configured to manage client keys")

        self._current_key_pair = self._key_store.get_latest_key()
        if not self._current_key_pair or self._current_key_pair.metadata.expired:
            self._current_key_pair = self._register_new_key_pair()

        self._initialized = True

    def close(self) -> None:
        for channel in self._channels:
            channel.close()
        self._channels.clear()
        self._initialized = False

    def __enter__(self) -> "StratiumClient":
        self.initialize()
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def wrap(self, plaintext: bytes, options: Optional[WrapOptions] = None) -> WrapResult:
        self._ensure_ready()
        opts = options or WrapOptions()
        for attempt in range(2):
            try:
                return self._wrap_once(plaintext, opts)
            except APIError as exc:
                if attempt == 0 and "no active client keys" in str(exc).lower():
                    self._current_key_pair = self._register_new_key_pair()
                    continue
                raise
        raise APIError("failed to wrap payload after retrying key registration")

    def unwrap(self, ztdf_blob: bytes) -> bytes:
        self._ensure_ready()
        pair = self._ensure_active_key_pair()
        ztdf_file = load_ztdf(ztdf_blob)
        manifest = ztdf_file.manifest
        entry = manifest.encryption_information.key_access[0]
        wrapped_key = base64.b64decode(entry.wrapped_key)

        result = self.key_access.unwrap_dek(
            resource=manifest.filename or "encrypted-file",
            wrapped_dek=wrapped_key,
            key_id=entry.kid,
            client_key_id=pair.metadata.key_id,
            action="decrypt",
            context={},
            policy=manifest.encryption_information.policy or "",
        )
        if not result.access_granted:
            raise APIError(result.access_reason or "access denied")

        dek = decrypt_dek(result.dek_for_subject, pair.private_key)
        encryption_method = manifest.encryption_information.method
        iv = base64.b64decode(encryption_method.iv)

        integrity_info = manifest.encryption_information.integrity_information
        if (
            encryption_method.is_streamable
            and integrity_info
            and integrity_info.segments
        ):
            segments = [
                CryptoIntegritySegment(
                    hash_base64=segment.hash or "",
                    segment_size=segment.segment_size,
                    encrypted_segment_size=segment.encrypted_segment_size,
                )
                for segment in integrity_info.segments
            ]
            root_hash = (
                integrity_info.root_signature.digest() if integrity_info.root_signature else None
            )
            plaintext = decrypt_segmented_payload(
                ztdf_file.payload,
                dek,
                iv,
                segments,
                root_hash,
            )
        else:
            plaintext = decrypt_payload(ztdf_file.payload, dek, iv)
            if manifest.payload_hash:
                expected_hash = base64.b64decode(manifest.payload_hash)
                if not verify_payload_hash(plaintext, expected_hash):
                    raise EncryptionError("payload integrity verification failed")

        if entry.policy_binding and manifest.encryption_information.policy:
            if not verify_policy_binding(
                dek,
                manifest.encryption_information.policy,
                entry.policy_binding.hash,
            ):
                raise EncryptionError("policy binding verification failed")

        return plaintext

    def _wrap_once(self, plaintext: bytes, options: WrapOptions) -> WrapResult:
        pair = self._ensure_active_key_pair()

        dek = generate_dek()
        iv = generate_iv()
        encryption = encrypt_payload(plaintext, dek, iv)
        client_wrapped_dek = wrap_dek_with_private_key(dek, pair.private_key)

        wrap_request = WrapDEKRequest(
            resource=options.resource,
            client_wrapped_dek=client_wrapped_dek,
            action=options.action or "wrap",
            context=options.context,
            policy=options.policy_base64,
            client_key_id=pair.metadata.key_id,
        )
        response = self.key_access.wrap_dek(wrap_request)
        if not response.access_granted:
            raise APIError(response.access_reason or "access denied")

        payload_hash = calculate_payload_hash(plaintext) if options.integrity_check else None
        policy_binding = (
            calculate_policy_binding(dek, options.policy_base64)
            if options.policy_base64
            else None
        )

        manifest = build_manifest_dict(
            filename=options.filename,
            content_type=options.content_type,
            iv=encryption.iv,
            key_access_result=response,
            payload_hash=payload_hash,
            policy_binding=policy_binding,
            policy_base64=options.policy_base64 or None,
            key_access_url=self._key_access_manifest_url(),
        )
        ztdf_blob = package_ztdf(manifest, encryption.ciphertext)
        return WrapResult(ztdf_blob=ztdf_blob, plaintext_size=len(plaintext), encrypted_size=len(encryption.ciphertext))

    def _ensure_ready(self) -> None:
        if not self._initialized:
            self.initialize()

    def _ensure_active_key_pair(self) -> StoredKeyPair:
        if self._current_key_pair and not self._current_key_pair.metadata.expired:
            return self._current_key_pair
        self._current_key_pair = self._register_new_key_pair()
        return self._current_key_pair

    def _register_new_key_pair(self) -> StoredKeyPair:
        if not self.key_manager:
            raise ValidationError("key manager client not configured")

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        public_pem = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        expires_at = datetime.now(timezone.utc) + timedelta(days=1)
        owner_id = self._config.subject_id or self._config.client_id

        registered = self.key_manager.register_key(
            client_id=owner_id,
            public_key_pem=public_pem,
            expires_at=expires_at,
        )
        metadata = KeyMetadata(
            key_id=registered.key_id,
            created_at=registered.created_at,
            expires_at=registered.expires_at or expires_at,
        )
        stored = StoredKeyPair(metadata=metadata, public_key=public_key, private_key=private_key)
        self._key_store.save_key_pair(stored)
        return stored

    def _key_access_manifest_url(self) -> str:
        scheme = "https" if self._config.use_tls else "http"
        return f"{scheme}://{self._config.key_access_address}"
