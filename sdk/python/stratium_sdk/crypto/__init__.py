"""
Cryptographic helpers that mirror the behavior of the Go/Java/JS SDKs.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from dataclasses import dataclass
from typing import Iterable, List, Sequence

from cryptography import exceptions as crypto_exceptions
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..errors import EncryptionError, ValidationError

AES_KEY_SIZE_BYTES = 32
AES_GCM_IV_BYTES = 12


def generate_dek() -> bytes:
    return os.urandom(AES_KEY_SIZE_BYTES)


def generate_iv() -> bytes:
    return os.urandom(AES_GCM_IV_BYTES)


@dataclass
class PayloadEncryptionResult:
    ciphertext: bytes
    iv: bytes


def encrypt_payload(plaintext: bytes, dek: bytes, iv: bytes) -> PayloadEncryptionResult:
    if not plaintext:
        raise ValidationError("plaintext cannot be empty")
    if not dek or len(dek) != AES_KEY_SIZE_BYTES:
        raise ValidationError("DEK must be 32 bytes for AES-256-GCM")
    if not iv or len(iv) != AES_GCM_IV_BYTES:
        raise ValidationError("IV must be 12 bytes for AES-GCM")
    aesgcm = AESGCM(dek)
    ciphertext = aesgcm.encrypt(iv, plaintext, None)
    return PayloadEncryptionResult(ciphertext=ciphertext, iv=iv)


def decrypt_payload(ciphertext: bytes, dek: bytes, iv: bytes) -> bytes:
    try:
        aesgcm = AESGCM(dek)
        return aesgcm.decrypt(iv, ciphertext, None)
    except crypto_exceptions.InvalidTag as exc:
        raise EncryptionError("AES-GCM integrity check failed") from exc
    except Exception as exc:
        raise EncryptionError(f"unable to decrypt payload: {exc}") from exc


def decrypt_segmented_payload(
    payload: bytes,
    dek: bytes,
    base_nonce: bytes,
    segments: Sequence["IntegritySegment"],
    expected_root_hash: bytes | None,
) -> bytes:
    if not segments:
        raise EncryptionError("integrity segments are required for segmented payloads")

    offset = 0
    chunks: List[bytes] = []
    hasher = hashlib.sha256()

    for index, segment in enumerate(segments):
        encrypted_size = segment.encrypted_segment_size
        if encrypted_size <= 0 or offset + encrypted_size > len(payload):
            raise EncryptionError(f"segment {index} exceeds payload bounds")

        chunk = payload[offset : offset + encrypted_size]
        offset += encrypted_size

        if segment.hash_base64:
            expected_hash = segment.digest()
            if hashlib.sha256(chunk).digest() != expected_hash:
                raise EncryptionError(f"segment hash mismatch at index {index}")

        nonce = derive_chunk_nonce(base_nonce, index)
        chunks.append(decrypt_payload(chunk, dek, nonce))
        hasher.update(chunk)

    if offset != len(payload):
        raise EncryptionError("payload length mismatch with integrity segments")

    if expected_root_hash and hasher.digest() != expected_root_hash:
        raise EncryptionError("payload root hash mismatch")

    return b"".join(chunks)


def calculate_payload_hash(payload: bytes) -> bytes:
    return hashlib.sha256(payload).digest()


def verify_payload_hash(payload: bytes, expected: bytes) -> bool:
    return hmac.compare_digest(calculate_payload_hash(payload), expected)


def calculate_policy_binding(dek: bytes, policy_base64: str) -> bytes:
    mac = hmac.new(dek, policy_base64.encode("utf-8"), hashlib.sha256)
    return mac.digest()


def verify_policy_binding(dek: bytes, policy_base64: str, expected_base64: str) -> bool:
    expected = _b64decode(expected_base64)
    actual = calculate_policy_binding(dek, policy_base64)
    return hmac.compare_digest(actual, expected)


def wrap_dek_with_private_key(dek: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    numbers = private_key.private_numbers()
    modulus = numbers.public_numbers.n
    d = numbers.d
    k = (modulus.bit_length() + 7) // 8
    if len(dek) > k - 11:
        raise EncryptionError("DEK is too large for the configured client RSA key")

    ps = b"\xFF" * (k - len(dek) - 3)
    em = b"\x00\x01" + ps + b"\x00" + dek
    m = int.from_bytes(em, "big")
    c = pow(m, d, modulus)
    return c.to_bytes(k, "big")


def decrypt_dek(ciphertext: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
    paddings = [
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA1(), label=None),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None),
        padding.PKCS1v15(),
    ]
    for pad in paddings:
        try:
            return private_key.decrypt(ciphertext, pad)
        except Exception:
            continue
    raise EncryptionError("unable to decrypt DEK using the provided client key")


def derive_chunk_nonce(base_nonce: bytes, index: int) -> bytes:
    if len(base_nonce) < 4:
        return base_nonce
    prefix = base_nonce[:-4]
    counter = (int.from_bytes(base_nonce[-4:], "big") + index) & 0xFFFFFFFF
    return prefix + counter.to_bytes(4, "big")


def load_private_key(pem_data: bytes) -> rsa.RSAPrivateKey:
    key = serialization.load_pem_private_key(pem_data, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise ValidationError("client private key must be RSA")
    return key


def _b64decode(value: str) -> bytes:
    import base64

    return base64.b64decode(value.encode("utf-8"))


@dataclass
class IntegritySegment:
    hash_base64: str
    segment_size: int
    encrypted_segment_size: int

    def digest(self) -> bytes:
        return _b64decode(self.hash_base64)
