"""
Shared utilities for gRPC clients.
"""

from __future__ import annotations

from typing import Iterable, Optional, Sequence, Tuple

import grpc

from ..auth import TokenProvider
from ..constants import AuthHeaderPrefix


def create_channel(address: str, use_tls: bool) -> grpc.Channel:
    """Creates either a secure or insecure gRPC channel for the supplied address."""

    if use_tls:
        credentials = grpc.ssl_channel_credentials()
        return grpc.secure_channel(address, credentials)
    return grpc.insecure_channel(address)


def call_metadata(token_provider: Optional[TokenProvider]) -> Optional[Sequence[Tuple[str, str]]]:
    if not token_provider:
        return None
    token = token_provider.get_token()
    return (("authorization", f"{AuthHeaderPrefix}{token}"),)
