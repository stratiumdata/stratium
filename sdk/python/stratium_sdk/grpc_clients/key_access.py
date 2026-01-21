"""
Key Access service client wrapper.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional

import grpc

from ..auth import TokenProvider
from ..errors import ValidationError
from ..proto.services.key_access import key_access_pb2, key_access_pb2_grpc
from .base import call_metadata


@dataclass
class WrapDEKRequest:
    resource: str
    client_wrapped_dek: bytes
    action: str = "wrap"
    context: Dict[str, str] = field(default_factory=dict)
    policy: str = ""
    client_key_id: str = ""

    def validate(self) -> None:
        if not self.resource:
            raise ValidationError("resource is required for DEK wrapping")
        if not self.client_wrapped_dek:
            raise ValidationError("client_wrapped_dek cannot be empty")
        if not self.client_key_id:
            raise ValidationError("client_key_id is required")


@dataclass
class WrapDEKResponse:
    wrapped_dek: bytes
    key_id: str
    access_granted: bool
    access_reason: str


@dataclass
class UnwrapDEKResponse:
    dek_for_subject: bytes
    access_granted: bool
    access_reason: str


class KeyAccessClient:
    """Thin wrapper around the generated gRPC stub with automatic auth metadata."""

    def __init__(self, channel: grpc.Channel, token_provider: Optional[TokenProvider] = None) -> None:
        self._stub = key_access_pb2_grpc.KeyAccessServiceStub(channel)
        self._token_provider = token_provider

    def wrap_dek(self, request: WrapDEKRequest) -> WrapDEKResponse:
        request.validate()
        metadata = call_metadata(self._token_provider)
        proto_request = key_access_pb2.WrapDEKRequest(
            resource=request.resource,
            dek=request.client_wrapped_dek,
            action=request.action or "wrap",
            context=request.context,
            policy=request.policy or "",
            client_key_id=request.client_key_id,
        )
        response = self._stub.WrapDEK(proto_request, metadata=metadata)
        return WrapDEKResponse(
            wrapped_dek=response.wrapped_dek,
            key_id=response.key_id,
            access_granted=response.access_granted,
            access_reason=response.access_reason,
        )

    def unwrap_dek(
        self,
        *,
        resource: str,
        wrapped_dek: bytes,
        key_id: str,
        client_key_id: str,
        action: str = "unwrap",
        context: Optional[Dict[str, str]] = None,
        policy: str = "",
    ) -> UnwrapDEKResponse:
        if not resource:
            raise ValidationError("resource is required")
        if not key_id:
            raise ValidationError("key_id is required")
        if not client_key_id:
            raise ValidationError("client_key_id is required")
        if not wrapped_dek:
            raise ValidationError("wrapped_dek cannot be empty")

        metadata = call_metadata(self._token_provider)
        proto_request = key_access_pb2.UnwrapDEKRequest(
            resource=resource,
            wrapped_dek=wrapped_dek,
            key_id=key_id,
            client_key_id=client_key_id,
            action=action or "unwrap",
            context=context or {},
            policy=policy or "",
        )
        response = self._stub.UnwrapDEK(proto_request, metadata=metadata)
        return UnwrapDEKResponse(
            dek_for_subject=response.dek_for_subject,
            access_granted=response.access_granted,
            access_reason=response.access_reason,
        )
