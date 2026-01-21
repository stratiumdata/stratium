"""
Key Manager gRPC client wrapper.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional

import grpc
from google.protobuf import timestamp_pb2

from ..auth import TokenProvider
from ..errors import APIError, ValidationError
from ..proto.services.key_manager import key_manager_pb2, key_manager_pb2_grpc
from .base import call_metadata


@dataclass
class ClientKey:
    key_id: str
    client_id: str
    key_type: key_manager_pb2.KeyType.ValueType
    public_key_pem: str
    status: str
    created_at: datetime
    expires_at: Optional[datetime]
    metadata: Dict[str, str]

    @staticmethod
    def from_proto(proto: key_manager_pb2.Key) -> "ClientKey":
        created = proto.created_at.ToDatetime().replace(tzinfo=timezone.utc) if proto.HasField("created_at") else None
        expires = proto.expires_at.ToDatetime().replace(tzinfo=timezone.utc) if proto.HasField("expires_at") else None
        return ClientKey(
            key_id=proto.key_id,
            client_id=proto.client_id,
            key_type=proto.key_type,
            public_key_pem=proto.public_key_pem,
            status=key_manager_pb2.KeyStatus.Name(proto.status),
            created_at=created or datetime.now(timezone.utc),
            expires_at=expires,
            metadata=dict(proto.metadata),
        )


class KeyManagerClient:
    """Provides helpers for client key registration and lookup."""

    def __init__(self, channel: grpc.Channel, token_provider: Optional[TokenProvider] = None) -> None:
        self._stub = key_manager_pb2_grpc.KeyManagerServiceStub(channel)
        self._token_provider = token_provider

    def register_key(
        self,
        *,
        client_id: str,
        public_key_pem: str,
        key_type: key_manager_pb2.KeyType.ValueType = key_manager_pb2.KEY_TYPE_RSA_2048,
        expires_at: Optional[datetime] = None,
        metadata: Optional[Dict[str, str]] = None,
    ) -> ClientKey:
        if not client_id:
            raise ValidationError("client_id is required")
        if not public_key_pem:
            raise ValidationError("public_key_pem is required")

        proto_request = key_manager_pb2.RegisterClientKeyRequest(
            client_id=client_id,
            public_key_pem=public_key_pem,
            key_type=key_type,
            metadata=metadata or {},
        )
        if expires_at:
            proto_request.expires_at.CopyFrom(_to_timestamp(expires_at))

        response = self._stub.RegisterClientKey(proto_request, metadata=call_metadata(self._token_provider))
        if not response.success:
            raise APIError(response.error_message or "key registration failed")
        return ClientKey.from_proto(response.key)

    def get_key(self, *, client_id: str, key_id: str) -> ClientKey:
        if not client_id:
            raise ValidationError("client_id is required")
        if not key_id:
            raise ValidationError("key_id is required")

        request = key_manager_pb2.GetClientKeyRequest(client_id=client_id, key_id=key_id)
        response = self._stub.GetClientKey(request, metadata=call_metadata(self._token_provider))
        if not response.found:
            raise APIError(response.error_message or "key not found")
        return ClientKey.from_proto(response.key)

    def list_keys(self, *, client_id: str, include_revoked: bool = False) -> List[ClientKey]:
        if not client_id:
            raise ValidationError("client_id is required")

        request = key_manager_pb2.ListClientKeysRequest(client_id=client_id, include_revoked=include_revoked)
        response = self._stub.ListClientKeys(request, metadata=call_metadata(self._token_provider))
        return [ClientKey.from_proto(key) for key in response.keys]


def _to_timestamp(value: datetime) -> timestamp_pb2.Timestamp:
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    ts = timestamp_pb2.Timestamp()
    ts.FromDatetime(value.astimezone(timezone.utc))
    return ts
