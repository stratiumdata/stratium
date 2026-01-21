"""
Platform service client wrapper.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional

import grpc
from google.protobuf import struct_pb2

from ..auth import TokenProvider
from ..constants import SubjectAttrID, SubjectAttrSub, SubjectAttrUserID
from ..errors import ValidationError
from ..proto.services.platform import platform_pb2, platform_pb2_grpc
from .base import call_metadata


@dataclass
class AuthorizationDecision:
    decision: platform_pb2.Decision.ValueType
    reason: str
    evaluated_policy: str
    details: Dict[str, str]
    timestamp: Optional[datetime]

    @property
    def allowed(self) -> bool:
        return self.decision == platform_pb2.DECISION_ALLOW


@dataclass
class Condition:
    type: str
    operator: str
    value: str
    parameters: Dict[str, str]


@dataclass
class Entitlement:
    id: str
    subject: str
    resource: str
    actions: List[str]
    conditions: List[Condition]
    metadata: Dict[str, str]
    created_at: Optional[datetime]
    expires_at: Optional[datetime]
    active: bool


class PlatformClient:
    """Thin wrapper around the generated PlatformService stub."""

    def __init__(self, channel: grpc.Channel, token_provider: Optional[TokenProvider] = None) -> None:
        self._stub = platform_pb2_grpc.PlatformServiceStub(channel)
        self._token_provider = token_provider

    def get_decision(
        self,
        *,
        subject_attributes: Dict[str, str],
        resource_attributes: Dict[str, str],
        action: str,
        context: Optional[Dict[str, str]] = None,
        policy_id: Optional[str] = None,
    ) -> AuthorizationDecision:
        _assert_subject_identifier(subject_attributes)
        if not action:
            raise ValidationError("action is required")

        request = platform_pb2.GetDecisionRequest(
            subject_attributes=_string_value_map(subject_attributes),
            resource_attributes=resource_attributes,
            action=action,
            context=context or {},
            policy_id=policy_id or "",
        )
        response = self._stub.GetDecision(request, metadata=call_metadata(self._token_provider))
        timestamp = response.timestamp.ToDatetime().replace(tzinfo=timezone.utc) if response.HasField("timestamp") else None
        return AuthorizationDecision(
            decision=response.decision,
            reason=response.reason,
            evaluated_policy=response.evaluated_policy,
            details=dict(response.details),
            timestamp=timestamp,
        )

    def get_entitlements(
        self,
        *,
        subject_attributes: Dict[str, str],
        resource_filter: str = "",
        action_filter: str = "",
        context: Optional[Dict[str, str]] = None,
    ) -> List[Entitlement]:
        _assert_subject_identifier(subject_attributes)
        request = platform_pb2.GetEntitlementsRequest(
            subject=_string_value_map(subject_attributes),
            resource_filter=resource_filter,
            action_filter=action_filter,
            context=context or {},
        )
        response = self._stub.GetEntitlements(request, metadata=call_metadata(self._token_provider))
        entitlements: List[Entitlement] = []
        for proto in response.entitlements:
            created_at = proto.created_at.ToDatetime().replace(tzinfo=timezone.utc) if proto.HasField("created_at") else None
            expires_at = proto.expires_at.ToDatetime().replace(tzinfo=timezone.utc) if proto.HasField("expires_at") else None
            conditions = [
                Condition(
                    type=condition.type,
                    operator=condition.operator,
                    value=condition.value,
                    parameters=dict(condition.parameters),
                )
                for condition in proto.conditions
            ]
            entitlements.append(
                Entitlement(
                    id=proto.id,
                    subject=proto.subject,
                    resource=proto.resource,
                    actions=list(proto.actions),
                    conditions=conditions,
                    metadata=dict(proto.metadata),
                    created_at=created_at,
                    expires_at=expires_at,
                    active=proto.active,
                )
            )
        return entitlements

    def check_access(self, **kwargs) -> bool:
        """Convenience helper returning True when the platform decision is ALLOW."""

        decision = self.get_decision(**kwargs)
        return decision.allowed


def _string_value_map(values: Dict[str, str]) -> Dict[str, struct_pb2.Value]:
    return {key: struct_pb2.Value(string_value=str(value)) for key, value in values.items()}


def _assert_subject_identifier(values: Dict[str, str]) -> None:
    if not values:
        raise ValidationError("subject_attributes are required")
    if any(key in values for key in (SubjectAttrSub, SubjectAttrUserID, SubjectAttrID)):
        return
    raise ValidationError("subject attributes must include one of: sub, user_id, id")
