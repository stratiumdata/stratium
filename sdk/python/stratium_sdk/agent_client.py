"""
Agent-aware Stratium client for AI agent authorization with delegation tokens.

Provides double-hop authorization where every agent action is evaluated against
both the user's permissions and the agent's permissions within a delegation context.

Example::

    from stratium_sdk import StratiumConfig, AgentConfig, StratiumAgentClient, ActionTier

    config = StratiumConfig(
        platform_address="localhost:50051",
        key_access_address="localhost:50053",
        bearer_token="<user-oidc-token>",
    )
    agent_config = AgentConfig(
        agent_id="<registered-agent-id>",
        agent_secret="<agent-client-secret>",
        gateway_address="localhost:50054",
    )

    client = StratiumAgentClient(config, agent_config)
    client.initialize()

    delegation = client.create_delegation(
        purpose="Research documents",
        max_action_tier=ActionTier.READ_ONLY,
        approved_tools=["read_file", "search"],
        classification_caps={"nato": "CONFIDENTIAL"},
    )

    result = client.execute_action(
        action="read",
        tool_name="read_file",
        action_tier=ActionTier.READ_ONLY,
        target_service="key-access",
        method="/key_access.KeyAccessService/UnwrapDEK",
        resource_attributes={"classification": "CONFIDENTIAL", "hierarchy": "nato"},
    )
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
from typing import Dict, List, Optional, Sequence

import grpc

from .auth import TokenProvider, build_token_provider
from .config import StratiumConfig
from .errors import APIError, ValidationError
from .grpc_clients.base import create_channel


class ActionTier(IntEnum):
    """Sensitivity level of an action."""

    REASONING = 0
    READ_ONLY = 1
    INTERNAL_MODIFY = 2
    EXTERNAL_COMMS = 3
    DESTRUCTIVE = 4


class AgentTrustTier(IntEnum):
    """Trust level assigned to an agent."""

    UNVERIFIED = 0
    REGISTERED = 1
    CERTIFIED = 2
    PLATFORM_TRUSTED = 3


@dataclass
class AgentConfig:
    """Configuration for agent authentication."""

    agent_id: str
    agent_secret: str
    gateway_address: str
    default_purpose: str = ""
    default_max_tier: ActionTier = ActionTier.READ_ONLY
    classification_caps: Dict[str, str] = field(default_factory=dict)

    def validate(self) -> None:
        if not self.agent_id:
            raise ValidationError("agent_id is required")
        if not self.gateway_address:
            raise ValidationError("gateway_address is required")


@dataclass
class Delegation:
    """Represents an active delegation token."""

    token: str
    delegation_id: str
    depth: int
    expires_at: datetime
    root_delegation_id: str


@dataclass
class AgentAction:
    """An action to execute through the Agent Gateway."""

    action: str
    tool_name: str
    action_tier: ActionTier = ActionTier.READ_ONLY
    target_service: str = ""
    method: str = ""
    resource_attributes: Dict[str, str] = field(default_factory=dict)
    payload: bytes = b""


@dataclass
class ActionResult:
    """Result of an agent action execution."""

    authorized: bool
    payload: bytes = b""
    error: str = ""
    denied_at_depth: int = -1
    denied_principal: str = ""


@dataclass
class PlannedAction:
    """An action to validate before execution."""

    tool_name: str
    action: str
    declared_tier: ActionTier = ActionTier.READ_ONLY
    resource: Dict[str, str] = field(default_factory=dict)
    parameters: Dict[str, str] = field(default_factory=dict)


@dataclass
class ActionValidationItem:
    """Validation result for a single action."""

    action_index: int
    valid: bool
    reason: str = ""
    actual_tier: ActionTier = ActionTier.REASONING
    tier_mismatch: bool = False


@dataclass
class ValidationResult:
    """Result of action plan validation."""

    valid: bool
    results: List[ActionValidationItem] = field(default_factory=list)


class StratiumAgentClient:
    """
    Agent-aware Stratium client with delegation token flows.

    Wraps a standard StratiumConfig with agent credentials and provides
    methods for creating delegations, executing actions through the gateway,
    and validating action plans.
    """

    def __init__(
        self,
        user_config: StratiumConfig,
        agent_config: AgentConfig,
        token_provider: Optional[TokenProvider] = None,
    ) -> None:
        self._user_config = user_config
        self._agent_config = agent_config
        self._agent_config.validate()

        self._token_provider = token_provider or build_token_provider(user_config)
        self._gateway_channel: Optional[grpc.Channel] = None
        self._gateway_stub = None
        self._active_delegation: Optional[Delegation] = None
        self._initialized = False

    def initialize(self) -> None:
        """Establish connection to the Agent Gateway."""
        if self._initialized:
            return

        self._gateway_channel = create_channel(
            self._agent_config.gateway_address,
            self._user_config.use_tls,
        )
        # Import the generated stub lazily to avoid hard dependency on proto gen
        try:
            from .proto.services.agent_gateway import (
                agent_gateway_pb2_grpc as ag_grpc,
            )

            self._gateway_stub = ag_grpc.AgentGatewayServiceStub(self._gateway_channel)
        except ImportError:
            raise ImportError(
                "Agent Gateway proto stubs not found. "
                "Generate them with: cd sdk/python && make generate-proto"
            )

        self._initialized = True

    def create_delegation(
        self,
        purpose: str = "",
        max_action_tier: ActionTier = ActionTier.READ_ONLY,
        approved_tools: Optional[Sequence[str]] = None,
        approved_actions: Optional[Sequence[ActionTier]] = None,
        classification_caps: Optional[Dict[str, str]] = None,
        resource_constraints: Optional[Dict[str, str]] = None,
        ttl_seconds: int = 900,
        conversation_id: str = "",
    ) -> Delegation:
        """Create a delegation for this user+agent pair."""
        self._ensure_initialized()
        from .proto.services.agent_gateway import agent_gateway_pb2 as ag_pb

        purpose = purpose or self._agent_config.default_purpose
        if classification_caps is None:
            classification_caps = self._agent_config.classification_caps

        proto_actions = [ag_pb.ActionTier.Value(f"ACTION_TIER_{a.name}") for a in (approved_actions or [])]

        request = ag_pb.CreateDelegationRequest(
            agent_id=self._agent_config.agent_id,
            approved_tools=list(approved_tools or []),
            approved_actions=proto_actions,
            max_action_tier=int(max_action_tier),
            classification_caps=classification_caps or {},
            resource_constraints=resource_constraints or {},
            purpose=purpose,
            ttl_seconds=ttl_seconds,
            conversation_id=conversation_id,
        )

        metadata = self._auth_metadata()
        response = self._gateway_stub.CreateDelegation(request, metadata=metadata)

        expires_at = datetime.fromtimestamp(
            response.expires_at.seconds, tz=timezone.utc
        ) if response.expires_at else datetime.now(timezone.utc)

        delegation = Delegation(
            token=response.delegation_token,
            delegation_id=response.delegation_id,
            depth=response.depth,
            expires_at=expires_at,
            root_delegation_id=response.root_delegation_id,
        )
        self._active_delegation = delegation
        return delegation

    def execute_action(
        self,
        action: str,
        tool_name: str,
        action_tier: ActionTier = ActionTier.READ_ONLY,
        target_service: str = "",
        method: str = "",
        resource_attributes: Optional[Dict[str, str]] = None,
        payload: bytes = b"",
    ) -> ActionResult:
        """Execute an action through the Agent Gateway with double-hop auth."""
        self._ensure_initialized()
        self._ensure_delegation()
        from .proto.services.agent_gateway import agent_gateway_pb2 as ag_pb

        request = ag_pb.ExecuteActionRequest(
            delegation_token=self._active_delegation.token,
            target_service=target_service,
            method=method,
            action=action,
            action_tier=int(action_tier),
            tool_name=tool_name,
            resource_attributes=resource_attributes or {},
            payload=payload,
        )

        response = self._gateway_stub.ExecuteAction(request)

        result = ActionResult(
            authorized=response.authorized,
            payload=response.payload,
            error=response.error,
        )
        if response.decision:
            result.denied_at_depth = response.decision.denied_at_depth
            result.denied_principal = response.decision.denied_principal
        return result

    def validate_action_plan(
        self,
        actions: Sequence[PlannedAction],
    ) -> ValidationResult:
        """Validate a set of planned actions before execution."""
        self._ensure_initialized()
        self._ensure_delegation()
        from .proto.services.agent_gateway import agent_gateway_pb2 as ag_pb

        proto_actions = []
        for a in actions:
            proto_actions.append(
                ag_pb.PlannedAction(
                    tool_name=a.tool_name,
                    action=a.action,
                    declared_tier=int(a.declared_tier),
                    resource=a.resource,
                    parameters=a.parameters,
                )
            )

        request = ag_pb.ValidateActionPlanRequest(
            delegation_id=self._active_delegation.delegation_id,
            actions=proto_actions,
        )

        response = self._gateway_stub.ValidateActionPlan(request)

        return ValidationResult(
            valid=response.valid,
            results=[
                ActionValidationItem(
                    action_index=r.action_index,
                    valid=r.valid,
                    reason=r.reason,
                    actual_tier=ActionTier(r.actual_tier),
                    tier_mismatch=r.tier_mismatch,
                )
                for r in response.results
            ],
        )

    def revoke_delegation(self, reason: str = "") -> None:
        """Revoke the active delegation."""
        self._ensure_initialized()
        self._ensure_delegation()
        from .proto.services.agent_gateway import agent_gateway_pb2 as ag_pb

        request = ag_pb.RevokeDelegationRequest(
            delegation_id=self._active_delegation.delegation_id,
            reason=reason,
        )
        self._gateway_stub.RevokeDelegation(request)
        self._active_delegation = None

    @property
    def active_delegation(self) -> Optional[Delegation]:
        """Return the current active delegation, or None."""
        return self._active_delegation

    def close(self) -> None:
        """Close the gateway channel."""
        if self._gateway_channel is not None:
            self._gateway_channel.close()
            self._gateway_channel = None
        self._initialized = False

    def __enter__(self) -> StratiumAgentClient:
        self.initialize()
        return self

    def __exit__(self, *args) -> None:
        self.close()

    # --- Internal ---

    def _ensure_initialized(self) -> None:
        if not self._initialized:
            raise APIError("client not initialized — call initialize() first")

    def _ensure_delegation(self) -> None:
        if self._active_delegation is None:
            raise APIError("no active delegation — call create_delegation() first")

    def _auth_metadata(self) -> List[tuple]:
        """Build gRPC metadata with the bearer token."""
        if self._token_provider is None:
            return []
        token = self._token_provider.get_token()
        if token:
            return [("authorization", f"Bearer {token}")]
        return []
