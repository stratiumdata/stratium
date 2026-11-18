"""The PDP client.

Every method that can fail returns a value rather than raising. An exception
is one `except Exception: pass` away from becoming an allow; a Decision whose
allowed is False cannot be swallowed that way.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence

import grpc

from ._pdp import pdp_pb2, pdp_pb2_grpc
from ._types import (
    Decision, Grant, Scope, canonical_raw_input,
    decision_from_error, decision_from_response,
)


class Client:
    def __init__(
        self, pdp_addr: str, *, connect_timeout: float = 5.0,
        insecure: bool = False, ca_file: str | None = None,
    ) -> None:
        """Connect to the PDP over TLS, verifying its certificate against
        ca_file (a PEM bundle, for a private CA) or the system roots.

        Plaintext needs insecure=True, for local development only: delegation
        tokens ride on every call and are bearer credentials. A bad ca_file
        raises here, at construction, before any decision could depend on it.
        """
        self._addr = pdp_addr
        self._timeout = connect_timeout
        if insecure:
            if ca_file is not None:
                raise ValueError("insecure=True conflicts with ca_file: choose one")
            self._channel = grpc.insecure_channel(pdp_addr)
        else:
            roots = None
            if ca_file is not None:
                with open(ca_file, "rb") as f:
                    roots = f.read()
            self._channel = grpc.secure_channel(
                pdp_addr, grpc.ssl_channel_credentials(root_certificates=roots))
        self._stub = pdp_pb2_grpc.PDPServiceStub(self._channel)

    def decide(
        self, *, agent_id: str, subject: str, tool: str,
        raw_input: str | Mapping, token: str,
        resource: Mapping[str, str] | None = None,
        approval_id: str | None = None,
    ) -> Decision:
        req = pdp_pb2.DecideRequest(
            agent_id=agent_id, subject=subject, tool=tool,
            raw_input=canonical_raw_input(raw_input), token=token,
        )
        if resource:
            req.resource.update(resource)
        if approval_id:
            # Names a pending approval this call should CONSUME rather than
            # create -- the retry after an EFFECT_ESCALATE. Without it the PDP
            # treats the retry as a fresh ask: the approval is never consumed,
            # a SECOND pending approval is created, and the answer is ESCALATE
            # again, so an approved call never succeeds.
            #
            # Set only when non-empty. The field is `optional string`, and the
            # proto is explicit that an explicitly-sent empty string is a
            # caller bug earning InvalidArgument rather than "no approval".
            req.approval_id = approval_id
        try:
            return decision_from_response(self._stub.Decide(req, timeout=self._timeout))
        except Exception as err:  # noqa: BLE001 -- deliberate; see the module docstring
            # Every failure mode lands here: an unreachable PDP, a non-OK
            # status, a deadline. All of them mean the same thing -- no
            # decision was reached -- and all of them must refuse the call.
            return decision_from_error(err)

    def create_delegation(
        self, *, subject: str, agent_id: str, tools: Sequence[str],
        max_action_tier: int, purpose: str, ttl_seconds: int,
        parent_delegation_id: str | None = None,
        escalate_at: int | None = None,
        parent_token: str | None = None,
    ) -> Grant:
        """Mint a delegation.

        A child (parent_delegation_id set) also needs parent_token: the
        parent grant's own current token. The PDP will not narrow a
        delegation for a caller that only knows its id.

        Raises on failure, unlike decide(): there is no safe fallback value
        for "you have no authority" that a caller could mistake for one, and a
        PEP that cannot get a token has nothing to enforce with.
        """
        req = pdp_pb2.CreateDelegationRequest(
            subject=subject, agent_id=agent_id, purpose=purpose,
            ttl_seconds=ttl_seconds,
            requested_scope=pdp_pb2.RequestedScope(
                max_action_tier=max_action_tier, tools=list(tools)
            ),
        )
        if parent_delegation_id:
            if not parent_token:
                raise ValueError(
                    "parent_token is required with parent_delegation_id: "
                    "pass the parent grant's token")
            req.parent_delegation_id = parent_delegation_id
            req.parent_token = parent_token
        elif parent_token:
            raise ValueError("parent_token is set without parent_delegation_id")
        # Only ever LOWERS the threshold the delegation would carry anyway
        # (the agent's, or the parent's). None asks for nothing; it does not
        # mean "never escalate", and cannot remove an inherited threshold.
        if escalate_at is not None:
            req.requested_scope.escalate_at = escalate_at

        resp = self._stub.CreateDelegation(req, timeout=self._timeout)
        return Grant(
            token=resp.token,
            delegation_id=resp.delegation_id,
            granted_scope=Scope(
                max_action_tier=resp.granted_scope.max_action_tier,
                tools=tuple(resp.granted_scope.tools),
                escalate_at=(resp.granted_scope.escalate_at
                             if resp.granted_scope.HasField("escalate_at") else None),
            ),
            epoch=resp.epoch,
        )

    def get_approval(self, approval_id: str) -> str:
        """The approval's current status, lowercased.

        Here rather than in _escalation so that nothing outside this class
        touches the stub: a Session reaching into client._stub would couple
        two modules through a private attribute, and every later SDK would
        copy the shape.
        """
        resp = self._stub.GetApproval(
            pdp_pb2.GetApprovalRequest(approval_id=approval_id), timeout=self._timeout
        )
        return (resp.status or "").lower()

    def close(self) -> None:
        self._channel.close()

    def __enter__(self) -> "Client":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
