// escalation.go implements the PEP's half of E6: on EFFECT_ESCALATE, block
// until a human resolves the pending approval DecideResponse.approval_id
// names, or the configured timeout passes -- then either retry Decide with
// that id or deny. It never decides anything itself: it waits, it retries
// once, it reports. See hook.go's package doc for the boundary every
// enforcement path in this binary shares, and
// internal/pdpgrpc/escalation.go for the PDP-side half of this same RPC
// exchange (creating the pending row, verifying one offered on a retry).
//
// The approval id lives only in memory for the lifetime of one runHook call,
// and travels only over the same gRPC connection Decide already uses --
// never written to a file. It names a live authorization grant (whoever
// presents it on a Decide retry gets whatever resolveEscalation would give
// the original caller, for a matching request), so a second, on-disk copy
// would be worse than none: the same reasoning that keeps raw_input out of
// local logs (hook.go's package doc) applies to this id too. There is no
// file I/O anywhere in this file, which is what actually makes that true --
// not a comment promising it.
package main

import (
	"context"
	"fmt"
	"io"
	"time"

	"stratium/internal/pdpgrpc"
)

// awaitApproval is what runHook's EFFECT_ESCALATE case calls. Every return
// from this function goes through writeDeny except one: a second,
// independent Decide call actually answering EFFECT_ALLOW. A poll resolving
// "approved" proves only that a human signed off on the escalation
// condition, not that the principal, agent, and delegation legs still hold —
// the retry re-evaluates all three fresh, exactly as resolveEscalation
// (internal/pdpgrpc/escalation.go) documents for the server side of this
// same exchange, so this function cannot itself turn a denial into an
// allow no matter what GetApproval reports.
func awaitApproval(
	stdout io.Writer,
	client pdpgrpc.PDPServiceClient,
	cfg hookConfig,
	req *pdpgrpc.DecideRequest,
	resp *pdpgrpc.DecideResponse,
) int {
	approvalID := resp.GetApprovalId()
	if approvalID == "" {
		// DecideResponse.approval_id's own doc comment guarantees this is
		// populated whenever effect is ESCALATE. A PDP build that violates its
		// own contract has given this hook nothing to poll for -- deny rather
		// than guess at an id, the same fail-closed rule every other branch in
		// this file follows for a response it cannot act on.
		return writeDeny(stdout, fmt.Sprintf(
			"stratium-pep: PDP returned ESCALATE with no approval_id to poll; denying (PDP reason: %s)",
			resp.GetReason()))
	}

	// pollCtx bounds the ENTIRE wait at cfg.ApprovalTimeout — independent of
	// cfg.ConnectTimeout, which governs one RPC's round trip, not how long a
	// human may reasonably take to act. A timeout here must deny, never poll
	// forever: an agent silently blocked past this deadline is
	// indistinguishable from a hung tool call (C22).
	pollCtx, cancel := context.WithTimeout(context.Background(), cfg.ApprovalTimeout)
	defer cancel()

	ok, reason := pollApproval(pollCtx, client, cfg.ApprovalPollInterval, approvalID)
	if !ok {
		return writeDeny(stdout, fmt.Sprintf("stratium-pep: %s", reason))
	}

	// The retry: req, unchanged, plus the now-approved id. Reusing req rather
	// than rebuilding one is not just convenient — it is required for
	// correctness: resolveEscalation binds the approval to this exact
	// request via input_digest (Task 3), so resending anything other than
	// byte-identical tool/verb/raw_input/normalized_input would legitimately
	// fail that check. A fresh ConnectTimeout budget, not whatever remains of
	// pollCtx: a slow-but-answering PDP on this one call is the same failure
	// describeRPCError already names for the very first call, not a reason to
	// keep counting against an escalation timeout the poll has already
	// satisfied.
	retryCtx, retryCancel := context.WithTimeout(context.Background(), cfg.ConnectTimeout)
	defer retryCancel()
	req.ApprovalId = &approvalID
	retryResp, err := client.Decide(retryCtx, req)
	if err != nil {
		return writeDeny(stdout, fmt.Sprintf("stratium-pep: retry after approval: %s",
			describeRPCError(err, agentOrDelegationUnknownMsg)))
	}

	if retryResp.GetEffect() == pdpgrpc.Effect_EFFECT_ALLOW {
		return 0
	}
	// EFFECT_DENY — a leg the approval does not cover started refusing
	// between the escalation and this retry (a revoked delegation, a policy
	// that now forbids) — or, defensively, EFFECT_ESCALATE again:
	// resolveEscalation never leaves a verified retry at ESCALATE (see its
	// own doc comment), so this should not happen, but this function polls
	// and retries exactly once, never recursively. Either way this denies.
	return writeDeny(stdout, retryResp.GetReason())
}

// pollApproval blocks until approvalID resolves to "approved" or "denied",
// ctx ends, or GetApproval reports an error this hook cannot recover from —
// whichever happens first. ok is true only for a resolved "approved" status;
// every other outcome reports why in reason, for awaitApproval's deny
// message. approvalID is never included in any error this function lets
// escape to a log file — see the package doc — only in the in-memory reason
// string awaitApproval passes straight to writeDeny's stdout JSON, the same
// transient channel every other deny reason in this binary already uses.
//
// ctx bounds the whole poll (awaitApproval builds it from
// cfg.ApprovalTimeout), not each individual GetApproval call — there is no
// second, per-call timeout the way Decide gets ConnectTimeout, because one
// slow GetApproval response is not the risk this function exists to bound;
// the total wait is, and ctx already cuts off a call that runs past it. Every
// exit this can produce because ctx ended — whether ctx was already done
// before a call, ended while one was in flight, or ended while this function
// was simply waiting for the next tick — reports the same timeoutReason
// below, deterministically, rather than sometimes surfacing the transport's
// own DeadlineExceeded/Canceled text depending on which of two places
// happened to notice first.
//
// The wait between checks is a time.Ticker selected against ctx.Done(),
// never a bare time.Sleep: a channel select is what makes this loop stop the
// instant ctx ends rather than only after whichever sleep happens to be in
// progress finishes. That is the mechanism "a context cancellation or a PEP
// shutdown mid-poll denies rather than hanging" depends on
// (TestPollApproval_ContextCancelledMidPoll_ReturnsPromptlyAndDenies proves
// it directly), and it is also what keeps this loop from busy-waiting: the
// select blocks on the ticker exactly as long as interval says to, whether
// or not GetApproval itself answered instantly
// (TestRunHook_Escalate_PollRespectsInterval_DoesNotBusyWait proves the call
// count this produces stays bounded).
func pollApproval(ctx context.Context, client pdpgrpc.PDPServiceClient, interval time.Duration, approvalID string) (ok bool, reason string) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	timeoutReason := fmt.Sprintf("approval %s did not resolve within the escalation timeout", approvalID)

	for {
		resp, err := client.GetApproval(ctx, &pdpgrpc.GetApprovalRequest{ApprovalId: approvalID})
		if err != nil {
			// ctx.Err() takes priority over whatever GetApproval's error says:
			// when ApprovalTimeout happens to be an exact multiple of interval,
			// the ticker and ctx.Done() become ready in the same instant below,
			// and select's own choice between them is unspecified (Go spec: a
			// select with multiple ready cases picks one pseudo-randomly) — so a
			// call started just as ctx expired can fail with the transport's own
			// DeadlineExceeded/Canceled instead of ever reaching the ctx.Done()
			// case below. Attributing THAT to the timeout too keeps the reported
			// reason deterministic regardless of which branch happened to win,
			// rather than an operator seeing two different messages for the
			// same underlying event depending on scheduling luck.
			if ctx.Err() != nil {
				return false, timeoutReason
			}
			return false, describeRPCError(err, fmt.Sprintf("approval %s is unknown to the PDP", approvalID))
		}

		switch resp.GetStatus() {
		case "approved":
			return true, ""
		case "denied":
			// Deliberately returns here rather than falling through to a
			// retry: a denied approval can never pass Approval.Verify's status
			// check (internal/pdpgrpc's models.Approval.Verify), so sending one
			// anyway would only spend a round trip to receive the same denial
			// back from a different function, with a less specific reason.
			return false, fmt.Sprintf("approval %s was denied", approvalID)
		}
		// Any other value — in practice always "pending" — keeps waiting.

		select {
		case <-ticker.C:
			// Still pending; check again next tick.
		case <-ctx.Done():
			return false, timeoutReason
		}
	}
}
