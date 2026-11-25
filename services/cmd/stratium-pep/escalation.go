// escalation.go implements the PEP's half of E6: on EFFECT_ESCALATE, block
// until a human resolves the pending approval DecideResponse.approval_id
// names, or the configured timeout passes -- then either retry Decide with
// that id or deny. It never decides anything itself: it waits, it retries
// once, it reports an (effect, reason) pair. See hook.go's package doc for
// the boundary every enforcement path in this binary shares, and
// internal/pdpgrpc/escalation.go for the PDP-side half of this same RPC
// exchange (creating the pending row, verifying one offered on a retry).
//
// pollApproval and resolveApproval are transport-agnostic on purpose: neither
// writes anything or picks an exit code, which is what let mcp.go's
// mcpAuthorizer (Task 2) reuse both completely unmodified for a second
// enforcement surface with a different reporting contract (a correlated
// JSON-RPC error, not stdout JSON and a process exit code). awaitApproval is
// the thin remainder that IS transport-specific — runHook's own stdout/exit-
// code translation of resolveApproval's result — and exists only because
// runHook (hook.go) still calls it directly; see resolveApproval's own doc
// comment for why the split happened here rather than mcp.go reimplementing
// the wait.
//
// resolveApproval reads three timeouts by VALUE, not a cfg struct — a second
// reshape, for proxy.go's authorize (Task 2, proxy's own Phase 11), this
// file's third caller. mcp.go's cfg is genuinely a hookConfig (mcp reuses a
// session file exactly like hook does), so passing it through unmodified cost
// nothing. proxy has no session file at all (its token arrives per call in
// gRPC metadata, never a file this process's own operator wrote ahead of
// time — see proxy.go's own package doc) and carries ListenAddr/TargetAddr
// hookConfig has no room for, so proxyConfig and hookConfig are two
// genuinely different Go types with no shared supertype to convert between.
// The alternative this rejected: build a hookConfig value inside proxy.go
// populated with only the three fields this function actually reads
// (ConnectTimeout, ApprovalPollInterval, ApprovalTimeout) and PDPAddr/
// AgentID/Subject/SessionFilePath left zero. That compiles, but it is a lie
// wearing hookConfig's name — a reader grepping for hookConfig usages would
// find a "hook" config that has never touched a hook, and the zeroed fields
// are safe today only because resolveApproval happens not to read them, an
// implementation detail this signature should not depend on a caller
// noticing. Stating the three durations this function actually needs,
// directly, is the smaller and more honest fix — the same reasoning Phase 6
// already applied once to split resolveApproval out of awaitApproval in the
// first place, applied a second time to the OTHER coupling this function
// still carried.
//
// The approval id lives only in memory for the lifetime of one decision —
// one runHook invocation, or one tools/call frame under mcp — and travels
// only over the same gRPC connection Decide already uses -- never written to
// a file. It names a live authorization grant (whoever presents it on a
// Decide retry gets whatever resolveEscalation would give the original
// caller, for a matching request), so a second, on-disk copy would be worse
// than none: the same reasoning that keeps raw_input out of local logs
// (hook.go's package doc) applies to this id too, for both callers. There is
// no file I/O anywhere in this file, which is what actually makes that true
// -- not a comment promising it.
package main

import (
	"context"
	"fmt"
	"io"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stratiumdata/stratium/internal/pdpgrpc"
)

// awaitApproval is what runHook's EFFECT_ESCALATE case calls: resolveApproval's
// outcome, reported through this hook's own stdout/exit-code contract. All the
// actual waiting, retrying, and effect logic lives in resolveApproval below —
// this function's only remaining job is translating that outcome into what
// runHook's caller (Claude Code's PreToolUse contract) understands.
func awaitApproval(
	stdout io.Writer,
	client pdpgrpc.PDPServiceClient,
	cfg hookConfig,
	req *pdpgrpc.DecideRequest,
	resp *pdpgrpc.DecideResponse,
) int {
	// context.Background(), not some ctx this function invents: runHook (hook.go) has no incoming
	// context of its own to propagate -- a CLI invocation has no network peer that could
	// disconnect mid-poll -- see resolveApproval's own doc comment for why passing anything else
	// here (in particular runHook's own ConnectTimeout-scoped ctx variable, were it threaded this
	// far) would be actively wrong, not merely unnecessary.
	effect, reason := resolveApproval(context.Background(), client, cfg.ConnectTimeout, cfg.ApprovalPollInterval, cfg.ApprovalTimeout, req, resp)
	if effect == pdpgrpc.Effect_EFFECT_ALLOW {
		return 0
	}
	return writeDeny(stdout, reason)
}

// resolveApproval blocks until resp's escalation resolves — approved and
// re-verified by a retry Decide, denied by the approver, or timed out — and
// reports what happened as a plain (effect, reason) pair, independent of how
// any caller reports it. This is the seam Task 2 (the "mcp" enforcement
// surface) needed that the original single-caller awaitApproval did not
// expose: awaitApproval wrote Claude Code's hookOutput JSON to stdout and
// returned a PreToolUse exit code directly inline with its polling and retry
// logic, which is exactly right for a hook and exactly wrong for a second
// transport that has no stdout-JSON contract and no process-exit-per-call
// model at all (mcp.go's mcpAuthorizer instead turns a DENY here into a
// JSON-RPC error correlated to the original request's id, and an ALLOW into
// forwarding the already-held frame — see mcp_authorize.go). Splitting the
// transport-free decision from its reporting is the reshaping this file
// needed for a second mode to reuse it at all; nothing about the escalation
// logic itself — the timeout, the retry, the fail-closed defaults below —
// changed in the split. pollApproval needed no such change: it already took
// no writer and returned no exit code, which is exactly why both callers use
// it completely unmodified.
//
// A poll resolving "approved" proves only that a human signed off on the
// escalation condition, not that the principal, agent, and delegation legs
// still hold — the retry re-evaluates all three fresh, exactly as
// resolveEscalation (internal/pdpgrpc/escalation.go) documents for the server
// side of this same exchange, so this function cannot itself turn a denial
// into an allow no matter what GetApproval reports.
//
// connectTimeout/pollInterval/approvalTimeout are the exact three fields
// every caller's own config type carries under those names (hookConfig,
// proxyConfig) — passed by value rather than by a shared config struct; see
// the package doc for why a concrete hookConfig parameter stopped being the
// right shape once a caller with no session file needed this function too.
//
// ctx is a THIRD reshape the same caller forced, on top of the config-type
// one above -- and that caller is gone: proxy.go stopped blocking entirely in
// Phase 15 (K5/K11, see its own package doc), so BOTH remaining callers pass
// context.Background(). The parameter stays because a function making RPCs
// takes a context, and because the reshape costs those callers nothing:
// ctx is used ONLY as the PARENT for cancellation, never to shorten
// approvalTimeout itself: context.WithTimeout(ctx, approvalTimeout) resolves
// whichever of ctx's own cancellation or approvalTimeout comes first, so a
// caller passing context.Background() (hook.go, mcp_authorize.go -- neither
// has a deadline of its own to contribute) sees IDENTICAL behavior to before
// this parameter existed. What it BOUGHT, and what a future caller holding a
// real caller-supplied context would get back, is prompt exit when the
// original caller disconnects mid-poll, instead of continuing to hold a
// goroutine and spend GetApproval calls against a call nothing is listening
// for anymore. That is worth keeping reachable, and it is why hook.go's own
// ctx variable (built inside runHook, scoped to cfg.ConnectTimeout -- a much
// SHORTER budget meant for one RPC's round trip, not an entire escalation
// wait) is deliberately NOT what awaitApproval passes here: reusing it would
// silently cap every hook escalation at ConnectTimeout instead of
// ApprovalTimeout, the exact miscalibration this function's own
// long-standing "independent of connectTimeout" contract (below) exists to
// prevent. Each caller passes what it actually has to offer, not whatever
// context.Context value happens to be lying around in its own scope.
//
// A third return value carrying the retry's own DecideResponse was added in Phase 15 and REMOVED
// again in the same phase, which is worth one sentence so nobody re-adds it half-remembering why:
// proxy.go's authorize needed it to apply spec §4.7.2 K5 to the response an escalation RESOLVED
// to rather than to the escalation itself, and then proxy stopped calling this function at all.
// Both remaining callers would have discarded it -- a bearer token is legitimate on hook and mcp,
// so neither has a K5 rule to apply -- and a return value every caller ignores is dead API. A
// caller that needs it again should add it back and hand the RESOLVED response, never the
// escalation, to whatever narrows the allow.
func resolveApproval(
	ctx context.Context,
	client pdpgrpc.PDPServiceClient,
	connectTimeout, pollInterval, approvalTimeout time.Duration,
	req *pdpgrpc.DecideRequest,
	resp *pdpgrpc.DecideResponse,
) (effect pdpgrpc.Effect, reason string) {
	approvalID := resp.GetApprovalId()
	if approvalID == "" {
		// DecideResponse.approval_id's own doc comment guarantees this is
		// populated whenever effect is ESCALATE. A PDP build that violates its
		// own contract has given this caller nothing to poll for -- deny rather
		// than guess at an id, the same fail-closed rule every other branch in
		// this file follows for a response it cannot act on.
		return pdpgrpc.Effect_EFFECT_DENY, fmt.Sprintf(
			"stratium-pep: PDP returned ESCALATE with no approval_id to poll; denying (PDP reason: %s)",
			resp.GetReason())
	}

	// pollCtx bounds the wait at approvalTimeout AT THE LATEST -- independent
	// of connectTimeout, which governs one RPC's round trip, not how long a
	// human may reasonably take to act -- or ends sooner if ctx itself ends
	// first (see this function's own doc comment for why that is safe for
	// every caller, not just the one that motivated it). A timeout here must
	// deny, never poll forever: an agent silently blocked past this deadline
	// is indistinguishable from a hung tool call (C22).
	pollCtx, cancel := context.WithTimeout(ctx, approvalTimeout)
	defer cancel()

	ok, pollReason := pollApproval(pollCtx, client, pollInterval, approvalID, req.GetToken())
	if !ok {
		return pdpgrpc.Effect_EFFECT_DENY, fmt.Sprintf("stratium-pep: %s", pollReason)
	}

	// The retry: req, unchanged, plus the now-approved id. Reusing req rather
	// than rebuilding one is not just convenient — it is required for
	// correctness: resolveEscalation binds the approval to this exact
	// request via input_digest (Task 3), so resending anything other than
	// byte-identical tool/verb/raw_input/normalized_input would legitimately
	// fail that check. A fresh connectTimeout budget, not whatever remains of
	// pollCtx: a slow-but-answering PDP on this one call is the same failure
	// describeRPCError already names for the very first call, not a reason to
	// keep counting against an escalation timeout the poll has already
	// satisfied. Still derived from ctx, for the identical early-exit reason
	// pollCtx is: a caller that vanished during the poll has no more use for
	// a retry that succeeds after it than for one that keeps polling.
	retryCtx, retryCancel := context.WithTimeout(ctx, connectTimeout)
	defer retryCancel()
	req.ApprovalId = &approvalID
	retryResp, err := client.Decide(retryCtx, req)
	if err != nil {
		return pdpgrpc.Effect_EFFECT_DENY, fmt.Sprintf("stratium-pep: retry after approval: %s",
			describeRPCError(err, agentOrDelegationUnknownMsg))
	}

	if retryResp.GetEffect() == pdpgrpc.Effect_EFFECT_ALLOW {
		return pdpgrpc.Effect_EFFECT_ALLOW, ""
	}
	// EFFECT_DENY — a leg the approval does not cover started refusing
	// between the escalation and this retry (a revoked delegation, a policy
	// that now forbids) — or, defensively, EFFECT_ESCALATE again:
	// resolveEscalation never leaves a verified retry at ESCALATE (see its
	// own doc comment), so this should not happen, but this function polls
	// and retries exactly once, never recursively. Either way this denies,
	// with the retry's OWN reason passed through unprefixed — like runHook's
	// top-level DENY case, this is the PDP's own verdict text, not a local
	// diagnostic this process is synthesizing, and the two must stay visually
	// distinguishable to a human reading the denial.
	return pdpgrpc.Effect_EFFECT_DENY, retryResp.GetReason()
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
func pollApproval(ctx context.Context, client pdpgrpc.PDPServiceClient, interval time.Duration, approvalID, token string) (ok bool, reason string) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	timeoutReason := fmt.Sprintf("approval %s did not resolve within the escalation timeout", approvalID)

	for {
		resp, err := client.GetApproval(ctx, &pdpgrpc.GetApprovalRequest{ApprovalId: approvalID, Token: token})
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
			//
			// A DeadlineExceeded status counts as well, with ctx still live.
			// ctx's deadline is the only one this call has, and the PDP
			// enforces the same deadline from its side of the wire: its
			// answer can arrive a moment before this process's own timer
			// fires.
			if ctx.Err() != nil || status.Code(err) == codes.DeadlineExceeded {
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
