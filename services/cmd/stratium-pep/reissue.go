// reissue.go is the PEP's answer to a token that has outlived its usefulness:
// a long agent session can easily outlast a short-lived token even though
// the delegation behind it is still good for hours more (spec §4.7.1 K1/K2).
// reissueAndRetryDecide is called only when the FIRST Decide response for a
// tool call came back EFFECT_DENY -- never for ALLOW (nothing to fix) or
// ESCALATE (the token already authenticated; what is pending is a human
// decision, not a credential problem) -- see hook.go's runHook and
// mcp_authorize.go's decideAndRelay for the two call sites.
//
// It deliberately does NOT try to tell "the token expired" apart from "the
// policy denied this call" before deciding whether to reissue. Both reach
// the PEP as the exact same wire shape -- EFFECT_DENY, no distinguishing
// field (see internal/pdpgrpc/server.go's denyAndAudit, which routes a token
// failure and an ordinary policy denial through one shared helper) -- so the
// only way to tell them apart here would be pattern-matching the PDP's own
// Reason text, which is exactly the kind of local interpretation this binary
// exists not to do (hook.go's package doc: it classifies nothing, decides
// nothing). Attempting one reissue on ANY denial, then trusting the retried
// Decide call's own fresh, full evaluation as the real answer, needs no such
// guess: a denial that had nothing to do with the token simply comes back
// denied again on retry, at the cost of one extra round trip, never a false
// allow -- IssueToken re-validates the delegation independently (its own doc
// comment) and the retried Decide re-evaluates all three legs independently,
// so nothing here can widen what either would have decided on its own.
//
// Bounded to exactly one attempt, with no loop and no recursion: a PEP that
// kept reissuing on every subsequent denial would leave a tool call whose
// delegation is genuinely dead (revoked, or expired past what any new token
// could paper over) hung indistinguishably from a broken one -- the same
// reasoning cfg.ApprovalTimeout already rests C22's escalation wait on
// (escalation.go's resolveApproval). One IssueToken call, one retried
// Decide call, then whatever that pair produced is final.
//
// The reissued token is used for this one retry and discarded, the same
// in-memory-only shape escalation.go's approval id already has (see that
// file's own package doc): it is never written back to the session file
// (writeSessionFile has exactly one caller, session-start -- session_file.go's
// package doc) and never cached anywhere this function, or its callers, can
// reach again on a later call. The next tool call reads the session file
// fresh, per loadSessionFile's own contract, and pays the same reissue cost
// again if the cached token is still the expired one -- slower than caching
// a reissued token would be, but caching one inside mcp's long-lived
// mcpAuthorizer would mean a session ending (the file deleted) or a
// revocation stops taking effect on the very next call, exactly the
// property session_file.go's package doc says must be preserved.
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/stratiumdata/stratium/internal/pdpgrpc"
)

// reissueTTLSeconds is what every IssueToken call this file makes requests.
// Not a guess at how long the caller actually needs -- IssueToken always
// clamps whatever is requested down to the named delegation's own remaining
// expires_at (internal/pdpgrpc/token.go's clampTokenExpiry), the identical
// clamp CreateDelegation's own first token relies on when it asks for
// exactly the delegation's expiry with nothing independently requested at
// all (delegation.go's own comment on that call). Asking for far more than
// any real delegation will ever have left, rather than picking a shorter
// duration this binary has no basis for, means the reissued token's actual
// expiry always comes from the delegation's own row -- the one source of
// truth for how long it may live -- never from a value guessed here.
const reissueTTLSeconds int64 = 10 * 365 * 24 * 60 * 60 // 10 years; always clamped down in practice

// reissueAndRetryDecide mints exactly one fresh token for delegationID via
// IssueToken, then retries req -- now carrying that token -- exactly once
// against Decide. A non-nil error means either call failed and the caller
// must deny; a non-nil response is a genuine retried decision (ALLOW,
// ESCALATE, or a fresh DENY) that the caller's own switch handles exactly as
// it would have handled the first Decide response. See the package doc for
// why this never attempts a second reissue and never inspects why the first
// call was denied.
//
// req is reused, not rebuilt, and its Token field is mutated in place before
// the retry -- the same reuse-not-rebuild choice escalation.go's
// resolveApproval makes for its own post-approval retry (that function's own
// doc comment explains why: resending anything other than the original
// request risks failing a binding check it does not actually need to risk
// here, and reusing the identical struct is what guarantees the retry asks
// about exactly the same tool call). A caller that goes on to escalate after
// a successful reissue (an unusual but possible ordering -- a token denial
// followed by a fresh evaluation that turns out to need human approval)
// therefore polls and retries under the NEW token, not the stale one that
// was just replaced, without either caller needing to thread it through
// separately.
//
// connectTimeout is read by VALUE, not a cfg hookConfig struct: this
// function has exactly one caller in hook.go (a genuine hookConfig) and one
// in mcp_authorize.go's decideAndRelay (mcpAuthorizer.cfg, ALSO a
// hookConfig, per that struct's own deliberate reuse -- see its doc
// comment), but reads only this one field of either. A concrete hookConfig
// parameter here would be the identical "lie wearing hookConfig's name"
// escalation.go's own package doc already named and fixed for
// resolveApproval, one function over, for the same reason: a signature
// naming a caller-shaped type it mostly ignores reads as hook-specific to
// anyone grepping for hookConfig usages, when this logic is not -- both of
// its real callers already prove that -- and a future third caller with no
// hookConfig of its own (proxy's authorize needed exactly this reshape for
// resolveApproval, escalation.go's own doc comment) would hit the identical
// wall resolveApproval already hit before this parameter existed. Stating
// the one duration this function actually needs, directly, is the smaller
// and more honest fix, applying the same lesson to this function that
// resolveApproval's own history already paid for once.
func reissueAndRetryDecide(
	client pdpgrpc.PDPServiceClient,
	connectTimeout time.Duration,
	delegationID string,
	req *pdpgrpc.DecideRequest,
) (*pdpgrpc.DecideResponse, error) {
	issueCtx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	issued, err := client.IssueToken(issueCtx, &pdpgrpc.IssueTokenRequest{
		DelegationId: delegationID,
		TtlSeconds:   reissueTTLSeconds,
		// The token being replaced authenticates the request: the PDP will
		// not mint for a bare delegation id. It checks this token's
		// signature and delegation, not its expiry.
		Token: req.GetToken(),
	})
	if err != nil {
		return nil, fmt.Errorf("re-issue token: %s", describeRPCError(err, agentOrDelegationUnknownMsg))
	}

	req.Token = issued.GetToken()

	retryCtx, retryCancel := context.WithTimeout(context.Background(), connectTimeout)
	defer retryCancel()
	resp, err := client.Decide(retryCtx, req)
	if err != nil {
		return nil, fmt.Errorf("retry after re-issuing token: %s", describeRPCError(err, agentOrDelegationUnknownMsg))
	}
	return resp, nil
}
