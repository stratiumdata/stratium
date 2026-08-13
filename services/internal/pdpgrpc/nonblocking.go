package pdpgrpc

// DegradeEscalateToDeny reports what a non-blocking enforcement surface
// (extauthz — spec E5/§4.7, C23) must do with resp. Such a surface cannot
// hold a call open for human approval — Envoy's ext_authz check has a
// millisecond timeout budget, not minutes (§4.6) — so EFFECT_ESCALATE
// degrades to a denial, with the pending approval's id carried forward
// unchanged so a later retry, once approved, can present it. That is the
// whole of what E5's "deny plus a pending approval record" requires.
//
// deny is true for anything that is not an outright EFFECT_ALLOW —
// EFFECT_DENY and a degraded EFFECT_ESCALATE alike, since a surface that
// cannot express ESCALATE has only two answers available. approvalID is
// resp's own ApprovalId, unchanged: Decide already populates it only on
// EFFECT_ESCALATE and leaves it empty on every other effect
// (DecideResponse.approval_id's own doc comment, proto/pdp/v1/pdp.proto),
// so this function adds no new fact and cannot fabricate a pending record
// for a genuine, non-escalated denial — it only names the mapping a
// non-blocking surface performs on what Decide already sends every surface.
// A nil resp (never returned by a real Decide call, but not trusted to be
// impossible here) fails closed the same way: GetEffect's own nil handling
// returns EFFECT_DENY, never EFFECT_ALLOW.
//
// Its first real caller is cmd/stratium-pep/extauthz.go's
// checkResponseFromDecide, wired in the same phase that made the extauthz
// surface exist at all (Phase 10 Task 3) — and this shape needed no change
// to serve it. deny is exactly the ALLOW/not-ALLOW fold Check needs to
// choose between an OkResponse and a PERMISSION_DENIED; approvalID is
// exactly the value that denial attaches when there is one. What that
// caller does NOT lean on this function for is which reason text to show:
// deciding whether a denial should read as an ordinary refusal or as "this
// is pending approval" is a response-framing question this function was
// never asked, so checkResponseFromDecide reads resp.GetEffect() itself for
// that rather than inferring escalation from approvalID being non-empty a
// second time — the same "assert the invariant, do not lean on it holding"
// discipline this function's own defensive nil-handling above already
// follows for EFFECT_DENY's zero value. See checkResponseFromDecide's own
// doc comment for why, and its
// TestCheckResponseFromDecide_DenyWithStrayApprovalID_NotTreatedAsEscalation
// for the case that distinction actually guards.
//
// See TestC23_NonBlockingSurfaceDegradesToDeny
// (internal/authz/conformance_test.go) for the separate question of whether
// that conformance property can now be unskipped — Phase 10 Task 4's call,
// since internal/authz itself stays untouched here, not this function's.
func DegradeEscalateToDeny(resp *DecideResponse) (deny bool, approvalID string) {
	return resp.GetEffect() != Effect_EFFECT_ALLOW, resp.GetApprovalId()
}
