package authz

import (
	"context"
	"fmt"

	"github.com/stratiumdata/stratium/pkg/models"
)

// RequestedScope is what the caller asked for when creating a delegation.
type RequestedScope struct {
	MaxActionTier models.ActionTier
	Tools         []string
}

// GrantedScope is what survived the clamp, with what was removed and why.
type GrantedScope struct {
	MaxActionTier models.ActionTier

	// Tools is nil both when nothing was requested and when every requested
	// tool was clamped away — the two cannot be told apart from this field
	// alone. That collision matters here specifically: Agent.HasTool and
	// Delegation.HasTool both treat an empty tool list as UNRESTRICTED,
	// deliberately (models/agent.go, models/delegation.go), so writing a
	// fully-denied Tools straight into a HasTool-shaped field would grant
	// the opposite of what the clamp decided. Removed is what disambiguates
	// — check it for "tool" entries, or compare against the length of the
	// original RequestedScope.Tools the caller already holds — before this
	// crosses into anything that reads an empty list as unrestricted.
	Tools []string

	// Removed names each dimension that was clamped away and the reason, so
	// the caller and the audit row can both say what happened rather than
	// silently returning something narrower than was asked for.
	Removed []ClampRemoval
}

// ClampRemoval names one thing Clamp took away from the request, and why.
type ClampRemoval struct {
	// Dimension is "tier" or "tool". A plain string, not an enum, matching
	// PolicyVerdict.Source: this is written straight into an audit row and
	// an API response, both of which want the string, and a closed Go type
	// buys nothing neither of them can already do with one.
	Dimension string

	// Value is the specific value that did not survive: the requested
	// tier's name for "tier", or the tool name for "tool".
	Value string

	// Reason distinguishes a policy that genuinely said no from a question
	// that could not be answered at all. The two need different operator
	// responses — a denial is a decision to challenge or accept; a probe
	// error is an outage to go fix — so this is its own field, not folded
	// into a string an operator would have to pattern-match.
	Reason ClampReason

	// Detail carries the probe error's text when Reason is
	// ClampReasonProbeError. Empty for ClampReasonDenied — there is no
	// engine error to report, only a verdict.
	Detail string
}

// ClampReason is why a dimension did not survive the clamp.
type ClampReason int

const (
	// ClampReasonDenied means the policy set was asked and said no.
	ClampReasonDenied ClampReason = iota
	// ClampReasonProbeError means the question could not be answered at
	// all. Fail-closed: unanswerable is not a grant (spec §3.8 G6).
	ClampReasonProbeError
)

func (r ClampReason) String() string {
	if r == ClampReasonProbeError {
		return "probe error"
	}
	return "denied"
}

// Clamp narrows req to the intersection of what was requested and what
// allows grants, one resource-independent dimension at a time — the tier
// ceiling and the tool set (spec §3.8 G6). It never rejects the request
// outright: §3.3 Y4 is clamp-silently-and-record, not fail the creation, so
// an over-broad default degrades to what the principal actually holds
// instead of failing hard the way dropping straight to nothing would. Every
// dimension it drops is named in the returned GrantedScope.Removed.
//
// allows is injected so this package stays pure: no policy engine and no
// database handle reach into authz. Task 3 supplies one backed by
// policy.Probe. allows itself takes no context — Clamp's ctx exists only so
// a caller whose request is already cancelled is not made to sit through a
// tier walk and a tool-by-tool probe for nothing.
func Clamp(
	ctx context.Context,
	req RequestedScope,
	allows func(tool string, tier models.ActionTier) (bool, error),
) (GrantedScope, error) {
	if err := ctx.Err(); err != nil {
		return GrantedScope{}, fmt.Errorf("clamp: %w", err)
	}

	tier, tierRemoval := clampTier(req.MaxActionTier, allows)
	tools, toolRemovals := clampTools(req.Tools, allows)

	granted := GrantedScope{MaxActionTier: tier, Tools: tools}
	if tierRemoval != nil {
		granted.Removed = append(granted.Removed, *tierRemoval)
	}
	granted.Removed = append(granted.Removed, toolRemovals...)
	return granted, nil
}

// clampTier walks the requested tier down one step at a time until allows
// grants one. REASONING is never itself probed: models.ActionTier's zero
// value is deliberately the least-privileged member (see that type's doc
// comment), so it is the walk's unconditional floor — "permitted at
// nothing" still returns a usable result instead of depending on allows's
// cooperation for the one tier that must always be safe to grant.
//
// A probe error stops the walk immediately rather than trying the next
// tier down. An error means the question was unanswerable, and treating
// that as license to go ask an easier one substitutes optimism for the
// fail-closed rule this package exists to enforce (spec §3.8 G6) — it also
// keeps the removal reason unambiguous, one call and one outcome, rather
// than needing to pick which of several tiers' worth of errors and denials
// to report as THE reason the requested tier was not granted.
func clampTier(
	requested models.ActionTier,
	allows func(string, models.ActionTier) (bool, error),
) (models.ActionTier, *ClampRemoval) {
	for t := requested; t > models.ActionTierReasoning; t-- {
		ok, err := allows("", t)
		if err != nil {
			return models.ActionTierReasoning, &ClampRemoval{
				Dimension: "tier", Value: requested.String(),
				Reason: ClampReasonProbeError, Detail: err.Error(),
			}
		}
		if ok {
			if t == requested {
				return t, nil
			}
			return t, &ClampRemoval{Dimension: "tier", Value: requested.String(), Reason: ClampReasonDenied}
		}
	}
	if requested == models.ActionTierReasoning {
		return models.ActionTierReasoning, nil
	}
	return models.ActionTierReasoning, &ClampRemoval{Dimension: "tier", Value: requested.String(), Reason: ClampReasonDenied}
}

// clampTools probes each requested tool independently, calling allows with
// the zero-value tier (ActionTierReasoning) rather than the requested or
// granted tier. This mirrors GrantProbe.Tool's own "empty when probing the
// tier ceiling" convention: the tool and tier dimensions are orthogonal
// probes over the same held authority (spec G6's mechanism asks about each
// dimension of the request alone, not combinations of them). A tool
// surviving this probe is not a promise it may run at any particular tier —
// the tier ceiling is enforced independently, both by clampTier above and,
// at runtime, unconditionally by DelegationLeg regardless of which tool is
// named. See models.Agent.HasTool / models.Delegation.HasTool for the
// downstream consequence of an empty result here.
func clampTools(
	tools []string,
	allows func(string, models.ActionTier) (bool, error),
) ([]string, []ClampRemoval) {
	var granted []string
	var removed []ClampRemoval
	for _, tool := range tools {
		ok, err := allows(tool, models.ActionTierReasoning)
		switch {
		case err != nil:
			removed = append(removed, ClampRemoval{
				Dimension: "tool", Value: tool, Reason: ClampReasonProbeError, Detail: err.Error(),
			})
		case !ok:
			removed = append(removed, ClampRemoval{Dimension: "tool", Value: tool, Reason: ClampReasonDenied})
		default:
			granted = append(granted, tool)
		}
	}
	return granted, removed
}
