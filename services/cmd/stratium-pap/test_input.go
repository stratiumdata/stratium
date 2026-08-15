// test_input.go implements POST /v1/policies/test (spec §4.10.2), Task 5's
// second authoring endpoint: evaluate a candidate policy -- validated the
// same way validate.go's own endpoint does, via the shared validateCandidate
// -- against an operator-supplied sample input, and report the result
// without persisting anything. Three mechanics, named N9/N10/N11 in the spec,
// are what make this endpoint honest rather than merely functional, and each
// gets its own section below.
//
// N9 -- evaluate the candidate twice, alone and alongside the tenant's
// existing policies, and return both, labelled. Deny-overrides makes
// isolation misleading in exactly one direction: a candidate deny tested
// alone is accurate (a deny always wins the fold), while a candidate allow
// tested alone is not, since an existing forbid anywhere in the tenant makes
// it irrelevant. singlePolicySource and candidateAppendingSource (below) are
// two AllPolicySource implementations that make policy.Multi -- unmodified,
// reused exactly as pdpgrpc.Server.Decide uses it for a real decision --
// answer both questions without a second, parallel combining rule.
//
// N10 -- return principal-leg verdicts, and say so in the payload itself.
// Policies produce only that leg; the agent and delegation legs are
// structural and policy-independent (internal/authz.AgentLeg/DelegationLeg,
// neither called anywhere in this file). policyTestResponse.LegsEvaluated
// carries that fact on every response, as data rather than prose.
//
// N11 -- derive the tier by default (deriveOrDeclareTier, mirroring
// pdpgrpc.Server.Decide's own steps exactly, including §4.4.1's evidence
// rule), with an explicit override for hypotheticals, and label which one a
// given response used.
package main

import (
	"context"
	"fmt"
	"net/http"

	"stratium/internal/authz"
	"stratium/internal/policy"
	"stratium/pkg/models"
)

// tierSourceDerived and tierSourceDeclaredOverride label policyTestTier.Source
// (N11): a declared tier is a hypothesis an operator asked to explore, never
// a claim this endpoint verified against raw input the way the decision path
// does (spec defect D1, there; a labelled hypothesis, here) -- the labelling
// is what keeps the two apart, per this task's own brief.
const (
	tierSourceDerived          = "derived"
	tierSourceDeclaredOverride = "declared_override"
)

// testInputPrincipal, testInputAction, testInputAgent, and testInputDelegation
// are this endpoint's own wire shapes for authz.Principal/authz.Action/
// authz.AgentInfo/policy.DelegationContext -- not those types themselves,
// reused directly: none of the four carry JSON tags (internal/authz is not
// touched by this task, and internal/policy's own DelegationContext has no
// wire format of its own either), and adding any would mean editing a
// package this task's binding constraints keep untouched. Decoding into a
// local, tagged shape and converting is the same layering createPolicy
// already gives models.Policy for a real write; here there is no persisted
// counterpart to reuse, so the shape is new.
//
// testInputAction omits Verb and NormalizedInput on purpose: both are
// server-derived (spec §4.4.2 T2/T3 retired them from the wire everywhere
// else in this system), populated below by the identical authz.
// ExtractFromCatalog/ApplyExtraction calls production uses, never accepted
// as claims from a caller here either. It also omits DeclaredTier --
// authz.Action's OWN tier field, a decision-path concept (C1/C2/C3,
// cross-checked by authz.CheckDeclaredTier, part of the agent leg this
// endpoint never evaluates) distinct from policyTestRequest.DeclaredTier
// below, N11's override. Carrying both would invite the question "which one
// wins," so only the one this endpoint actually implements is exposed.
type testInputPrincipal struct {
	Subject    string            `json:"subject"`
	Attributes map[string]string `json:"attributes"`
}

type testInputAction struct {
	Tool     string `json:"tool"`
	RawInput string `json:"raw_input"`
}

type testInputAgent struct {
	TrustTier    models.AgentTrustTier `json:"trust_tier"`
	Enabled      bool                  `json:"enabled"`
	Suspended    bool                  `json:"suspended"`
	AllowedTools []string              `json:"allowed_tools"`
}

type testInputDelegation struct {
	Depth              int               `json:"depth"`
	MaxActionTier      models.ActionTier `json:"max_action_tier"`
	ClassificationCaps map[string]string `json:"classification_caps"`
	Purpose            string            `json:"purpose"`
}

// policyTestRequest is the candidate (validated the same way validate.go's
// own endpoint validates one) plus a full policy.EvaluationInput's worth of
// sample data -- every dimension a policy in any of the four languages might
// condition on (spec Y3: "deny Unverified agents on financial tools" needs
// the agent dimension visible even though this endpoint never runs the agent
// leg itself).
type policyTestRequest struct {
	Language string `json:"language"`
	Text     string `json:"policy_content"`

	Principal  testInputPrincipal  `json:"principal"`
	Action     testInputAction     `json:"action"`
	Resource   map[string]string   `json:"resource"`
	Agent      testInputAgent      `json:"agent"`
	Delegation testInputDelegation `json:"delegation"`

	// DeclaredTier is N11's explicit override for a hypothetical ("what
	// happens at DESTRUCTIVE" should not require crafting an input that
	// derives there). Omitted (nil) means "derive from Action.RawInput
	// through the tenant's own catalog" -- the default, and the only path
	// production itself has. A pointer, not a bare models.ActionTier: the
	// zero value (0) is ActionTierReasoning, a real tier, so a bare field
	// could never distinguish "test the derivation" from "override to
	// REASONING" the way ToolCatalogEntry.ActionTier's own doc comment
	// (pkg/models) already reasons for the identical shape.
	DeclaredTier *models.ActionTier `json:"declared_tier,omitempty"`
}

// legVerdict is one leg's outcome as this endpoint reports it: LegResult's
// own Effect/Reason, plus the deciding verdict's Source/PolicyID when one
// exists. "PolicyVerdict already carries Source and PolicyID, so attributing
// each verdict is free" is this task's own brief, quoted directly -- Source
// and PolicyID are omitted (via omitempty), never zero-valued placeholders,
// for the genuine default-deny-no-verdict case (authz.FoldVerdicts returns a
// nil *PolicyVerdict when an empty candidate set folds to deny with nothing
// to attribute it to -- see that function's own doc comment), matching
// authz.Result.Deciding's own documented reason for staying a pointer rather
// than a zero-value struct: "no policy spoke" and "a policy denied" are
// different facts an auditor needs told apart, and the same is true for an
// operator reading this response.
type legVerdict struct {
	Effect   string `json:"effect"`
	Reason   string `json:"reason"`
	Source   string `json:"source,omitempty"`
	PolicyID string `json:"policy_id,omitempty"`
}

// toLegVerdict converts FoldVerdicts' own two return values into the wire
// shape above -- the one and only place that conversion happens, called
// twice per request (isolated, folded) so both read identically.
func toLegVerdict(leg authz.LegResult, deciding *authz.PolicyVerdict) legVerdict {
	v := legVerdict{Effect: leg.Effect.String(), Reason: leg.Reason}
	if deciding != nil {
		v.Source = deciding.Source
		v.PolicyID = deciding.PolicyID
	}
	return v
}

// legsEvaluated states N10 structurally: which of the three authorization
// legs this endpoint actually ran. Principal is always true and Agent/
// Delegation are always false -- not a per-request outcome but a fact about
// what this endpoint IS -- carried on every response rather than left to a
// doc comment an operator will not read, per N10's own explicit requirement
// ("not in a doc comment, not in prose"). The required mutation "drop the
// not-evaluated marker from the response" targets exactly this type.
type legsEvaluated struct {
	Principal  bool `json:"principal"`
	Agent      bool `json:"agent"`
	Delegation bool `json:"delegation"`
}

// policyTestTier is N11's own label: the tier value plus which of the two
// paths (derive vs. declare) produced it. Value is models.ActionTier, the
// same bare-int wire shape every other exposed tier field in this API
// already uses (models.TierOverride.ActionTier, models.ToolCatalogEntry.
// ActionTier) -- consistency with the rest of this surface, not a new
// convention for one field.
type policyTestTier struct {
	Value  models.ActionTier `json:"value"`
	Source string            `json:"source"`
}

// policyTestResponse is deliberately not a pdpgrpc.DecideResponse-shaped
// type, and shares no Go type with one: this is the admin plane, unreachable
// by any agent, but a test result must not be mistakable for an
// authorization even in a log (this task's own binding constraint) -- a
// reviewer or a future caller cannot mistake this for a decision if there is
// no decision-shaped type available to mistake it for.
type policyTestResponse struct {
	Isolated             legVerdict `json:"isolated"`
	WithExistingPolicies legVerdict `json:"with_existing_policies"`

	Tier          policyTestTier `json:"tier"`
	LegsEvaluated legsEvaluated  `json:"legs_evaluated"`
}

// singlePolicySource is an AllPolicySource (internal/policy/multi.go) that
// reports exactly one policy -- the candidate -- regardless of what the
// tenant has actually stored. policy.Multi built over this source can only
// ever see the candidate, so its fold answers N9's first question ("did I
// write this rule correctly") with nothing else able to interfere.
type singlePolicySource struct {
	policy policy.StoredPolicy
}

func (s singlePolicySource) LoadAllPolicies(context.Context) ([]policy.StoredPolicy, error) {
	return []policy.StoredPolicy{s.policy}, nil
}

// candidateAppendingSource wraps a tenant's real AllPolicySource -- *store.
// Store satisfies the interface structurally, exactly as internal/policy/
// multi.go's own doc comment describes -- adding the candidate to whatever
// the tenant already has enabled. This is N9's second question ("will it
// change anything"), and it answers ADDS the candidate, never replaces:
// "alongside the tenant's existing policies" is the spec's own word choice,
// and a candidate that is actually a proposed edit to an existing policy
// will fold both the old, stored text and the new candidate text together
// (deny-overrides, so a stricter of the two generally wins) -- the correct
// reading of "alongside", not a gap needing a policy id to exclude.
//
// LoadAllPolicies builds a fresh slice rather than appending onto base's own
// result in place: the array base.LoadAllPolicies hands back is not this
// type's to mutate, the same immutability discipline multiSet.Evaluate
// applies to a sub-engine's own verdict slice (internal/policy/multi.go).
type candidateAppendingSource struct {
	base      policy.AllPolicySource
	candidate policy.StoredPolicy
}

func (c candidateAppendingSource) LoadAllPolicies(ctx context.Context) ([]policy.StoredPolicy, error) {
	existing, err := c.base.LoadAllPolicies(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]policy.StoredPolicy, len(existing)+1)
	copy(out, existing)
	out[len(existing)] = c.candidate
	return out, nil
}

// derivedTierResult bundles deriveOrDeclareTier's return values: Action and
// Resource travel together (both are ApplyExtraction's own output, a single
// step), and Tier/TierSource travel together (N11's value-plus-label pair).
type derivedTierResult struct {
	Action     authz.Action
	Resource   map[string]string
	Tier       models.ActionTier
	TierSource string
}

// deriveOrDeclareTier resolves N11's tier, mirroring pdpgrpc.Server.Decide's
// own steps EXACTLY -- LoadToolCatalog, ExtractFromCatalog, ApplyExtraction,
// then either DeriveTier or the operator's own override -- by calling every
// one of those exact exported internal/authz and internal/store functions
// rather than a second implementation of §4.4's resolution order (this
// task's own binding constraint: "internal/authz stays pure and is not
// touched", read together with "do not write a second combining rule" for
// FoldVerdicts -- the identical discipline applied to tier derivation).
//
// Tenant tier_overrides are loaded too, and honored through the identical
// authz.HonoredOverrides call pdpgrpc.Decide makes -- not a second copy of
// the raise-only filter, which is exactly how the two would drift apart. This
// comment previously said the opposite, and gave a good reason: at the time
// Decide left TierTable.Overrides unset, so loading them HERE and only here
// would have made this endpoint MORE accurate than a real decision. Phase 14
// Task 7 wired overrides into Decide, which turned that same reasoning around
// -- not loading them now makes this endpoint LESS accurate than production,
// and it would silently report a tier that ignores every override a real
// decision honors. A dry-run that answers a different question than the thing
// it is predicting is worse than no dry-run, and this endpoint's whole purpose
// (N11) is letting an operator see production's answer before committing.
//
// Dropped rows are discarded rather than reported: pdpgrpc.Decide logs them
// because a decision has no other channel, but this endpoint's response has no
// field for "your stored configuration contains a row that is being ignored,"
// and inventing one is a schema change no task has asked for. The tier
// reported is still exactly the tier production would derive, which is what
// N11 promises -- see this task's report for the residual.
//
// override is N11's escape hatch: when non-nil, DeriveTier is never called,
// so the evidence rule (which binds INSIDE DeriveTier -- tier.go's own doc
// comment) does not apply to a declared value. That is correct, not a hole:
// a declared value is not a derivation to protect, it is the operator's own
// stated hypothesis, and the response labels it as exactly that
// (tierSourceDeclaredOverride). Extraction still runs on the override path
// regardless, since it governs Resource/Verb/NormalizedInput -- a question
// independent of which tier is ultimately used.
func (s *Server) deriveOrDeclareTier(
	ctx context.Context, action authz.Action, resource map[string]string, override *models.ActionTier,
) (derivedTierResult, error) {
	catalogEntries, err := s.store.LoadToolCatalog(ctx)
	if err != nil {
		return derivedTierResult{}, fmt.Errorf("load tool catalog: %w", err)
	}

	extracted := authz.ExtractFromCatalog(catalogEntries, action)
	action, resource = authz.ApplyExtraction(extracted, action, resource)

	if override != nil {
		return derivedTierResult{Action: action, Resource: resource, Tier: *override, TierSource: tierSourceDeclaredOverride}, nil
	}

	storedOverrides, err := s.store.LoadTierOverrides(ctx)
	if err != nil {
		return derivedTierResult{}, fmt.Errorf("load tier overrides: %w", err)
	}

	tiers := authz.TierTable{Catalog: authz.BuildTierCatalog(catalogEntries, authz.DefaultCatalog())}
	tiers.Overrides, _ = authz.HonoredOverrides(
		authz.TierTable{Catalog: tiers.Catalog, Overrides: storedOverrides}, catalogEntries)
	tier, err := authz.DeriveTier(tiers, action)
	if err != nil {
		// Unreachable while this endpoint's TierTable leaves DenyUnknown at
		// its zero value false (matching production -- see this function's
		// own doc comment), exactly as it is on pdpgrpc.Server.Decide's
		// identical call: deriveTierByName never returns an error on that
		// branch. Handled anyway, the same defensive posture Multi.Evaluate
		// takes on multiSet.Evaluate's own always-nil error return -- a
		// function's signature is its contract, not today's specific config.
		return derivedTierResult{}, fmt.Errorf("derive tier: %w", err)
	}
	return derivedTierResult{Action: action, Resource: resource, Tier: tier, TierSource: tierSourceDerived}, nil
}

// testPolicyAgainstSampleInput handles POST /v1/policies/test. Every store
// call it makes -- LoadToolCatalog (deriveOrDeclareTier) and LoadAllPolicies
// (candidateAppendingSource, inside the "with existing policies" Multi) -- is
// a pre-existing, already read-only method; nothing here opens a write
// transaction, so, as with validatePolicy (validate.go), there is no write
// path for test_input_test.go's zero-write-expectation proof to have missed.
func testPolicyAgainstSampleInput(s *Server, w http.ResponseWriter, r *http.Request, _ Operator) {
	var req policyTestRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	candidate, err := s.validateCandidate(r.Context(), req.Language, req.Text)
	if err != nil {
		// Fail closed: an unparseable candidate has nothing to evaluate, so
		// the whole request refuses here rather than folding a Prepare
		// failure into a misleading deny verdict two steps later.
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if req.DeclaredTier != nil {
		if _, err := models.ParseActionTier(int(*req.DeclaredTier)); err != nil {
			// The same range check pdpgrpc/server.go applies to
			// DecideRequest's own declared_tier, reused here for the
			// identical reason: casting an untrusted int straight to
			// models.ActionTier would admit a value outside the lattice.
			http.Error(w, "declared_tier: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	action := authz.Action{Tool: req.Action.Tool, RawInput: req.Action.RawInput}
	derived, err := s.deriveOrDeclareTier(r.Context(), action, req.Resource, req.DeclaredTier)
	if err != nil {
		// An unreadable catalog is this endpoint's own infrastructure
		// failing, not anything wrong with the operator's request -- fail
		// closed with 500, never a silent fallback to DefaultCatalog() as
		// though the tenant had no rows (pdpgrpc/server.go's own
		// LoadToolCatalog failure handling draws the identical line).
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	evalInput := policy.EvaluationInput{
		Principal:   authz.Principal{Subject: req.Principal.Subject, Attributes: req.Principal.Attributes},
		Action:      derived.Action,
		DerivedTier: derived.Tier,
		Resource:    derived.Resource,
		Agent: authz.AgentInfo{
			TrustTier: req.Agent.TrustTier, Enabled: req.Agent.Enabled,
			Suspended: req.Agent.Suspended, AllowedTools: req.Agent.AllowedTools,
		},
		Delegation: policy.DelegationContext{
			Depth: req.Delegation.Depth, MaxActionTier: req.Delegation.MaxActionTier,
			ClassificationCaps: req.Delegation.ClassificationCaps, Purpose: req.Delegation.Purpose,
		},
	}

	// N9: evaluate twice. Two policy.Multi instances differing only in their
	// AllPolicySource -- the identical PrincipalPolicy production uses
	// (policy.Multi{} is what pdpgrpc.Server wires as s.policy), never a
	// bespoke evaluator for this endpoint.
	isolatedVerdicts := policy.NewMulti(singlePolicySource{candidate}, s.registry).Evaluate(r.Context(), evalInput)
	foldedVerdicts := policy.NewMulti(candidateAppendingSource{base: s.store, candidate: candidate}, s.registry).Evaluate(r.Context(), evalInput)

	// FoldVerdicts is the ONE combining rule (this task's own binding
	// constraint) -- called here, directly, exactly as authz.Decide's own
	// principal-leg step calls it (compound.go: "res.Principal, res.Deciding
	// = FoldVerdicts(req.PrincipalVerdicts)"), with nothing else layered on
	// before or after: no clamping, no agent/delegation combination -- N10's
	// "principal-leg verdicts" is precisely this call's own output and
	// nothing more.
	isolatedLeg, isolatedDeciding := authz.FoldVerdicts(isolatedVerdicts)
	foldedLeg, foldedDeciding := authz.FoldVerdicts(foldedVerdicts)

	writeJSON(w, http.StatusOK, policyTestResponse{
		Isolated:             toLegVerdict(isolatedLeg, isolatedDeciding),
		WithExistingPolicies: toLegVerdict(foldedLeg, foldedDeciding),
		Tier:                 policyTestTier{Value: derived.Tier, Source: derived.TierSource},
		LegsEvaluated:        legsEvaluated{Principal: true, Agent: false, Delegation: false},
	})
}
