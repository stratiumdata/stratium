// Package xacml implements policy.PolicyEngine using a small, fixed subset
// of XACML 3.0 — the fourth and final policy language of Phase 4. Full
// XACML 3.0 (obligations, advice, policy sets, policy or policy-set
// references, <Condition>, the full function/XPath library, every
// combining algorithm) is deliberately out of scope: XACML's complete
// grammar is enormous, and an engine that accepted the full grammar while
// implementing a fraction of it would invite exactly the failure this
// package exists to prevent — a document that parses, looks like a working
// policy, and is silently unable to produce the verdict its author
// intended. Validate rejects every construct outside the subset below **by
// name**, so an author learns the gap at authoring time, not by discovering
// years later that a rule never fired.
//
// # The supported subset
//
// One <Policy> per StoredPolicy row:
//
//	<Policy PolicyId="..." RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
//	  <Target> ... </Target>              <!-- optional, at most one -->
//	  <Rule RuleId="..." Effect="Permit"> <!-- one or more -->
//	    <Target> ... </Target>            <!-- optional, at most one -->
//	  </Rule>
//	</Policy>
//
// RuleCombiningAlgId must be exactly the deny-overrides URN above — see
// "rule combining" below for why no other algorithm is accepted, including
// ones that sound close (ordered-deny-overrides, deny-unless-permit,
// permit-overrides).
//
// Every element named above is bounded to *at most one* occurrence in the
// position shown — Policy's own Target, a Rule's own Target, and (further
// below) a Match's AttributeValue and AttributeDesignator. Rule itself,
// and AnyOf/AllOf/Match inside a Target, are the only things meant to
// repeat. This is enforced by validateStructure (structure.go), not left
// to xml.Unmarshal's own binding: every one of those four bounded fields
// binds to a non-slice Go value, which silently keeps only the last
// occurrence written for AttributeValue/AttributeDesignator — or, worse,
// for a duplicated Target specifically, evaluates as if the two were
// OR-ed together (see (*xmlTarget).evaluate), silently *widening* what a
// Policy or Rule applies to. A stray copy-pasted or template-emitted
// second Target is exactly the kind of accept-and-ignore this package
// exists to prevent, and unlike the missing-Rule or empty-AnyOf cases
// below, it fails open rather than closed if left unchecked.
//
// <Target> — at Policy level or Rule level, identical grammar and
// semantics either place — is a conjunction of <AnyOf> elements (XACML 3.0
// §5.5: "The <Target> element SHALL contain a conjunctive sequence of
// <AnyOf> elements"), each <AnyOf> itself a disjunction of <AllOf>
// conjunctions of attribute matches:
//
//	<Target>
//	  <AnyOf>               <!-- zero or more; Target itself may also be absent -->
//	    <AllOf>              <!-- one or more per AnyOf -->
//	      <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal"> <!-- one or more per AllOf -->
//	        <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">VALUE</AttributeValue>
//	        <AttributeDesignator AttributeId="..." DataType="http://www.w3.org/2001/XMLSchema#string" Category="..."/>
//	      </Match>
//	    </AllOf>
//	  </AnyOf>
//	</Target>
//
// A Target that is absent entirely, or present with zero <AnyOf> children,
// matches every request — XACML's own spec-defined behaviour for "no
// target," not this package's invention (see (*xmlTarget).evaluate). That
// is the one deliberately meaningful empty case in this grammar. An empty
// <AnyOf> (zero AllOf) or empty <AllOf> (zero Match) has no such
// spec-defined meaning — real XACML's own schema requires at least one
// child of each — and both are rejected by Validate rather than silently
// treated as always-true or always-false: the same "an empty collection
// that can never mean what its author intended" defect class jsonpolicy's
// empty `"in": []` guards against (see jsonpolicy's package doc).
//
// MatchId must be exactly the string-equal URN above: "string equality
// only" per the task brief, enforced by rejecting every other function
// identifier by name — including a near-miss like
// string-equal-ignore-case, which would silently change what a rule
// matches rather than failing to compile. DataType must be exactly
// xsd:string on both AttributeValue and AttributeDesignator, for the same
// reason: an unstated or different DataType is a place a silent type
// mismatch could hide.
//
// AttributeValue's text must carry no leading or trailing whitespace.
// xs:string preserves it verbatim, so a value written across lines — the
// ordinary way to format XML by hand, and the one authoring style absent
// from this package's own pre-review fixtures, which all wrote values
// inline — compares against the padded string, never the trimmed one an
// author almost certainly meant, and can never match anything.
//
// AttributeDesignator's Category must match the category implied by its
// own AttributeId: the access-subject category for subject-id/subject:*,
// the resource category for resource-id/resource:*, the action category
// for action-id, and the environment category — XACML's catch-all for
// contextual attributes belonging to none of the other three — for the
// four Stratium-specific designators (agent-trust-tier, derived-tier,
// delegation-purpose, delegation-max-tier). Category is real XACML schema
// machinery, required by any general-purpose authoring tool, so accepting
// it while never checking it would be exactly the "reads as configurable,
// isn't" trap this package exists to close.
//
// agent-trust-tier, derived-tier, and delegation-max-tier each have a
// closed value space of their own — see "Attribute designators" below —
// and AttributeValue's text must be one of the real enum spellings
// (CERTIFIED, DESTRUCTIVE, and so on), never a typo, a wrong case, or a
// bare ordinal digit.
//
// A <Policy> with zero <Rule> children is rejected: it can carry a Target,
// validate cleanly, and never produce a verdict for any request, ever — the
// same silently-dead-policy shape as a JSON policy missing its match block.
//
// No <Condition>, no functions beyond string-equal, no obligations, no
// advice, no policy sets, and no policy or policy-set references —
// Validate rejects each of these by name; see structure.go's structural
// whitelist, the single place in this package that decides which element
// and attribute names may appear anywhere in a document, and
// structure_test.go for one test per rejected construct.
//
// # Attribute designators — the engine's public surface
//
// An AttributeDesignator's AttributeId names one EvaluationInput dimension.
// This is the complete list; an AttributeId outside it fails Validate as
// unknown (see attributeIDKnown):
//
//	subject-id            Principal.Subject
//	subject:<key>         Principal.Attributes[<key>]       (open, tenant-supplied)
//	resource-id           Resource["id"]
//	resource:<key>        Resource[<key>]                    (open, tenant-supplied)
//	action-id             Action.Tool
//	agent-trust-tier      Agent.TrustTier.String()                  (closed vocabulary — see below)
//	delegation-purpose    Delegation.Purpose
//	delegation-max-tier   Delegation.MaxActionTier.String()         (closed vocabulary — see below)
//	derived-tier          DerivedTier.String()                     (closed vocabulary — see below)
//
// These are the same dimensions cedar/request.go and rego/input.go expose
// (trust_tier, max_action_tier, purpose, derived_tier), spelled with
// XACML's own hyphenated AttributeId convention instead of Cedar's flat
// context-record fields or Rego's dotted input paths — a naming
// difference, not a scope difference for three of the four: trust_tier,
// max_action_tier, and purpose line up exactly. derived-tier is also a
// *value-encoding* difference, not only a naming one: Cedar
// (request.go:49) and Rego expose the tier as its ordinal int, this
// engine's Match compares against DerivedTier.String() (a name like
// "DESTRUCTIVE") because XACML's own AttributeValue is text, not a typed
// integer literal — a rule ported from `context.derived_tier == 3` reads
// as `<AttributeValue>3</AttributeValue>` here and will validate (subject
// to the closed vocabulary below rejecting it, since "3" is not a real
// ActionTier spelling) rather than silently keep working. subject:<key>
// and resource:<key> are
// this package's own convention (the brief specifies which dimensions to
// expose, not an XML syntax for the open-ended ones): a Match's
// AttributeDesignator carries exactly one AttributeId with no path
// expression, the same constraint jsonpolicy's single attr field faces, so
// an open, colon-prefixed name is how "any principal attribute" /"any
// resource attribute" (the brief's own words) becomes expressible at all.
//
// Two deliberate narrowings versus Cedar's and Rego's full context, both
// for the reason jsonpolicy's own agentAttrValue/delegationAttrValue give:
//
//   - Only agent-trust-tier and delegation-purpose/-max-tier are wired up.
//     Agent.Enabled, Agent.Suspended, Agent.AllowedTools, Agent.ID,
//     Delegation.Depth, and Delegation.ClassificationCaps are not exposed.
//     Extend resolveAttr and attributeIDKnown together (schema.go) when a
//     concrete rule needs one of them, rather than guessing now.
//   - EvaluationInput.Environment is not mapped, for the same reason Cedar
//     and Rego leave it unmapped: no rule in scope needs it.
//
// Every AttributeDesignator also carries a Category, checked against
// categoryFor(AttributeId) (schema.go) — the access-subject category for
// subject-id/subject:*, the resource category for resource-id/resource:*,
// the action category for action-id, and the environment category (XACML's
// own catch-all for contextual attributes belonging to none of the other
// three) for the four Stratium-specific designators, none of which
// describe the subject, the resource, or the action itself.
//
// # Indeterminate: an unresolvable designator denies
//
// subject:<key> and resource:<key> (including resource-id, which is
// resource:id under a fixed name) read Go maps that may not carry the
// requested key — EvaluationInput.Principal.Attributes and .Resource are
// tenant-supplied free-form data (see EvaluationInput's own doc comment),
// so a key's absence is real information, not a zero value. Every other
// designator listed above reads a fixed Go struct field, which always
// holds some value — Go gives a struct field no "absent" state distinct
// from its zero value — so only those two open dimensions can ever fail to
// resolve.
//
// XACML calls this outcome Indeterminate and leaves how a combining
// algorithm treats it unspecified. This package does not leave it open:
// every Indeterminate is a deny, always — the only reading consistent with
// a fail-closed PDP, and the task brief's own explicit instruction. An
// Indeterminate Match makes its enclosing AllOf, AnyOf, and Target
// Indeterminate too (see (*xmlMatch).evaluate and its callers) — this
// package does not implement XACML's full three-valued short-circuiting,
// under which a definite false found elsewhere in the same Target can
// "rescue" an indeterminate sibling back to a clean non-match. Skipping
// that machinery can only make this engine deny in a few cases the full
// XACML Indeterminate{D,P,DP} algebra would have called a non-match —
// strictly more conservative, never less, which is the direction this
// system's fail-closed posture already requires, and considerably simpler
// to implement and verify than reproducing the full algebra for a
// deliberately small subset. compiledPolicy.evaluate (evaluate.go) is
// where an Indeterminate target — the Policy's own, or any Rule's — turns
// into an actual deny verdict; see its own doc comment.
//
// # Rule combining: deny-overrides, and only within one policy
//
// A Policy's own Rules combine with deny-overrides — the one combining
// decision this package implements, because it is internal to a single
// <Policy>, never across policies (see policy.PolicyEngine's own doc
// comment and authz.FoldVerdicts, which owns cross-policy combining
// exclusively — this package must not duplicate any of that logic).
// Evaluate returns at most one verdict per StoredPolicy: a Deny wins over
// any Permit, an Indeterminate anywhere in the Rule list counts as a Deny
// for this purpose (see above), and a Policy whose Target or Rules never
// match at all contributes no verdict — never a manufactured deny — the
// same "no match is silence, not a verdict" contract Cedar, Rego, and JSON
// hold.
//
// # Compile once, evaluate many
//
// Prepare parses, whitelists, and semantically validates every
// StoredPolicy's text exactly once, through parseAndValidate — the sole
// entry point into this package's XML handling. Evaluate walks the
// resulting compiledPolicy values only; it does not touch encoding/xml at
// all. TestXMLParsingOnlyCalledFromPrepareOrValidate (engine_test.go)
// guards this structurally, the same approach jsonpolicy and rego use for
// their own D5 guards — including treating parseAndValidate and its own
// validateStructure helper as parse-shaped in their own right, not only
// the literal xml.Unmarshal/Token calls inside them, which is precisely
// the gap an earlier version of jsonpolicy's own guard had (see that
// test's doc comment).
//
// # The narrowing invariant
//
// Same as every other engine in this package tree: a policy verdict can
// never widen anything. authz.PolicyVerdict carries only Effect, Reason,
// Source, PolicyID, and Priority — no field through which a verdict could
// raise a tier, add a tool, or loosen a cap — and Priority is recorded for
// provenance only (spec Y7): nothing in this package sorts, filters, or
// short-circuits evaluation by it. Evaluate returns every policy that
// matched, independently; authz.FoldVerdicts, not this package, applies
// deny-overrides across the result.
package xacml

import (
	"context"
	"encoding/xml"
	"fmt"

	"stratium/internal/policy"
)

const (
	// language is the value stored in policies.language for this engine —
	// and, via NewMulti's own construction-time panic, the only Registry key
	// this Engine may ever be registered under (see policy.Registry's doc
	// comment).
	language = "xacml"

	// ruleCombiningAlgDenyOverrides is the only RuleCombiningAlgId this
	// engine accepts. Permit-overrides is rejected by name, not merely by
	// omission, because it is the specific danger the brief calls out: it
	// would let one rule's permit mask another's deny within the same
	// policy, contradicting the system's own cross-policy fold
	// (authz.FoldVerdicts) and reopening exactly the local-combining hole
	// this design removed everywhere else.
	ruleCombiningAlgDenyOverrides = "urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides"

	// matchIDStringEqual is the only MatchId this engine accepts — "string
	// equality only" per the brief. A near-miss such as
	// string-equal-ignore-case is a different function with different
	// results, not a stylistic variant, so it is rejected the same as any
	// other unsupported function identifier, never treated as close enough.
	matchIDStringEqual = "urn:oasis:names:tc:xacml:1.0:function:string-equal"

	// dataTypeString is the only DataType this engine accepts, on both
	// AttributeValue and AttributeDesignator. Requiring it explicitly
	// (rather than assuming string) keeps this engine's one supported
	// comparison — string equality — the only comparison a validated
	// document can ever express.
	dataTypeString = "http://www.w3.org/2001/XMLSchema#string"

	effectPermit = "Permit"
	effectDeny   = "Deny"
)

// Engine implements policy.PolicyEngine for XACML. It holds no state: every
// compiledPolicy a Prepare call produces is everything a decision needs,
// and those live in the returned compiledSet.
type Engine struct{}

var _ policy.PolicyEngine = Engine{}

// New returns an XACML policy.PolicyEngine.
func New() Engine { return Engine{} }

// Language is the value stored in policies.language for XACML policies.
func (Engine) Language() string { return language }

// Prepare parses, whitelists, and validates every policy's text exactly
// once via parseAndValidate, keyed by StoredPolicy.ID so a validation
// failure — and later, every verdict Evaluate returns — can be attributed
// back to the specific policy that produced it. A nil or empty policies
// prepares successfully to a set that evaluates to zero verdicts.
// Preparation stops at the first policy that fails: the error names only
// that policy, never a well-formed neighbor that happened to share the
// same Prepare call (see policytest's own "does not blame the neighbor"
// property).
func (Engine) Prepare(_ context.Context, policies []policy.StoredPolicy) (policy.CompiledPolicySet, error) {
	compiled := make([]compiledPolicy, 0, len(policies))
	for _, sp := range policies {
		doc, err := parseAndValidate(sp.Text)
		if err != nil {
			return nil, fmt.Errorf("xacml: prepare policy %s (%q): %w", sp.ID, sp.Name, err)
		}
		compiled = append(compiled, newCompiledPolicy(sp, doc))
	}
	return compiledSet{policies: compiled}, nil
}

// Validate checks policy text without persisting or evaluating it, for the
// PAP's authoring path: a bad policy — including one that would silently
// never fire, such as an unsupported construct or an unknown attribute
// designator — is refused at write time rather than discovered at decision
// time. It parses text through the same parseAndValidate Prepare uses, so
// anything Validate accepts, Prepare accepts too.
func (Engine) Validate(_ context.Context, text string) error {
	if _, err := parseAndValidate(text); err != nil {
		return fmt.Errorf("xacml: validate: %w", err)
	}
	return nil
}

// parseAndValidate is the single choke point every policy text passes
// through, called from both Prepare and Validate — the same shape
// jsonpolicy's parseDoc and rego's checkPackage take, and for the same
// reason: anything Validate accepts must also prepare, and there must be
// exactly one place that requirement could drift out of sync with itself.
//
// It runs in three steps, each independently testable: validateStructure
// (structure.go) walks the raw token stream and rejects any element or
// attribute name outside this package's supported grammar, by name, before
// anything is unmarshaled into a Go value — this is what stands in for
// encoding/json's DisallowUnknownFields, which encoding/xml has no
// equivalent of; xml.Unmarshal only extracts values from a document
// validateStructure has already confirmed uses no unsupported construct;
// and (*xmlPolicy).validate (schema.go) checks the semantic constraints a
// bare element/attribute whitelist cannot express — RuleCombiningAlgId is
// exactly deny-overrides, MatchId is exactly string-equal, at least one
// Rule is present, every AttributeId is one this engine knows.
func parseAndValidate(text string) (xmlPolicy, error) {
	if err := validateStructure(text); err != nil {
		return xmlPolicy{}, fmt.Errorf("structure: %w", err)
	}

	var doc xmlPolicy
	if err := xml.Unmarshal([]byte(text), &doc); err != nil {
		return xmlPolicy{}, fmt.Errorf("parse: %w", err)
	}

	if err := doc.validate(); err != nil {
		return xmlPolicy{}, fmt.Errorf("validate: %w", err)
	}
	return doc, nil
}
