package cedar

import (
	"encoding/json"
	"fmt"
	"slices"

	cedarlib "github.com/cedar-policy/cedar-go"

	"stratium/pkg/models"
)

// This file is Cedar's contribution to contract property 8 (see
// policytest/contract.go's DeadForm doc comment): every policy engine must
// refuse, at authoring time, a policy that is syntactically well-formed but
// can never produce its author's intended verdict. Rego (checkPackage),
// jsonpolicy, and xacml (schema.go) each already do this for their own
// language; Cedar predates the contract and had never been audited for the
// class until this task.
//
// # Why targeted checks, not schema validation
//
// cedar-go v1.8.0 does ship real schema support — x/exp/schema (parsing,
// resolution) and x/exp/schema/validate (a Validator that typechecks policy
// scope and conditions against a resolved schema, catching unknown entity
// types, undeclared record attributes, and operand type mismatches all at
// once). It was evaluated first, and rejected for two independent reasons,
// either of which alone would be enough:
//
//  1. Every package under x/exp carries this module's own explicit
//     disclaimer (see its README's "Backward Compatibility Considerations"):
//     "code in this directory is not subject to the semantic versioning
//     constraints of the rest of the module and breaking changes may be
//     made at any time." Building a permanent authoring-time gate — the
//     thing standing between a tenant and a silently-dead policy — on code
//     the library itself declines to make any stability promise about is a
//     worse bet than a hand-written check this package fully owns.
//  2. More fundamentally, Cedar's schema records are closed by construction
//     (x/exp/schema/validate's checkRecord rejects any attribute not
//     declared in the schema — "unexpected attribute" — by design, matching
//     Cedar's real validator). This engine's request shape has THREE
//     genuinely open, tenant-supplied maps reachable from policy text:
//     Principal's entity attributes, Resource's entity attributes, and
//     context.delegation.classification_caps — every one of them
//     deliberately unenumerable (see request.go's buildRequest and
//     xacml/schema.go's own identical note that "Principal.Attributes and
//     Resource are tenant-supplied free-form maps with no fixed field set
//     to enumerate"). A Cedar schema cannot express "this record's shape is
//     open" — there is no wildcard/"additional attributes allowed" record
//     type in the language — so validating against one would force a
//     choice between two bad options: declare a closed, guessed-at set of
//     keys (silently breaking every tenant policy that references a resource
//     or principal attribute this package's author didn't happen to
//     anticipate — exactly the over-rejection risk this task was warned
//     against), or leave those three maps so permissive the validator
//     catches nothing there at all, at which point most of its value is
//     gone anyway.
//
// Even where schema validation WOULD have applied cleanly (the closed
// parts: context's own top-level shape, the agent record), it still could
// not have caught the two most consequential dead forms named in the task
// brief — a wrong-case enum ("Certified") and a bare ordinal ported from
// Rego ("2") — because both are ordinary, well-typed String-to-String
// comparisons. Cedar's type system checks that the *shapes* line up, not
// that a String literal is one of a *specific set* of strings; that is a
// value-level constraint no schema-driven type checker (Cedar's or anyone
// else's) expresses. Those two, plus the third value-vocabulary case
// (padded whitespace), needed a hand-written closed-vocabulary check no
// matter which route was taken — see checkTierVocabulary below, built the
// same way xacml/schema.go's own agentTrustTierValues/actionTierValues are:
// from models' own String() methods, never a second copy of the spelling.
//
// # Why cedar-go's stable JSON policy format, not x/exp/ast
//
// Having ruled out x/exp/schema, walking a parsed policy's structure at all
// requires *some* representation of it — and cedar-go v1.8.0 has no stable,
// exported way to inspect an already-parsed policy's scope and condition
// expressions except by round-tripping through
// (*cedarlib.Policy).MarshalJSON. Its return type is Cedar's own spec'd
// JSON policy format (https://docs.cedarpolicy.com/policies/json-format.html),
// which every Cedar implementation (this one, the Rust reference engine,
// Java) reads and writes for interop — a stable, cross-SDK wire contract,
// not an internal Go type. The alternative, (*cedarlib.Policy).AST(),
// returns a type from the *stable* top-level ast package, but that
// package's own Node type is defined by embedding x/exp/ast.Node (see
// cedar-go's ast/node.go), so any code that actually reads a returned
// scope or condition — as opposed to only building new policies with the
// package's fluent constructors — ends up depending on x/exp/ast's field
// layout regardless of which door it walked through. That reintroduces
// exactly the "no semver guarantee" exposure the schema-validator decision
// above already ruled out, for the same reason. deadform_json.go's structs
// are this package's own, minimal, and stay correct as long as cedar-go
// keeps emitting the format its README calls "the JSON format" (i.e.
// forever) rather than as long as one experimental Go package's internal
// struct layout is unchanged.
//
// # Why only through "&&", for either clause kind
//
// checkDeadForms walks every "when" AND every "unless" clause body the same
// way: looking for a handful of specific dead shapes, but only within
// conjuncts reached by unwrapping "&&" nodes (conjuncts, deadform_json.go),
// never "||" or "!". That restriction is required, not merely conservative
// — and, importantly, it does not depend on which clause kind is being
// walked. The && / || split is a fact about how those two operators compose
// truth values; nothing about it changes depending on what the enclosing
// clause does with the result:
//
//   - Every "&&" conjunct is independently necessary for its clause body to
//     hold, so a dead (always-false) conjunct forces the *whole* body false
//     regardless of what the other conjuncts say — the same reason one
//     false term in a chain of ANDs forces the chain false no matter how
//     many true terms sit beside it.
//   - "||" does not have that property: `a || (1 == 2)` is exactly as true
//     as `a` alone, for every value of `a`. Recursing into an "||" and
//     flagging its dead arm would reject a clause body that is still,
//     genuinely, sometimes true — over-rejection this task's fail-closed
//     constraint forbids. "!" is opaque for a related reason: this file has
//     no general-purpose boolean prover, only a handful of "is this one
//     leaf always false" checks, and the negation of an always-false leaf
//     is an always-*true* one — a different question none of those checks
//     answer.
//
// What an always-false clause BODY means for the enclosing POLICY, though,
// does depend on which clause kind wraps it — this is the one place clause
// polarity matters, and it is why both kinds must be checked rather than
// one of them being "the safe one to leave alone":
//
//   - "when { X }" requires X to hold. An always-false X (via a dead
//     conjunct) means the clause can never hold, so the policy built around
//     it can never match at all — dead in the most literal sense.
//   - "unless { Y }" requires !Y to hold. An always-false Y (via a dead
//     conjunct — the identical structural fact, just fed to a clause with
//     the opposite polarity) makes !Y always TRUE: the clause is
//     unconditionally satisfied, imposing no restriction whatsoever. On a
//     permit policy this silently deletes the exception its author wrote —
//     every request the exception existed to carve out now matches anyway.
//     An earlier version of this file reasoned that made "unless" bodies
//     safe to skip ("a no-op, not a reason the enclosing policy can never
//     match") — true about *whether the policy can match*, and beside the
//     point: DeadForm's own contract is "semantically incapable of ever
//     producing its author's INTENDED verdict" (see policytest/contract.go),
//     not narrowly "can never match at all," and a policy that now matches
//     UNCONDITIONALLY when its author wrote a conditional one already fails
//     that test. Verified against the real engine (see the task report): a
//     policy reading "permit everyone except CERTIFIED agents", spelled
//     `unless { trust_tier == "Certified" }` (wrong case — one of this
//     file's own audited dead forms), authorizes a CERTIFIED agent instead
//     of denying one — a fail-open widening, not a no-op.
//
// checkTierVocabulary, checkContextFieldKind, checkDerivedTierComparison,
// checkLiteralContradiction, and checkEmptySetMembership did not need to
// change for any of this, and that is exactly why reusing them unmodified
// for "unless" bodies is safe rather than merely convenient: every one of
// them already only ever proves a leaf is a CONTRADICTION (always false,
// for any request whatsoever), never rejects a value it finds merely
// suspicious for some other reason — see checkLiteralContradiction's own
// "a tautology... is left alone" note. An always-false leaf is exactly the
// fact the "&&" argument above needs, and it is a fact about the leaf, not
// about whether a "when" or an "unless" happens to contain it.
//
// # What stayed silent on purpose
//
// Four of the thirteen forms audited for this task (see the task report's
// full classification table) already produce a loud, named deny at
// *evaluation* time as of commit d84009d, which made Evaluate turn a
// cedar.Diagnostic evaluation error into a deny verdict instead of
// discarding it like a non-match: a typo'd context key, a typo'd nested
// record name, a String compared to context.derived_tier via an ordering
// operator, and a reference to a resource attribute the request doesn't
// carry. None of the four gained a *new* authoring-time check here, for two
// different reasons:
//
//   - The resource-attribute case cannot be checked statically at all
//     without the same over-rejection risk schema validation was rejected
//     for above: Resource is a tenant-open map with no fixed key set this
//     package could enumerate (see request.go's buildRequest), so there is
//     no way to tell "resource.nonexistent" apart from a real, merely
//     unfamiliar-to-this-package, tenant attribute name.
//   - The two context-typo cases (context.agent.trust_teir,
//     context.delegaton.purpose) could in principle be caught by walking
//     every context.X / context.X.Y dot-path and checking it against a
//     closed registry — context's own shape, unlike Resource's, is fully
//     fixed. But that exact shape of check would also flag
//     TestEvaluate_EvaluationFailureDeniesAndNamesThePolicy's own
//     `context.nope` fixture, whose entire purpose is proving the
//     evaluation-time attribute-error path still works; that test needs
//     Prepare to succeed so Evaluate's error path is what runs. Adding an
//     authoring-time rejection for the same shape would break it, for a
//     case already fail-closed one layer down. See
//     checkDerivedTierComparison's doc comment for the equivalent collision
//     worked through for the fourth (String-vs-Long) case, which is why
//     that check is scoped to == and != only rather than all six
//     comparison operators.

// checkDeadForms rejects parsed if it matches any of this file's known dead
// shapes. Called from both Prepare and Validate, immediately after parseOne
// succeeds — same placement as rego's checkPackage, for the same reason:
// an author is told at authoring time, not left to discover a permanently
// dead rule on its first (and every) real request.
func checkDeadForms(parsed *cedarlib.Policy) error {
	body, err := parsed.MarshalJSON()
	if err != nil {
		// parsed just came from this package's own parseOne, which means
		// cedar-go's own parser and its own JSON marshaler disagree about a
		// policy cedar-go itself just produced — a cedar-go bug this
		// checker has no meaningful way to recover from.
		return fmt.Errorf("marshal parsed policy for dead-form checks: %w", err)
	}
	var doc policyJSON
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("decode parsed policy for dead-form checks: %w", err)
	}

	if err := checkScopeEntityType("principal", doc.Principal, string(entityTypeUser)); err != nil {
		return err
	}
	if err := checkScopeEntityType("action", doc.Action, string(entityTypeAction)); err != nil {
		return err
	}
	if err := checkScopeEntityType("resource", doc.Resource, string(entityTypeResource)); err != nil {
		return err
	}

	// Both "when" and "unless" clause bodies are decomposed into && conjuncts
	// and fed through the identical leaf checks — see this file's package
	// doc, "Why only through &&, for either clause kind," for why that is
	// correct for both clause kinds despite their opposite polarity.
	var leaves []json.RawMessage
	for _, c := range doc.Conditions {
		leaves = append(leaves, conjuncts(c.Body)...)
	}
	for _, expr := range leaves {
		if err := checkTierVocabulary(expr); err != nil {
			return err
		}
		if err := checkContextFieldKind(expr); err != nil {
			return err
		}
		if err := checkDerivedTierComparison(expr); err != nil {
			return err
		}
		if err := checkLiteralContradiction(expr); err != nil {
			return err
		}
		if err := checkEmptySetMembership(expr); err != nil {
			return err
		}
	}
	return nil
}

// checkScopeEntityType rejects a principal, action, or resource scope clause
// naming an entity type buildRequest (request.go) could never produce in
// that slot. buildRequest assigns User/Action/Resource to the
// principal/action/resource slots unconditionally, from EvaluationInput
// alone, never from anything a policy says — so a single test, "is gotType
// exactly the one type this slot is ever constructed as," is both necessary
// and sufficient on its own: it rejects a type this engine has never heard
// of at all ("unknown entity type": Usr, or Widget for action) exactly the
// same way it rejects a real Cedar type used in the wrong slot ("wrong
// principal type": Resource is a real type, just never the *principal*'s;
// "wrong action type": User is real, just never the *action*'s), because
// neither is ever equal to wantType. An earlier version of this check split
// those into two separate conditions — "is gotType known at all" and "does
// gotType match this slot" — reasoning they were different defects;
// mutation testing this file (see the task report) proved the first was
// redundant in practice: wantType is always itself a known type, so
// anything that fails the first condition necessarily fails the second too,
// and no fixture existed (or could exist) that isolated the first from the
// second. Kept simple rather than restored, per this task's own
// instruction: over-rejection is the risk to guard against here, not
// under-documentation of a distinction with no behavioural difference.
//
// checkDeadForms calls this once per scope slot — principal, action,
// resource — the same check, just aimed at a different slot and wantType
// each time; there being three call sites rather than two used to be a gap
// in coverage (action's own scope clause went unchecked entirely), not a
// reason this function needed a fourth parameter or a different shape.
//
// Scoped to the "==" and "is" scope operators only, the two shapes that
// pin a slot to a single named type. "in" and "is ... in" describe group
// membership against an entity hierarchy this engine does not model at all
// today — see engine.go's package doc, "agent and delegation become context
// attributes, not entities" — so they are left alone here; extend this
// check if that changes. Action's own grammar does not even accept "is"
// (confirmed empirically: `action is Widget` fails to parse), so the "is"
// branch below is only ever live for principal and resource — harmless to
// leave shared rather than split, since a slot whose JSON never uses "is"
// is exactly what the sc.EntityType == "" guard already handles.
func checkScopeEntityType(slot string, sc scopeJSON, wantType string) error {
	var gotType string
	switch sc.Op {
	case "==":
		if sc.Entity == nil {
			return nil
		}
		gotType = sc.Entity.Type
	case "is":
		if sc.EntityType == "" {
			return nil
		}
		gotType = sc.EntityType
	default:
		return nil
	}

	if gotType == wantType {
		return nil
	}
	return fmt.Errorf("%s scope names entity type %q, but buildRequest always constructs the %s entity as type %s — this can never match a real request",
		slot, gotType, slot, wantType)
}

// agentTrustTierValues and actionTierNameValues are this package's own
// closed vocabularies, independently derived from models' own String()
// methods — the same way xacml/schema.go's identically-named vars are (see
// that file's doc comment for the review finding this pattern fixes). Built
// here, not imported from xacml (whose copies are unexported) and not
// hand-copied as bare string literals either: both packages build the same
// set from models the same way, so a tier models ever adds or renames is
// picked up automatically instead of either vocabulary silently going
// stale relative to the type that actually owns the spelling.
var (
	agentTrustTierValues = []string{
		models.TrustTierUnverified.String(), models.TrustTierRegistered.String(),
		models.TrustTierCertified.String(), models.TrustTierPlatformTrusted.String(),
	}
	actionTierNameValues = []string{
		models.ActionTierReasoning.String(), models.ActionTierReadOnly.String(),
		models.ActionTierInternalModify.String(), models.ActionTierExternalComms.String(),
		models.ActionTierDestructive.String(),
	}
)

// knownTierVocabulary maps the two String-typed, closed-vocabulary context
// paths (see request.go's buildRequest) to the set of spellings each may
// legally be compared against. context.agent.trust_tier and
// context.delegation.max_action_tier are the only two: derived_tier is a
// Long (see checkDerivedTierComparison), and every other context path
// (purpose, depth, id, enabled, suspended, allowed_tools,
// classification_caps and its open keys) is either free text or has no
// closed spelling of its own to violate.
var knownTierVocabulary = map[string][]string{
	"context.agent.trust_tier":           agentTrustTierValues,
	"context.delegation.max_action_tier": actionTierNameValues,
}

// checkTierVocabulary rejects an == or != comparison between one of
// knownTierVocabulary's paths and a STRING literal that is not a real
// member of that tier's own String() spellings. One membership check is
// what catches three of the thirteen audited forms alike — a wrong-case
// spelling ("Certified"), a bare ordinal ported from a Rego rule ("2"), and
// a padded literal (" CERTIFIED ") — because all three are simply absent
// from the set, for the same underlying reason: each reads as if it
// configures the comparison and does not.
//
// This is a value-level check and deliberately only half of what these two
// paths need: a non-string literal (5, true) is a KIND mismatch, not a
// vocabulary miss, and is checkContextFieldKind's job below, not this
// one's — contextFieldKind lists both paths as "string" for exactly that
// reason. An earlier version of this function assumed a non-string literal
// here was "already a loud evaluation-time error" and left it uncaught
// entirely; confirmed empirically (see the task report) that assumption was
// wrong — context.agent.trust_tier == 5 validates, prepares, and evaluates
// to zero verdicts, the identical silent-dead shape as every field
// contextFieldKind now covers. Splitting the value check (here) from the
// kind check (checkContextFieldKind) rather than folding a kind branch into
// this function keeps each check's own mutation coverage attributable to
// one specific rejection, the same reasoning checkDerivedTierComparison's
// own doc comment gives for why ITS kind and range checks are scoped the
// way they are.
func checkTierVocabulary(expr json.RawMessage) error {
	_, b, ok := asOperator(expr, "==", "!=")
	if !ok {
		return nil
	}
	path, lit, ok := pathAndLiteral(b.Left, b.Right)
	if !ok {
		return nil
	}
	vocab, known := knownTierVocabulary[path]
	if !known {
		return nil
	}
	s, isString := lit.(string)
	if !isString {
		// Not this check's concern — see the doc comment above:
		// checkContextFieldKind rejects a non-string literal here instead.
		return nil
	}
	if slices.Contains(vocab, s) {
		return nil
	}
	return fmt.Errorf("condition compares %s to %q, which is not a real tier spelling — must be exactly one of %v (case-sensitive, no surrounding whitespace); this can never match any value buildRequest actually produces",
		path, s, vocab)
}

// contextFieldKind maps every closed-kind context path this package can
// classify — other than context.derived_tier, owned by
// checkDerivedTierComparison's own range check below, which already
// subsumes a kind check for that one path (its own non-numeric-literal
// branch covers every non-Long kind, not only the ones knownTierVocabulary
// leaves this map to cover) — to its fixed Cedar kind: "string", "boolean",
// "long", or "set".
//
// context.agent.trust_tier and context.delegation.max_action_tier are
// listed here as "string" even though knownTierVocabulary (above) already
// checks them: that is a deliberate, non-overlapping split, not redundancy.
// knownTierVocabulary is a VALUE check (is this string literal a real tier
// spelling) that only ever runs once the literal is confirmed to be a
// string; this map is a KIND check (is the literal even the right Cedar
// type at all) that only ever fires when it is NOT a string. An earlier
// version of this file assumed a non-string literal against these two
// paths was "already a loud evaluation-time error" and left it unchecked
// entirely — confirmed empirically wrong (see checkTierVocabulary's own
// doc comment and the task report): context.agent.trust_tier == 5 is the
// identical silent-dead shape as context.agent.suspended == "true", just on
// a path this file had, until now, incorrectly assumed needed no kind
// check of its own.
//
// agent.id and delegation.purpose are the only other String context paths
// (see request.go's buildRequest) and are deliberately NOT listed: both are
// open free text with no closed vocabulary, but that is not why they are
// absent — trust_tier and max_action_tier are equally absent from any
// *vocabulary* concern here, since this map does not check values. They
// are left out because no audited dead form needs them, and each new entry
// here needs its own mutation-tested DeadForms fixture (see the task
// report) to earn its place rather than being added speculatively; add one
// there first if a real dead form ever needs it.
var contextFieldKind = map[string]string{
	"context.agent.trust_tier":           "string",
	"context.delegation.max_action_tier": "string",
	"context.agent.suspended":            "boolean",
	"context.agent.enabled":              "boolean",
	"context.delegation.depth":           "long",
	"context.agent.allowed_tools":        "set",
}

// literalKind reports the Cedar kind — "string", "long", or "boolean" — of
// v, a literalValue result. The same three Go kinds scalarLiteral itself
// recognizes as safe to compare (string, float64, bool); anything else (a
// decoded map or slice — an entity-UID or Set literal) is reported not ok
// rather than guessed at, the same caution scalarLiteral's own doc comment
// explains. A Set literal specifically never reaches here at all: Cedar's
// JSON format represents one as {"Set": [...]}, a shape literalValue does
// not recognize (it only decodes {"Value": ...} nodes) — see pathAndLiteral
// and isEmptySet, which read that shape directly rather than through
// literalValue.
func literalKind(v any) (kind string, ok bool) {
	switch v.(type) {
	case string:
		return "string", true
	case float64:
		return "long", true
	case bool:
		return "boolean", true
	default:
		return "", false
	}
}

// checkContextFieldKind rejects an == or != comparison between one of
// contextFieldKind's paths and a literal whose own Cedar kind provably
// disagrees with that field's fixed kind — e.g. context.agent.suspended
// (always a Boolean, see request.go's buildRequest) compared to a String
// literal ("true"), or context.agent.trust_tier (always a String) compared
// to a Long literal (5). Unlike checkTierVocabulary, this is a type-level
// check, not a value-level one: it needs no closed vocabulary of legal
// values, only the field's fixed Cedar kind, because a Boolean, Long, Set,
// or String is simply never equal to a value of a different kind — the
// identical "== is total: well-typed, and simply false, for any two
// differently-typed operands" fact checkDerivedTierComparison's own doc
// comment establishes for context.derived_tier, applied to every other
// closed-kind context field this package can classify. Confirmed
// empirically for every path in contextFieldKind (see the task report):
// each of context.agent.trust_tier == 5, context.delegation.max_action_tier
// == 5, context.agent.suspended == "true", context.agent.enabled ==
// "false", context.delegation.depth == "2", and context.agent.allowed_tools
// == "Bash" validates, prepares, and evaluates to zero verdicts against an
// input that should have matched — a forbid rule silently never denies.
//
// Scoped to == and != for the same reason checkTierVocabulary and
// checkDerivedTierComparison are: confirmed empirically that a Boolean,
// Long, or Set field compared to a mismatched-kind literal via one of the
// four ordering operators (<, <=, >, >=, none of which Cedar defines for
// those kinds) already fails at *evaluation* with a genuine Cedar type
// error ("expected comparable value, got bool/set/string"), which Evaluate
// (evaluate.go) already turns into a deny verdict naming the policy. That
// is already fail-closed; adding an authoring-time rejection for the
// ordering operators here would not close any additional gap, only
// duplicate one.
func checkContextFieldKind(expr json.RawMessage) error {
	_, b, ok := asOperator(expr, "==", "!=")
	if !ok {
		return nil
	}
	path, lit, ok := pathAndLiteral(b.Left, b.Right)
	if !ok {
		return nil
	}
	wantKind, known := contextFieldKind[path]
	if !known {
		return nil
	}
	gotKind, litOK := literalKind(lit)
	if !litOK || gotKind == wantKind {
		return nil
	}
	return fmt.Errorf("condition compares %s (always a Cedar %s) to %#v, which is a %s — never equal at any value; this can never match any value buildRequest actually produces",
		path, wantKind, lit, gotKind)
}

// checkDerivedTierComparison rejects a comparison between
// context.derived_tier (always a Cedar Long — see request.go's buildRequest)
// and a literal that cannot be its real value: either a non-numeric literal
// compared via == or != ("name instead of ordinal": derived_tier ==
// "DESTRUCTIVE" can never be true, since a Long is never equal to a String),
// or a numeric literal outside ActionTier's real ordinal range, compared via
// any of the six operators ("out-of-lattice ceiling": derived_tier > 99 can
// never be true, since no ActionTier value exceeds DESTRUCTIVE's ordinal).
// models.ParseActionTier — not a hand-rolled min/max here — is the range
// check, the same range-checking function models already exports for
// exactly this purpose (see its own doc comment: "casting an untrusted int
// directly to ActionTier would admit values outside the lattice").
//
// The non-numeric check is deliberately narrower than the range check: only
// == and != are rejected, never the four ordering operators. A non-numeric
// literal compared to derived_tier via <, <=, >, or >= already raises a
// genuine Cedar type error at evaluation time (confirmed empirically
// against this exact cedar-go release — see the task report), because
// those operators require comparable operands where == and != do not
// (Cedar's == is total: it is well-typed, and simply false, for any two
// differently-typed operands). Rejecting the ordering-operator case here
// too would not add coverage, only duplicate it — and would reject
// TestEvaluate_EvaluationFailureDeniesAndNamesThePolicy's own
// `context.derived_tier > "2"` fixture, whose entire purpose is proving
// that evaluation-time path still works.
func checkDerivedTierComparison(expr json.RawMessage) error {
	op, b, ok := asOperator(expr, "==", "!=", "<", "<=", ">", ">=")
	if !ok {
		return nil
	}
	path, lit, ok := pathAndLiteral(b.Left, b.Right)
	if !ok || path != "context.derived_tier" {
		return nil
	}

	n, isNumber := lit.(float64)
	if !isNumber {
		if op == "==" || op == "!=" {
			return fmt.Errorf("condition compares context.derived_tier (always a Long) to %#v, which is never a Long — this can never match any value buildRequest actually produces", lit)
		}
		return nil
	}
	if _, err := models.ParseActionTier(int(n)); err != nil {
		return fmt.Errorf("condition compares context.derived_tier to %v, which is not a valid action tier ordinal — this can never match any value buildRequest actually produces: %w", lit, err)
	}
	return nil
}

// checkLiteralContradiction rejects an == or != comparison between two pure
// literals (no reference to principal, action, resource, or context at
// all) that is always false — e.g. `1 == 2`. Cedar's == is total (it never
// errors, even across mismatched types — see checkDerivedTierComparison's
// doc comment), so a policy whose entire condition reduces to a false
// equality between constants parses, prepares, and evaluates cleanly, and
// then simply never matches, ever, for any request: nothing about it
// depends on the request in the first place.
//
// This is narrower than a general tautology/contradiction checker on
// purpose: proving an arbitrary boolean expression can never be true is
// SAT-hard in general, and nothing among the thirteen audited forms needs
// more than this direct case. A tautology (1 == 1) is left alone — it is
// not the defect class this task audits, and flagging it would reject a
// policy that, however oddly written, matches every request it is asked
// about.
//
// Restricted to scalarLiteral operands (string, float64, bool) — not every
// {"Value": ...} node literalValue accepts decodes to one. An entity-UID
// literal (User::"a", inside a `when` clause rather than a scope position)
// marshals as {"Value": {"__entity": {"type": "User", "id": "a"}}}, which
// decodes to a Go map[string]any; comparing two maps with == panics at
// runtime (confirmed empirically: `when { User::"a" == User::"b" } `
// crashed this function before this guard was added). Whether two distinct
// entity literals, or two extension-type constants, can ever compare equal
// is a real question — just a different and larger one than "is this
// specific numeral contradiction dead," the one case the thirteen audited
// forms actually need, and not worth widening this check's scope (or its
// panic surface) to answer today.
func checkLiteralContradiction(expr json.RawMessage) error {
	op, b, ok := asOperator(expr, "==", "!=")
	if !ok {
		return nil
	}
	l, lok := literalValue(b.Left)
	r, rok := literalValue(b.Right)
	if !lok || !rok {
		return nil // at least one side references the request; nothing to fold
	}
	ls, lok := scalarLiteral(l)
	rs, rok := scalarLiteral(r)
	if !lok || !rok {
		return nil
	}
	equal := ls == rs
	if (op == "==" && equal) || (op == "!=" && !equal) {
		return nil // a tautology, not a contradiction — not this check's concern
	}
	return fmt.Errorf("condition compares literal %v %s literal %v, which does not depend on the request at all and is always false — this policy can never match", l, op, r)
}

// scalarLiteral reports whether v — a literalValue result — is a Cedar
// String, Long, or Boolean, decoded by encoding/json as a string, float64,
// or bool respectively, the three Go kinds safe to compare with ==. Any
// other decoded shape (map[string]any for an entity/extension literal,
// []any were a Value node ever to wrap a Set — not observed, but not ruled
// out either) is reported not ok rather than risking a panic on Go's
// comparison of an uncomparable type.
func scalarLiteral(v any) (any, bool) {
	switch v.(type) {
	case string, float64, bool:
		return v, true
	default:
		return nil, false
	}
}

// checkEmptySetMembership rejects a membership test against an empty set
// literal — `expr in []` or `[].contains(expr)` — either of which is
// well-typed and can never be true for any request, since nothing is ever a
// member of the empty set. This is the Cedar-syntax instance of the same
// "an empty collection can never mean what its author intended" defect
// jsonpolicy's own empty `"in": []` check guards against (see
// policytest/contract.go's DeadForm doc comment).
func checkEmptySetMembership(expr json.RawMessage) error {
	if _, b, ok := asOperator(expr, "in"); ok && isEmptySet(b.Right) {
		return fmt.Errorf("condition tests membership in an empty set literal (`in []`), which is never true for any request — this policy can never match")
	}
	if _, b, ok := asOperator(expr, "contains"); ok && isEmptySet(b.Left) {
		return fmt.Errorf("condition calls .contains(...) on an empty set literal, which is never true for any request — this policy can never match")
	}
	return nil
}
