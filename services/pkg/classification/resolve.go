// resolve.go answers "what is this resource's classification?" from a
// tenant's own prefix rules (spec §3.9.1, R4-R7). It is the other half of
// this package's subject: classification.go says what the levels ARE and
// whether one is under a cap; this file says which one a given resource
// carries. R3 recorded that nothing supplied a label at all, which made
// every configured cap deny under R2; this is what supplies it.
//
// Pure, like everything else here: the rules are read from the store by the
// caller and passed in, no clock, no I/O, no ambient state.
package classification

import (
	"cmp"
	"strings"
)

// Rule is one tenant's mapping from a resource-id prefix to a level in a
// hierarchy. It is the row shape Task 2's table stores and the PDP reads;
// this package neither loads nor validates it.
//
// Level is NOT checked against Hierarchy here. That check belongs at write
// time, where an operator can be told their row is wrong while they still
// have somewhere to put the fix; a second copy of it on the decision path
// would be a second thing to drift. A rule naming a level its hierarchy does
// not have still matches, and CheckCap then denies with "unknown
// classification level" — which names the actual problem, where a rule that
// silently failed to match would report only that nothing was labelled.
type Rule struct {
	Prefix    string
	Hierarchy string
	Level     string
}

// Match is a resolved label, plus what resolving it overrode.
type Match struct {
	// Rule is the winning rule, whole. The caller needs Level and Hierarchy
	// to build the resource attributes CheckCap reads, and Prefix to name
	// the rule in a log line, so returning the row costs nothing over
	// returning the two fields and saves the caller a lookup it cannot do.
	Rule Rule

	// LoweredFrom is the rule this one overrode, and is non-nil ONLY when
	// the winner resolves strictly lower than it within the same hierarchy
	// (R6). Nil means either nothing was overridden or the override did not
	// lower anything; both are unremarkable and neither is worth a log line.
	//
	// A pointer to the overridden rule rather than a bool beside the label,
	// for two reasons. R6 makes this log line the operator's ONLY signal
	// that a carve-out is doing something, and a bare flag would say a
	// lowering happened without naming what it lowered — the operator would
	// then have to re-derive the next-longest match by hand, which is the
	// one thing only this function saw. And a single nilable field cannot
	// disagree with itself the way a bool paired with a rule can: there is
	// no way to claim a lowering without naming its subject.
	//
	// It is a field rather than a second return value because it is part of
	// the answer, not a separate question: a caller that writes
	// `label, _ := Resolve(...)` has discarded R6's signal invisibly,
	// whereas an unused struct field stays available to whatever the caller
	// passes the match along to.
	//
	// It never aliases the caller's rule slice.
	LoweredFrom *Rule

	// SwitchedHierarchyFrom is the nearest rule this one overrode from a
	// DIFFERENT hierarchy, and is nil unless the winner's hierarchy differs
	// from it. It is the ruling on the case Task 1 surfaced and neither R6
	// nor Task 2's uniqueness key resolves: a `commercial` PUBLIC carve-out
	// beneath a `nato` TOP-SECRET rule makes the resource escape a nato cap
	// entirely, because CheckCap consults one hierarchy per resource and a
	// nato cap says nothing about commercial.
	//
	// Reported, not refused, and reported SEPARATELY from LoweredFrom.
	//
	// Not refused, because refusing would make a genuinely two-scheme tenant
	// inexpressible — a commercial subtree inside a nato tree is a fact an
	// operator may legitimately be recording, and "this configuration cannot
	// be written" is the exact argument R6 used to reject highest-wins. The
	// allow itself is not the defect: per-hierarchy caps are designed so
	// that silence about a hierarchy is not a denial (R9 says so in as many
	// words, for the known-hierarchy case it deliberately leaves allowing).
	// What was missing was any signal at all, and that is what this closes.
	//
	// Not folded into LoweredFrom, because it is not a lowering and saying
	// so would put a false claim in the operator's only signal: no ordering
	// ranks a commercial level against a nato one, which is precisely why
	// overriddenBy skips other hierarchies rather than comparing across
	// them.
	//
	// No direction test, unlike LoweredFrom. A lowering is worth reporting
	// only when it lowers; a hierarchy switch escapes the outer hierarchy's
	// cap whichever hierarchy it moves to, so both directions are the same
	// event and gating on one would hide half of them.
	//
	// It never aliases the caller's rule slice.
	SwitchedHierarchyFrom *Rule

	// OverrodeUnrankable is the nearest rule this one overrode in its OWN
	// hierarchy whose level the system cannot rank, and is nil otherwise. It
	// closes, one column over, the hole R9 closed for the winner:
	//
	//	/data/    nato  SEKRET        <- one typed character, in the LEVEL
	//	/data/x/  nato  UNCLASSIFIED
	//	caps: {"nato": "CONFIDENTIAL"}
	//
	// overriddenBy skips the outer rule because there is no rank to compare,
	// so LoweredFrom is nil, SwitchedHierarchyFrom is nil (same hierarchy),
	// and a capped subtree allows with nothing said. The allow is R6 working
	// as designed; the loss is that the operator never learns their /data/
	// SECRET rule is inert.
	//
	// A third field rather than a third meaning for LoweredFrom, for R10's
	// reason exactly: reporting this as a lowering would assert an ordering
	// between UNCLASSIFIED and SEKRET that does not exist, which is the false
	// claim in the operator's only signal that R10 exists to prevent.
	//
	// The same standard switchedFrom is held to, applied consistently:
	// validateResourceLabelRule refuses SEKRET at write time, and that is a
	// better error message, not the enforcement — a stale read, an in-flight
	// migration and a direct psql write each hand this function rows it never
	// saw. The tempting reason to skip this is that an unrankable rule denies
	// loudly (R9) wherever it WINS, so it announces itself; that argument
	// fails precisely here, where it never wins because a carve-out covers
	// every id it would have decided.
	//
	// Nil when the WINNER is unrankable. R9 then denies the decision itself
	// and names the level, so there is no silence to break — with one honest
	// gap: R9 is reached only when a cap is CONFIGURED, since CheckCap
	// returns allow on len(caps) == 0 before looking at the label at all. An
	// uncapped delegation against an unrankable winner therefore produces
	// neither a denial nor a line. No consequence follows — an uncapped
	// delegation is unrestricted on this axis whatever the label says — but
	// the claim is narrowed to what holds rather than left as "R9 covers it".
	//
	// It never aliases the caller's rule slice.
	OverrodeUnrankable *Rule
}

// Resolve returns the label for resourceID: the rule with the LONGEST
// matching prefix (R6), plus the two things a caller cannot re-derive about
// what winning cost — whether that rule lowered the classification within its
// hierarchy (LoweredFrom, R6) and whether it left one (SwitchedHierarchyFrom).
// Both are reports about the rule set, not about the decision, which the
// winner alone settles.
//
// The second return is false when no rule matched. That is not a failure and
// it is not "unclassified" — it is the absence of a label, and R2/R7 make it
// deny at CheckCap. Do not substitute a default level for it.
//
// # Matching is plain string prefix: /data DOES match /database/x
//
// This is the case an operator will get wrong, so it is stated where their
// mental model forms. `/data` matches `/database/x` because `/data` is
// literally a prefix of it. An operator who means the directory writes the
// separator — `/data/` — and the spec's own R6 example does exactly that.
//
// The alternative, matching only at a path boundary, was rejected on three
// counts. It needs a separator vocabulary the resource id does not carry:
// ids come from whatever field the tenant catalogued as `resource_field`,
// which is usually a POSIX path but is equally a bucket key, a URL, a
// command string, or a dotted table name — so the matcher would be guessing
// at syntax, which is precisely the "guess now" R5 refuses when it rules out
// glob. It would put a second, invisible rule between what an operator wrote
// and what it does, against R5's "an operator can predict what a rule does
// by reading it". And it would break R7: the empty-prefix catch-all matches
// everything only because "" is a prefix of every string, and a
// boundary-aware matcher would have to special-case it back in — turning the
// one construct R7 says costs no mechanism into the mechanism.
//
// The hazard this accepts is real and named: a boundary-less rule that
// LOWERS covers sibling subtrees the operator never meant. That is the exact
// case LoweredFrom exists to surface (R6's mirror risk), and the operator
// documentation R7 calls for should say to write the separator.
//
// # Two rules with the same prefix resolve to NO label
//
// Not to an arbitrary one. Two rules can only tie on length by being the
// identical prefix — same length, both prefixes of the same id — so a tie is
// one prefix carrying two answers. Nothing ranks one above the other, so any
// winner would depend on the order the store returned rows in, which is the
// ruling lookupCap already applies to two caps differing only by case:
// ambiguity denies. Refusing costs no new failure mode, because an
// unresolved resource is R7's ordinary unlabelled case.
//
// This deliberately does NOT lean on Task 2's uniqueness key. That key is
// (tenant_id, prefix) — narrowed from (tenant_id, prefix, hierarchy) after
// this function's own reasoning showed the wider one permitted a legal pair
// of rows no resource could ever satisfy, CheckCap reading a single
// hierarchy per resource. So the key now forbids one prefix carrying two
// answers at all, and this refusal is defence in depth rather than the only
// guard.
//
// It stays, because a schema constraint is not a runtime one. A stale read,
// an in-flight migration, and a store bug all hand this function rules the
// constraint has not excluded, and "whichever row arrived first" is not an
// answer it should be capable of giving on a decision path.
//
// Rules that AGREE are not ambiguous: duplicates, and rules differing only
// in the case of their hierarchy or level (which Postgres' case-sensitive
// unique key would happily store as two rows), say the same thing.
func Resolve(rules []Rule, resourceID string) (Match, bool) {
	winner, ambiguous := longestMatch(rules, resourceID)
	if winner == nil || ambiguous {
		return Match{}, false
	}
	lowered, unrankable := overriddenBy(rules, resourceID, *winner)
	return Match{
		Rule:                  *winner,
		LoweredFrom:           lowered,
		SwitchedHierarchyFrom: switchedFrom(rules, resourceID, *winner),
		OverrodeUnrankable:    unrankable,
	}, true
}

// longestMatch finds the rule with the longest matching prefix, and reports
// whether another rule ties with it and disagrees.
//
// Ambiguity is tracked against the CURRENT winner and cleared whenever a
// longer rule replaces it, so it describes only the winning length. A rule
// set that is ambiguous at a shorter prefix is not ambiguous for a resource
// a longer rule covers, and neither the winner's identity nor the ambiguity
// verdict depends on the order the rules arrive in.
//
// The returned VALUE can. Among rules that agree only once case is folded,
// the first encountered wins, so Match.Rule.Level comes back "SECRET" or
// "secret" by slice order — a difference that reaches CheckCap's denial
// reason and the audit record. Left alone deliberately: the decision is
// identical either way (Index folds too), and normalising would report a
// level in casing the operator never wrote. The claim above is narrowed to
// what holds rather than widened to what would sound better.
func longestMatch(rules []Rule, resourceID string) (*Rule, bool) {
	var winner *Rule
	ambiguous := false
	for i := range rules {
		r := &rules[i]
		if !strings.HasPrefix(resourceID, r.Prefix) {
			continue
		}
		switch {
		case winner == nil || len(r.Prefix) > len(winner.Prefix):
			winner, ambiguous = r, false
		case len(r.Prefix) == len(winner.Prefix) && !agree(*r, *winner):
			ambiguous = true
		}
	}
	return winner, ambiguous
}

// agree reports whether two rules say the same thing. Hierarchy and level
// fold case, the same fold Index applies, so two rules this package cannot
// tell apart are not treated as a conflict. Prefix is not compared: agree is
// only asked about rules of equal length that both matched the same id, and
// those prefixes are necessarily the identical string.
func agree(a, b Rule) bool {
	return strings.EqualFold(a.Hierarchy, b.Hierarchy) && strings.EqualFold(a.Level, b.Level)
}

// overriddenBy returns the rule winner displaced, but only when winner
// resolves strictly LOWER than it — the one case R6 wants logged. Nil
// otherwise. Its second return is the nearest rule it skipped for being
// unrankable, which is Match.OverrodeUnrankable — computed here rather than
// in a pass of its own because this loop already has the eligibility test and
// already computes the rank that decides it.
//
// "The rule it overrides" is the next-longest match IN THE WINNER'S
// HIERARCHY, not the next-longest overall. A level is higher or lower only
// within one ordering; Index returns -1 across hierarchies rather than a
// comparable number, so a nearer rule in another hierarchy is not something
// the winner can be said to have lowered. Taking the next-longest overall
// would miss the lowering entirely whenever a rule from another hierarchy
// sits between the two — a false negative in the one signal an operator has.
//
// A level neither side can rank is not evidence of anything. An unrankable
// WINNER can never be reported as lowering (Index gives it -1, which would
// otherwise compare as beneath every real level and manufacture a lowering
// claim out of a typo), and an unrankable rule further out is skipped so the
// nearest rankable one is still found.
//
// The rule named may itself sit at an ambiguous length — two rules on one
// shorter prefix, disagreeing. That does not suppress the report: the
// decision is already settled by an unambiguous winner, so only the warning
// is at stake, and one naming the larger of two drops beats one naming
// nothing. TestResolve_OverriddenTieIsBrokenDeterministically is that case.
//
// This is a second pass rather than a second tracker in longestMatch because
// the hierarchy that decides which rules are even eligible is not known
// until the winner is.
func overriddenBy(rules []Rule, resourceID string, winner Rule) (lowered, unrankable *Rule) {
	winnerRank := Index(winner.Hierarchy, winner.Level)
	if winnerRank < 0 {
		return nil, nil
	}

	var overridden, unrankableRule Rule
	overriddenRank := -1
	found, foundUnrankable := false, false
	for _, r := range rules {
		if len(r.Prefix) >= len(winner.Prefix) || !strings.HasPrefix(resourceID, r.Prefix) {
			continue
		}
		if !strings.EqualFold(r.Hierarchy, winner.Hierarchy) {
			continue
		}
		rank := Index(r.Hierarchy, r.Level)
		if rank < 0 {
			// Still skipped for the lowering comparison — there is no rank to
			// compare — but no longer dropped on the floor. Nearest first, and
			// the level breaks a tie so the report does not depend on the
			// order rows arrived in, the same discipline the two winners below
			// and in switchedFrom follow.
			if !foundUnrankable || len(r.Prefix) > len(unrankableRule.Prefix) ||
				(len(r.Prefix) == len(unrankableRule.Prefix) && r.Level < unrankableRule.Level) {
				unrankableRule, foundUnrankable = r, true
			}
			continue
		}
		// Longest first; on a tie the higher level wins, so that a rule set
		// carrying the pair Task 2's key forbids still names the same rule
		// on every run. The tie affects only what gets logged — the winner
		// above is already settled — so the deterministic choice is the one
		// that reports the larger drop.
		if !found || len(r.Prefix) > len(overridden.Prefix) ||
			(len(r.Prefix) == len(overridden.Prefix) && rank > overriddenRank) {
			overridden, overriddenRank, found = r, rank, true
		}
	}

	// Copies: the caller's slice must not be reachable through a completed
	// match. Both reports are independent — a carve-out can lower a rankable
	// rule AND cover an inert one, and each is worth its own line.
	if foundUnrankable {
		unrankable = &unrankableRule
	}
	if !found || winnerRank >= overriddenRank {
		return nil, unrankable
	}
	return &overridden, unrankable
}

// switchedFrom returns the nearest rule winner displaced from a DIFFERENT
// hierarchy, or nil. See Match.SwitchedHierarchyFrom for the ruling this
// implements and why it is a separate field rather than part of the lowering
// report.
//
// The mirror image of overriddenBy's eligibility test, deliberately: that
// one keeps only same-hierarchy rules, this one keeps only different-
// hierarchy rules, and both fold case exactly as Index does. Every rule is
// therefore eligible for exactly one of the two reports, so the pair can
// never describe the same rule twice or drop one between them.
//
// No rank is consulted on either side, unlike overriddenBy, and no rule is
// skipped for being unrankable. There is nothing to rank: the claim is that
// the winner left a hierarchy, which is true of a `natoo` rule as much as a
// `nato` one, and a rule this function skipped for a typo would be a
// carve-out escaping a cap with nothing said about it — the very failure
// this field exists to prevent.
//
// The tie-break is by hierarchy then level, for the reason overriddenBy
// breaks its own tie: a tie means two rules on one identical prefix — the
// pair Task 2's key forbids and this package still refuses to assume away —
// and a report that named a different rule depending on the order rows
// arrived in would be a warning an operator cannot reproduce. Length first,
// though: the nearest rule left behind is the one worth naming.
func switchedFrom(rules []Rule, resourceID string, winner Rule) *Rule {
	var outer Rule
	found := false
	for _, r := range rules {
		if len(r.Prefix) >= len(winner.Prefix) || !strings.HasPrefix(resourceID, r.Prefix) {
			continue
		}
		if strings.EqualFold(r.Hierarchy, winner.Hierarchy) {
			continue
		}
		if !found || len(r.Prefix) > len(outer.Prefix) ||
			(len(r.Prefix) == len(outer.Prefix) &&
				cmp.Or(strings.Compare(r.Hierarchy, outer.Hierarchy),
					strings.Compare(r.Level, outer.Level)) < 0) {
			outer, found = r, true
		}
	}
	if !found {
		return nil
	}
	// A copy, for the reason overriddenBy returns one.
	return &outer
}
