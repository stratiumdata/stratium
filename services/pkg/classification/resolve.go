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

import "strings"

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
}

// Resolve returns the label for resourceID: the rule with the LONGEST
// matching prefix (R6), and whether that rule lowered the classification
// relative to the rule it overrode.
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
// (tenant_id, prefix, hierarchy), which forbids one prefix carrying two
// levels in ONE hierarchy but permits the same prefix in two hierarchies —
// and since CheckCap reads a single hierarchy from a resource, two
// hierarchies for one resource is an answer nothing downstream can use. So
// ambiguity is reachable configuration, not a violated invariant, and this
// function does not require its caller to have prevented it.
//
// Rules that AGREE are not ambiguous: duplicates, and rules differing only
// in the case of their hierarchy or level (which Postgres' case-sensitive
// unique key would happily store as two rows), say the same thing.
func Resolve(rules []Rule, resourceID string) (Match, bool) {
	winner, ambiguous := longestMatch(rules, resourceID)
	if winner == nil || ambiguous {
		return Match{}, false
	}
	return Match{Rule: *winner, LoweredFrom: overriddenBy(rules, resourceID, *winner)}, true
}

// longestMatch finds the rule with the longest matching prefix, and reports
// whether another rule ties with it and disagrees.
//
// Ambiguity is tracked against the CURRENT winner and cleared whenever a
// longer rule replaces it, so it describes only the winning length. A rule
// set that is ambiguous at a shorter prefix is not ambiguous for a resource
// a longer rule covers, and the result does not depend on the order the
// rules arrive in.
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
// otherwise.
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
// This is a second pass rather than a second tracker in longestMatch because
// the hierarchy that decides which rules are even eligible is not known
// until the winner is.
func overriddenBy(rules []Rule, resourceID string, winner Rule) *Rule {
	winnerRank := Index(winner.Hierarchy, winner.Level)
	if winnerRank < 0 {
		return nil
	}

	var overridden Rule
	overriddenRank := -1
	found := false
	for _, r := range rules {
		if len(r.Prefix) >= len(winner.Prefix) || !strings.HasPrefix(resourceID, r.Prefix) {
			continue
		}
		if !strings.EqualFold(r.Hierarchy, winner.Hierarchy) {
			continue
		}
		rank := Index(r.Hierarchy, r.Level)
		if rank < 0 {
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

	if !found || winnerRank >= overriddenRank {
		return nil
	}
	// A copy: the caller's slice must not be reachable through a completed
	// match.
	return &overridden
}
