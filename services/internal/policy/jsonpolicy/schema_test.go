package jsonpolicy

import (
	"testing"

	"stratium/pkg/models"
)

// intPtr returns a pointer to n. tierMatch.AtMost is *int, and Go cannot
// address a composite literal field's value directly.
func intPtr(n int) *int { return &n }

// TestTierMatch_MatchesComparesNumerically pins tierMatch.matches' own
// contract directly: tier <= AtMost as integers, never as decimal strings.
// It constructs tierMatch by hand rather than going through
// parseDoc/Validate, deliberately: tierMatch.validate (schema.go) now
// rejects any AtMost outside models.ActionTier's valid range [0, 4], and
// every legal pair drawn from that range is a single decimal digit on both
// sides — single-digit lexicographic order is numeric order by
// construction (the ASCII digits '0'-'9' sort the same as their values),
// so no pair a validated policy could ever carry is able to distinguish
// integer comparison from string comparison. Only a value outside what
// Validate would accept — AtMost: 10 here, deliberately unreachable through
// the public Prepare/Validate path (see TestValidate_AtMostOutOfRangeIsRejected)
// — can still expose the bug, which is exactly why this test talks to
// tierMatch directly instead of through Evaluate: it pins the comparison
// operator's own correctness as an implementation invariant, independent of
// what today's validation range happens to admit.
func TestTierMatch_MatchesComparesNumerically(t *testing.T) {
	tm := tierMatch{AtMost: intPtr(10)}

	// "4" <= "10" is false lexicographically (leading '4' > leading '1'),
	// but 4 <= 10 is true numerically — the one pairing that forces the two
	// comparisons apart. See tierMatch.matches' own doc comment.
	if !tm.matches(models.ActionTierDestructive) {
		t.Fatal("DESTRUCTIVE (4) did not match at_most: 10 — want true (4 <= 10 numerically); a string-comparison regression would report false here")
	}

	// Positive control: the same method must still correctly reject a
	// clearly-too-low ceiling, so the assertion above is proving "matches
	// when it numerically should," not "this method always returns true."
	small := tierMatch{AtMost: intPtr(1)}
	if small.matches(models.ActionTierDestructive) {
		t.Fatal("DESTRUCTIVE (4) matched at_most: 1 — want false (4 <= 1 is false under any correct comparison)")
	}
}
