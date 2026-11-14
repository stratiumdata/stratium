package authz

import (
	"fmt"
	"strings"

	"github.com/stratiumdata/stratium/pkg/models"
)

// satisfiesIDPrefix reports whether EVERY resource identity in ids is inside
// prefix, and why not when one is not.
//
// Every one, not any one, and that is the whole safety argument. A shell
// command names several paths (ShellResourceIDs); requiring only one of them
// to be in scope would let a benign path buy access for a dangerous one, the
// same decoy that strictest-wins labelling exists to defeat. Requiring all of
// them means an extra path adds an obligation rather than relieving one, so
// there is nothing an attacker can ADD to a command to widen it.
//
// The prefix comparison is a bare strings.HasPrefix with no boundary logic,
// which is safe only because write-time validation guarantees the prefix ends
// in "/" (internal/store's validateResourceConstraints). Without that,
// "/workspace" would admit "/workspace-evil/secrets.txt". If you are tempted
// to add boundary handling here, fix the validation instead: one rule in one
// place beats two half-rules.
func satisfiesIDPrefix(ids []string, prefix string) (bool, string) {
	if len(ids) == 0 {
		// Distinct from an outside-the-scope denial, deliberately. An
		// operator's audit trail has to tell "we could not check" apart from
		// "we checked and it was outside", the same distinction CheckCap
		// draws for an unlabelled resource.
		return false, "request identifies no resource; the delegation's " +
			models.ResourceIDPrefixKey + " constraint cannot be evaluated and therefore denies"
	}
	for _, id := range ids {
		// Checked before the prefix test, not after: "/workspace/../etc/shadow"
		// PASSES HasPrefix, so a prefix-first order would allow the escape.
		// Rejected on the segment rather than resolved, because nothing here
		// may assume the id is a filesystem path — it may be an S3 key, an
		// API route, or a document id, and path.Clean would be inventing a
		// meaning the tenant never gave it.
		if hasDotDotSegment(id) {
			return false, fmt.Sprintf(
				"resource %q contains a %q segment and cannot be checked against %s %q",
				id, "..", models.ResourceIDPrefixKey, prefix)
		}
		if !strings.HasPrefix(id, prefix) {
			return false, fmt.Sprintf("resource %q is outside delegation %s %q",
				id, models.ResourceIDPrefixKey, prefix)
		}
	}
	return true, ""
}

// hasDotDotSegment reports whether id contains a ".." PATH SEGMENT.
//
// A segment, not a substring: "/workspace/..hidden/x" and "/a/b..c.txt" are
// ordinary names and must not be refused. Splitting on "/" is the whole test.
func hasDotDotSegment(id string) bool {
	for _, segment := range strings.Split(id, "/") {
		if segment == ".." {
			return true
		}
	}
	return false
}
