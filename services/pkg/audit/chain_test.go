package audit

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"
)

var auditNow = time.Date(2026, 8, 8, 12, 0, 0, 0, time.UTC)

func entry(prev [32]byte, reason string) Entry {
	return Entry{
		PrevHash:   prev,
		TenantID:   "tenant-a",
		OccurredAt: auditNow,
		EventType:  "decision",
		Actor:      "alice@example.com",
		Decision:   "ALLOW",
		Reason:     reason,
	}
}

func TestVerify_IntactChain(t *testing.T) {
	e1 := entry(ZeroHash, "first")
	e2 := entry(e1.Hash(), "second")
	e3 := entry(e2.Hash(), "third")
	if err := Verify([]Entry{e1, e2, e3}); err != nil {
		t.Fatalf("intact chain must verify: %v", err)
	}
}

func TestVerify_EmptyChain(t *testing.T) {
	if err := Verify(nil); err != nil {
		t.Fatalf("an empty chain is vacuously valid: %v", err)
	}
}

func TestVerify_DetectsMutation(t *testing.T) {
	e1 := entry(ZeroHash, "first")
	e2 := entry(e1.Hash(), "second")
	e1.Reason = "tampered"
	if err := Verify([]Entry{e1, e2}); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("mutation must break the chain, got: %v", err)
	}
}

func TestVerify_DetectsDeletion(t *testing.T) {
	e1 := entry(ZeroHash, "first")
	e2 := entry(e1.Hash(), "second")
	e3 := entry(e2.Hash(), "third")
	if err := Verify([]Entry{e1, e3}); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("deletion must break the chain, got: %v", err)
	}
}

func TestVerify_RejectsNonZeroGenesis(t *testing.T) {
	bogus := [32]byte{1}
	if err := Verify([]Entry{entry(bogus, "first")}); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("a non-zero genesis prev_hash must be rejected, got: %v", err)
	}
}

func TestHash_Deterministic(t *testing.T) {
	if entry(ZeroHash, "same").Hash() != entry(ZeroHash, "same").Hash() { //nolint:staticcheck // SA4000: identical expressions are intentional — asserts Hash is deterministic across independent calls
		t.Fatal("identical entries must hash identically")
	}
}

// A field omitted from the serialization can be altered undetected. This test
// fails whenever a field is added to Entry without being added to Hash.
func TestHash_CoversEveryField(t *testing.T) {
	base := entry(ZeroHash, "base")
	// Every field on Entry must appear here. A field present on the struct but
	// absent from this table is a field nothing tests — deleting its write from
	// Hash would pass the whole suite. PrevHash matters most: it is the literal
	// chain link, and without it in the digest the structure stops being a chain.
	someUUID := uuid.MustParse("11111111-2222-3333-4444-555555555555")
	mutations := map[string]func(*Entry){
		"PrevHash":             func(e *Entry) { e.PrevHash = [32]byte{7} },
		"TenantID":             func(e *Entry) { e.TenantID = "other" },
		"OccurredAt":           func(e *Entry) { e.OccurredAt = e.OccurredAt.Add(time.Second) },
		"EventType":            func(e *Entry) { e.EventType = "other" },
		"Actor":                func(e *Entry) { e.Actor = "mallory@example.com" },
		"AgentID":              func(e *Entry) { e.AgentID = &someUUID },
		"DelegationID":         func(e *Entry) { e.DelegationID = &someUUID },
		"RootDelegationID":     func(e *Entry) { e.RootDelegationID = &someUUID },
		"ChainDepth":           func(e *Entry) { e.ChainDepth = 2 },
		"ToolName":             func(e *Entry) { e.ToolName = "Bash" },
		"Action":               func(e *Entry) { e.Action = "delete" },
		"DeclaredTier":         func(e *Entry) { e.DeclaredTier = 1 },
		"DerivedTier":          func(e *Entry) { e.DerivedTier = 4 },
		"Decision":             func(e *Entry) { e.Decision = "DENY" },
		"DeniedLeg":            func(e *Entry) { e.DeniedLeg = "agent" },
		"DeniedAtDepth":        func(e *Entry) { e.DeniedAtDepth = 3 },
		"Reason":               func(e *Entry) { e.Reason = "other" },
		"PolicySource":         func(e *Entry) { e.PolicySource = "cedar" },
		"PolicyID":             func(e *Entry) { e.PolicyID = "policy-123" },
		"UnevaluatedPolicyIDs": func(e *Entry) { e.UnevaluatedPolicyIDs = []string{"orphan-1", "orphan-2"} },
		"InputDigest":          func(e *Entry) { e.InputDigest = [32]byte{9} },
	}

	// Guard against the table silently falling behind the struct.
	if got, want := len(mutations), reflect.TypeOf(Entry{}).NumField(); got != want {
		t.Fatalf("mutation table covers %d fields but Entry has %d — add the missing ones", got, want)
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			m := base
			mutate(&m)
			if m.Hash() == base.Hash() {
				t.Fatalf("field %s is not covered by Hash", name)
			}
		})
	}
}

// Length prefixing prevents field-boundary ambiguity: without it, content can
// shift between fields undetected.
//
// The pair must be ADJACENT in Hash's write order. Actor and Reason are nine
// fields apart, and the fixed-width writes between them act as accidental
// delimiters — a test using that pair passes even with length-prefixing removed
// entirely, which is coverage that isn't there. EventType and Actor are written
// back to back with nothing in between, so they collide the moment prefixes go.
func TestHash_FieldBoundariesUnambiguous(t *testing.T) {
	a := entry(ZeroHash, "same")
	a.EventType, a.Actor = "decisionX", "Y"
	b := entry(ZeroHash, "same")
	b.EventType, b.Actor = "decision", "XY"
	if a.Hash() == b.Hash() {
		t.Fatal("adjacent field boundaries are ambiguous — serialization is not length-prefixed")
	}
}

// UnevaluatedPolicyIDs is a list, not a single value like every other field
// Hash covers — its own encoding needs two properties none of the other
// fields need to prove: order does not matter (this test), and one
// element's own boundary cannot bleed into its neighbor's (the next test).
//
// Two entries carrying the same SET of ids in different slice order must
// hash identically. Without Hash sorting its own copy, a chain built from
// the same underlying facts could fork its hash purely on which order a map
// or a concurrent aggregation happened to produce them in — exactly the kind
// of nondeterminism the audit hash chain cannot tolerate (see
// authz.Decide's own aggregation, which sorts for the same reason — this is
// the independent, defensive guarantee that Hash does not merely inherit
// that discipline from its caller).
func TestHash_UnevaluatedPolicyIDsOrderDoesNotAffectHash(t *testing.T) {
	a := entry(ZeroHash, "same")
	a.UnevaluatedPolicyIDs = []string{"orphan-a", "orphan-b", "orphan-c"}
	b := entry(ZeroHash, "same")
	b.UnevaluatedPolicyIDs = []string{"orphan-c", "orphan-a", "orphan-b"}
	if a.Hash() != b.Hash() {
		t.Fatal("the same set of ids in a different order must hash identically — Hash must sort its own copy")
	}
}

// Without a length prefix on each element, ["ab","c"] and ["a","bc"] would
// serialize to the same bytes ("ab" + "c" == "a" + "bc"), the same
// field-boundary hazard TestHash_FieldBoundariesUnambiguous guards against
// for Entry's own fields, one level down inside this one list field.
func TestHash_UnevaluatedPolicyIDsElementBoundariesUnambiguous(t *testing.T) {
	a := entry(ZeroHash, "same")
	a.UnevaluatedPolicyIDs = []string{"ab", "c"}
	b := entry(ZeroHash, "same")
	b.UnevaluatedPolicyIDs = []string{"a", "bc"}
	if a.Hash() == b.Hash() {
		t.Fatal("adjacent element boundaries are ambiguous — each list element must be length-prefixed")
	}
}

// Hash is unkeyed, so a forged entry can be linked onto another tenant's real
// entry by anyone who can read it. Verify must reject the mixed chain rather
// than trusting the caller to have filtered by tenant.
func TestVerify_RejectsCrossTenantForgery(t *testing.T) {
	a1 := entry(ZeroHash, "tenant-a first")
	a2 := entry(a1.Hash(), "tenant-a second")

	forged := entry(a2.Hash(), "forged")
	forged.TenantID = "tenant-b"

	if err := Verify([]Entry{a1, a2, forged}); !errors.Is(err, ErrChainBroken) {
		t.Fatalf("an entry from another tenant must break the chain, got: %v", err)
	}
}

func TestLink(t *testing.T) {
	e1 := Link(nil, entry([32]byte{}, "first"))
	if e1.PrevHash != ZeroHash {
		t.Fatal("a genesis entry must link to the zero hash")
	}
	e2 := Link(&e1, entry([32]byte{}, "second"))
	if e2.PrevHash != e1.Hash() {
		t.Fatal("Link must set PrevHash from the predecessor")
	}
	if err := Verify([]Entry{e1, e2}); err != nil {
		t.Fatalf("a linked chain must verify: %v", err)
	}
}

// TestEntry_RecordsOnlyADigestOfTheInput is half of conformance property C17
// (internal/authz/conformance_test.go), and it is a drift guard rather than a
// behavioural check: nothing here can fail today, and that is the point.
//
// C17 originally read "crypto-shredding a tenant's key renders inputs
// unrecoverable while the chain still verifies" -- a property that presumed
// this system retains decision inputs encrypted. It does not. Spec 4.9
// records the SHA-256 of the raw input and never the input itself, so the
// inputs are unrecoverable already, by construction, with no key to hold and
// none to destroy. Never recording is a stronger guarantee than encrypting
// and shredding: there is no ciphertext to mis-handle and no key-destruction
// procedure to get wrong.
//
// What that guarantee actually needs is protection from DRIFT. Someone adds
// raw-input retention for dry-run replay, or for debugging a support ticket,
// and a "never retained" property silently becomes "retained and hopefully
// protected." This pins Entry's field set by NAME so that addition cannot be
// made without editing this list, which puts the decision in front of a
// reviewer. TestHash_CoversEveryField already pins the COUNT -- that catches
// a field added and left out of the hash; this catches a field added at all.
func TestEntry_RecordsOnlyADigestOfTheInput(t *testing.T) {
	want := []string{
		"PrevHash", "TenantID", "OccurredAt", "EventType", "Actor",
		"AgentID", "DelegationID", "RootDelegationID", "ChainDepth",
		"ToolName", "Action", "DeclaredTier", "DerivedTier", "Decision",
		"DeniedLeg", "DeniedAtDepth", "Reason", "PolicySource", "PolicyID",
		"UnevaluatedPolicyIDs", "InputDigest",
	}

	et := reflect.TypeOf(Entry{})
	var got []string
	for i := range et.NumField() {
		got = append(got, et.Field(i).Name)
	}

	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Entry's fields changed.\n got: %v\nwant: %v\n\n"+
			"If you added a field that can carry a decision's RAW INPUT rather than a "+
			"digest of it, C17 is no longer true and the conformance suite must say so "+
			"instead of this list being widened. If the new field carries something else, "+
			"add it here and to TestHash_CoversEveryField's mutation table.", got, want)
	}

	// The digest is a fixed-width hash, not a string that could hold the
	// input itself. A [32]byte cannot be widened into plaintext without
	// changing the type, which this assertion would catch.
	if f, _ := et.FieldByName("InputDigest"); f.Type != reflect.TypeOf([32]byte{}) {
		t.Fatalf("InputDigest is %v, want [32]byte -- a digest, not a value that could carry the input", f.Type)
	}
}
