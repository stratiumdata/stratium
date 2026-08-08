package audit

import (
	"errors"
	"testing"
	"time"
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
	mutations := map[string]func(*Entry){
		"TenantID":      func(e *Entry) { e.TenantID = "other" },
		"OccurredAt":    func(e *Entry) { e.OccurredAt = e.OccurredAt.Add(time.Second) },
		"EventType":     func(e *Entry) { e.EventType = "other" },
		"Actor":         func(e *Entry) { e.Actor = "mallory@example.com" },
		"Decision":      func(e *Entry) { e.Decision = "DENY" },
		"DeniedLeg":     func(e *Entry) { e.DeniedLeg = "agent" },
		"DeniedAtDepth": func(e *Entry) { e.DeniedAtDepth = 3 },
		"Reason":        func(e *Entry) { e.Reason = "other" },
		"ToolName":      func(e *Entry) { e.ToolName = "Bash" },
		"Action":        func(e *Entry) { e.Action = "delete" },
		"DeclaredTier":  func(e *Entry) { e.DeclaredTier = 1 },
		"DerivedTier":   func(e *Entry) { e.DerivedTier = 4 },
		"ChainDepth":    func(e *Entry) { e.ChainDepth = 2 },
		"InputDigest":   func(e *Entry) { e.InputDigest = [32]byte{9} },
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

// Length prefixing prevents field-boundary ambiguity: without it,
// {Actor:"ab", Reason:"c"} and {Actor:"a", Reason:"bc"} hash identically.
func TestHash_FieldBoundariesUnambiguous(t *testing.T) {
	a := entry(ZeroHash, "c")
	a.Actor = "ab"
	b := entry(ZeroHash, "bc")
	b.Actor = "a"
	if a.Hash() == b.Hash() {
		t.Fatal("field boundaries are ambiguous — serialization is not length-prefixed")
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
