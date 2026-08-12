// Package audit implements the hash-chained, append-only audit trail.
//
// Each entry commits to its predecessor, so mutation or deletion breaks
// verification. The chain is per tenant: a tenant's first entry links to the
// zero hash.
//
// Raw tool inputs are never stored — only InputDigest. Encrypted plaintext
// storage and crypto-shredding are deferred until per-tenant key management is
// specified (spec §8); writing raw shell commands into an undeletable table
// before then would be worse than not storing them.
package audit

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
)

// ErrChainBroken indicates the chain does not verify.
var ErrChainBroken = errors.New("audit chain broken")

// ZeroHash is the PrevHash of a tenant's first entry.
var ZeroHash [32]byte

// Entry is one audit record.
//
// Every field must be covered by Hash. A field added here without a
// corresponding line in Hash can be altered undetected —
// TestHash_CoversEveryField guards that.
type Entry struct {
	PrevHash [32]byte

	TenantID   string
	OccurredAt time.Time
	EventType  string
	Actor      string

	AgentID          *uuid.UUID
	DelegationID     *uuid.UUID
	RootDelegationID *uuid.UUID
	ChainDepth       int16

	ToolName     string
	Action       string
	DeclaredTier int16
	DerivedTier  int16

	Decision      string
	DeniedLeg     string
	DeniedAtDepth int16
	Reason        string

	// PolicySource and PolicyID identify the policy verdict the decision was
	// attributed to (authz.Result.Deciding) — the engine ("cedar", "rego",
	// "entitlement", ...) and the specific policy or entitlement row. Both
	// are empty when the decision was default-deny with no verdict at all:
	// "no policy spoke" and "a policy denied" are different facts, and this
	// pair is what lets an auditor trace a denial to the rule that made it.
	PolicySource string
	PolicyID     string

	// UnevaluatedPolicyIDs lists every policy id that went unevaluated
	// because its language had no registered engine, or that engine's own
	// Prepare call failed for the whole batch (authz.Result.
	// UnevaluatedPolicyIDs — aggregated across every verdict authz.Decide
	// saw, not just the one PolicySource/PolicyID names). That aggregation
	// is why this needs to be its own column rather than something
	// PolicySource/PolicyID could already tell an auditor: PolicyID is
	// singular, and FoldVerdicts picks exactly one verdict to attribute a
	// decision to, so an orphaned or unprepared language's own ids would be
	// lost the moment some other verdict wins that tie-break — a Cedar deny,
	// say, always beats an orphaned "rego" verdict, because "cedar" sorts
	// first. This column is where those ids survive regardless of which
	// verdict decided the outcome. Empty on every ordinary decision.
	UnevaluatedPolicyIDs []string

	InputDigest [32]byte
}

// Hash computes the entry's digest over a length-prefixed canonical
// serialization. Length prefixes make field boundaries unambiguous.
func (e Entry) Hash() [32]byte {
	h := sha256.New()

	writeBytes := func(b []byte) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(len(b)))
		h.Write(n[:])
		h.Write(b)
	}
	writeStr := func(s string) { writeBytes([]byte(s)) }
	writeInt := func(v int64) {
		var n [8]byte
		binary.BigEndian.PutUint64(n[:], uint64(v)) //nolint:gosec // G115: bit-pattern reinterpretation for hash serialization, not a value conversion — lossless and deterministic for every int64
		h.Write(n[:])
	}
	writeUUID := func(u *uuid.UUID) {
		if u == nil {
			writeBytes(nil)
			return
		}
		writeBytes(u[:])
	}
	// writeStrList encodes a variable-length list deterministically: a count
	// (so the list's own end is unambiguous — without it, the boundary
	// between the last element and whatever this method writes next could
	// shift, the same field-boundary hazard writeBytes' own length prefix
	// guards against for a single value) followed by each element written
	// through writeStr, so no element's own boundary is ambiguous either.
	// Sorts a copy first — never ss itself, which the caller may still hold
	// a live reference to (see the immutability rule this codebase follows
	// throughout) — so two entries carrying the same set of ids in different
	// slice order still hash identically. Consumers of this list (the
	// aggregation in authz.Decide, and the audit_chain column it is written
	// to) are already expected to hand it over sorted; this is the
	// independent guarantee that Hash's own output does not depend on that
	// discipline holding upstream.
	writeStrList := func(ss []string) {
		sorted := append([]string(nil), ss...)
		sort.Strings(sorted)
		writeInt(int64(len(sorted)))
		for _, s := range sorted {
			writeStr(s)
		}
	}

	writeBytes(e.PrevHash[:])
	writeStr(e.TenantID)
	writeInt(e.OccurredAt.UTC().UnixNano())
	writeStr(e.EventType)
	writeStr(e.Actor)
	writeUUID(e.AgentID)
	writeUUID(e.DelegationID)
	writeUUID(e.RootDelegationID)
	writeInt(int64(e.ChainDepth))
	writeStr(e.ToolName)
	writeStr(e.Action)
	writeInt(int64(e.DeclaredTier))
	writeInt(int64(e.DerivedTier))
	writeStr(e.Decision)
	writeStr(e.DeniedLeg)
	writeInt(int64(e.DeniedAtDepth))
	writeStr(e.Reason)
	writeStr(e.PolicySource)
	writeStr(e.PolicyID)
	writeStrList(e.UnevaluatedPolicyIDs)
	writeBytes(e.InputDigest[:])

	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Verify walks a tenant's chain.
//
// Preconditions, both enforced rather than assumed: entries belong to a single
// tenant, and they are ordered by seq ascending. Ordering cannot be checked
// here — Entry carries no ordinal — so a caller that queries audit_chain
// without ORDER BY seq gets ErrChainBroken on intact data. That is a false
// alarm, never a false acceptance.
//
// The tenant check is defence in depth. Hash is unkeyed SHA-256, so anyone can
// compute a valid-looking PrevHash linking a forged entry onto another tenant's
// real one. Row-level security stops an ordinary session from assembling such a
// slice, but an admin, batch, or buggy paging caller could — and this package
// is the auditor-facing proof, so it should not depend on a caller's diligence.
func Verify(entries []Entry) error {
	if len(entries) == 0 {
		return nil
	}
	if entries[0].PrevHash != ZeroHash {
		return fmt.Errorf("%w: first entry does not link to the zero hash", ErrChainBroken)
	}
	tenant := entries[0].TenantID
	for i := 1; i < len(entries); i++ {
		if entries[i].TenantID != tenant {
			return fmt.Errorf("%w: entry %d belongs to tenant %q, chain is for %q",
				ErrChainBroken, i, entries[i].TenantID, tenant)
		}
		if want := entries[i-1].Hash(); entries[i].PrevHash != want {
			return fmt.Errorf("%w: entry %d does not link to entry %d", ErrChainBroken, i, i-1)
		}
	}
	return nil
}

// Link sets PrevHash from the predecessor, returning the entry ready to
// insert. Pass nil for a tenant's first entry.
func Link(prev *Entry, e Entry) Entry {
	if prev == nil {
		e.PrevHash = ZeroHash
		return e
	}
	e.PrevHash = prev.Hash()
	return e
}
