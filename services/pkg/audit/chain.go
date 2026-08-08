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
	writeBytes(e.InputDigest[:])

	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Verify walks a tenant's chain. Entries must be in sequence order and all
// belong to one tenant.
func Verify(entries []Entry) error {
	if len(entries) == 0 {
		return nil
	}
	if entries[0].PrevHash != ZeroHash {
		return fmt.Errorf("%w: first entry does not link to the zero hash", ErrChainBroken)
	}
	for i := 1; i < len(entries); i++ {
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
