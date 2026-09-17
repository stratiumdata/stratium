// audit_view.go holds the WIRE shape of an audit_chain row, which is
// deliberately not audit.Entry.
//
// audit.Entry is the CANONICAL shape: Entry.Hash() serializes every one of
// its fields, and TestHash_CoversEveryField fails if a field is added and
// left out. A reader needs two things Entry does not carry -- the row's seq
// (the cursor a caller pages with) and the stored entry_hash (Entry computes
// its own rather than carrying one) -- and adding either to Entry would
// change what every past row hashed to, breaking verification for the whole
// table. So the reader gets its own type, and the hashing type is left
// alone.
package models

import (
	"time"

	"github.com/google/uuid"
)

// AuditEntryView is one audit_chain row as the admin API returns it.
//
// PrevHash and EntryHash are []byte, which encoding/json renders as base64.
// They are included so a caller reading a CONTIGUOUS range can re-walk the
// chain themselves with audit.Verify. They cannot verify a filtered read:
// Verify requires its first entry to link to the zero hash, and a filtered
// subset is not contiguous. That is a property of the chain, not a gap in
// this type -- see docs/architecture.md §14.
type AuditEntryView struct {
	Seq int64 `json:"seq"`

	PrevHash  []byte `json:"prev_hash"`
	EntryHash []byte `json:"entry_hash"`

	OccurredAt time.Time `json:"occurred_at"`
	EventType  string    `json:"event_type"`
	Actor      string    `json:"actor"`

	AgentID      *uuid.UUID `json:"agent_id,omitempty"`
	DelegationID *uuid.UUID `json:"delegation_id,omitempty"`

	ToolName    string `json:"tool_name"`
	DerivedTier int16  `json:"derived_tier"`

	Decision string `json:"decision"`
	Reason   string `json:"reason"`
}

// AuditPage is one page of audit entries, newest first.
//
// NextBeforeSeq is the cursor for the following page and is omitted when the
// page was not full -- a caller that receives no cursor has reached the end,
// which is a different fact from "the next page happens to be empty" and is
// worth being able to tell apart without a second round trip.
type AuditPage struct {
	Entries       []AuditEntryView `json:"entries"`
	NextBeforeSeq *int64           `json:"next_before_seq,omitempty"`
}
