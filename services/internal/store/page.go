package store

import (
	"time"

	"github.com/google/uuid"
)

// List page-size bounds for the tables agents grow: approvals and
// delegations. Clamped here, as ListAudit's own are, so no caller of this
// package can ask the database for every row.
const (
	listDefaultLimit = 100
	listMaxLimit     = 500
)

// ListCursor names a row in a newest-first list: its timestamp and its id.
// A page "before" a cursor holds the rows that sort after it.
type ListCursor struct {
	At time.Time
	ID uuid.UUID
}

// clampListLimit applies the bounds above: zero or less takes the default.
func clampListLimit(limit int) int {
	switch {
	case limit <= 0:
		return listDefaultLimit
	case limit > listMaxLimit:
		return listMaxLimit
	}
	return limit
}

// cursorArgs are a cursor's two query parameters, both NULL when there is
// none, which the list queries read as "from the newest".
func cursorArgs(before *ListCursor) (at, id any) {
	if before == nil {
		return nil, nil
	}
	return before.At, before.ID.String()
}
