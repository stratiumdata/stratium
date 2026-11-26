package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/stratiumdata/stratium/internal/store"
)

// The approvals and delegations lists are newest first and come a page at a
// time: ?limit= sets the page size (the store clamps it, as it does for the
// audit list) and ?before= continues from a cursor. The body stays a plain
// array. When there are older rows, a Link header with rel="next" (RFC 8288)
// carries the URL of the next page.
//
// A cursor is the last row's timestamp and id, joined by cursorSeparator.
const cursorSeparator = "~"

// parsePage reads limit and before from the query. On a bad value it writes
// a 400 and returns ok false.
func parsePage(w http.ResponseWriter, r *http.Request) (before *store.ListCursor, limit int, ok bool) {
	q := r.URL.Query()
	if raw := q.Get("limit"); raw != "" {
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 {
			http.Error(w, "invalid limit: want a positive integer", http.StatusBadRequest)
			return nil, 0, false
		}
		limit = n
	}
	if raw := q.Get("before"); raw != "" {
		at, id, found := strings.Cut(raw, cursorSeparator)
		t, terr := time.Parse(time.RFC3339Nano, at)
		u, uerr := uuid.Parse(id)
		if !found || terr != nil || uerr != nil {
			http.Error(w, "invalid before: use the cursor from a previous page's Link header", http.StatusBadRequest)
			return nil, 0, false
		}
		before = &store.ListCursor{At: t, ID: u}
	}
	return before, limit, true
}

// linkNext sets the Link header for the page after next, or nothing when
// next is nil. The URL is this request's own path with the same limit.
func linkNext(w http.ResponseWriter, r *http.Request, next *store.ListCursor) {
	if next == nil {
		return
	}
	q := url.Values{}
	q.Set("before", next.At.UTC().Format(time.RFC3339Nano)+cursorSeparator+next.ID.String())
	if limit := r.URL.Query().Get("limit"); limit != "" {
		q.Set("limit", limit)
	}
	w.Header().Set("Link", fmt.Sprintf(`<%s?%s>; rel="next"`, r.URL.Path, q.Encode()))
}
