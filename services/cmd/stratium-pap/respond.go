// respond.go holds the small HTTP plumbing every CRUD handler in this
// package shares (policies.go, agents.go, tier_overrides.go): JSON
// encode/decode, path-parameter parsing, and mapping a store-layer error to
// a status code. Kept as its own file, not folded into server.go, so
// server.go stays about routing and authorization and this file stays about
// wire format -- the same "many small files, high cohesion" split every
// other package in this codebase already follows.
package main

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/google/uuid"

	"stratium/internal/authz"
	"stratium/internal/store"
)

// writeJSON encodes v as the response body with the given status code. Its
// own encoding error is deliberately swallowed rather than returned: by the
// time json.Marshal could fail, WriteHeader has already committed status to
// the wire (net/http gives no way to un-send a status code), so there is no
// remaining response left to change to an error -- the same reasoning every
// handler below already applies to its own final response write.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// decodeJSON decodes r's body into v. A nil body (no Content-Length, no
// chunked body -- e.g. a GET-shaped request with no body reader at all), a
// body that fails to decode, and a body carrying a field v does not have are
// all refused with a message naming the problem, never silently leaving v at
// its zero value: a caller that got no error from decodeJSON must be able to
// trust v reflects what was actually sent.
//
// DisallowUnknownFields is what makes that last clause true rather than
// merely intended. encoding/json's default is to DISCARD a key the target
// struct has no field for, so before this every one of decodeJSON's callers
// accepted a typo as a successful write of something other than what the
// operator typed. Most survived it by accident of their own validation --
// allowed_tools is required, caps refuse empty, tool_name is required -- but
// two did not, and both failed OPEN:
//
//   - agents.suspended. PUT {"suspened": true} returned 200 with the agent
//     still active: the reversible kill switch, silently not thrown, on the
//     one control an operator reaches for when an agent is misbehaving.
//   - resource_label_rules.prefix. A typo yielded "", which is the
//     empty-prefix CATCH-ALL rather than the narrow rule intended. Aimed at
//     a permissive level that labels every previously-unlabelled resource,
//     so resources a classification cap used to deny now satisfy it.
//
// Refusing at the decoder closes the whole class in one place, which is why
// neither field carries a guard of its own. The cost is that a client
// sending a field this server does not know now gets a 400 where it used to
// get a silent discard -- the correct direction for an admin API whose
// requests change security configuration.
func decodeJSON(r *http.Request, v any) error {
	if r.Body == nil {
		return errors.New("request body is required")
	}
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return errors.New("malformed request body: " + err.Error())
	}
	return nil
}

// pathID parses the {id} route wildcard as a UUID. On failure it writes the
// 400 response itself and returns ok=false, so every caller's own error
// path is a single "if !ok { return }" -- the same shape bearerToken
// (server.go) already established for a different kind of caller-facing
// parse failure.
func pathID(w http.ResponseWriter, r *http.Request) (uuid.UUID, bool) {
	id, err := uuid.Parse(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id: not a UUID", http.StatusBadRequest)
		return uuid.UUID{}, false
	}
	return id, true
}

// writeStoreError maps an error internal/store's CRUD methods (or
// internal/authz.ValidateOverride, called from within them) can return to
// an HTTP status. The response body is the error's own message: every
// sentinel case below describes either what is wrong with the REQUEST the
// calling operator themselves submitted (their policy failed its engine's
// Validate, their override would lower a tier, their chosen name collides
// with an existing row) or -- store.ErrConflict's own case -- what ELSE
// currently exists that the request conflicts with (an agent a live
// delegation or approval still names) -- not a secret either way, and not
// what the phase's "never log a bearer token, an operator's claims, or
// policy text" rule is about, which governs this process's own logs (see
// oidc.go's Verify for where that rule actually bites). Nothing here calls
// a logger with any of this text.
//
// default (StatusInternalServerError) intentionally does NOT echo err's own
// text to the client: unlike every named case above it, a fall-through here
// means something this package did not anticipate -- most plausibly a raw
// database error -- and internal/store's own errors already wrap enough
// context (table, id) that surfacing the underlying error verbatim to an
// HTTP caller risks leaking schema or connection detail no operator needs
// to fix their own request.
func writeStoreError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		http.Error(w, "not found", http.StatusNotFound)
	case errors.Is(err, store.ErrAlreadyExists),
		errors.Is(err, store.ErrConflict),
		errors.Is(err, store.ErrApprovalNotPending):
		// ErrApprovalNotPending joins ErrAlreadyExists/ErrConflict here, not
		// the 400 group below: like them, it names what the row's OWN
		// current state already is ("already approved/denied"), not
		// anything wrong with the request as submitted -- the same
		// distinction ErrConflict's own doc comment (internal/store/store.go)
		// draws between "what already exists" and "what is wrong with the
		// request."
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.Is(err, store.ErrUnknownLanguage),
		errors.Is(err, store.ErrInvalidEffect),
		errors.Is(err, store.ErrEffectMismatch),
		errors.Is(err, store.ErrEffectNotDeclarable),
		errors.Is(err, store.ErrPolicyInvalid),
		errors.Is(err, store.ErrAllowedToolsRequired),
		errors.Is(err, store.ErrInvalidRequest),
		errors.Is(err, authz.ErrOverrideLowersTier):
		// store.ErrInvalidRequest is also what CreateToolCatalogEntry/
		// UpdateToolCatalogEntry wrap the database's own tool_catalog_tier_
		// or_command_field CHECK violation with (isCheckViolation,
		// internal/store/store.go) -- this is the one line that turns that
		// CHECK into a clean 400 rather than letting it fall to the default
		// 500 case below, the task brief's own explicit requirement ("the
		// database CHECK should already refuse it -- confirm the API
		// surfaces that rather than crashing").
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, store.ErrApproverNotRootPrincipal):
		// N7 (spec §4.10.1): the operator's own identity is known (it is not
		// an authentication failure -- authorize's own 401 already covers
		// that case, earlier in the request), but it does not equal this
		// approval's root_principal, so this is an authorization refusal,
		// not "fix your request." The message names the same fact
		// resolveEscalation (internal/pdpgrpc/escalation.go) reasons about
		// at consumption time -- the approver is fixed to the chain's root
		// principal -- without echoing operatorIdentity or root_principal
		// themselves (err.Error() carries only the approval id).
		http.Error(w, err.Error(), http.StatusForbidden)
	default:
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}
