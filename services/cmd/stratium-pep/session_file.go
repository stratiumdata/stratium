// session_file.go is where "hook" (hook.go) and "session-start"
// (session_start.go) meet: writeSessionFile is the only producer of a
// session file, loadSessionFile is the only consumer, and both operate on
// exactly one shape -- *pdpgrpc.CreateDelegationResponse's JSON encoding --
// because a session file is nothing more than a cached copy of what
// CreateDelegation returned. Neither function trusts the other's side of
// that contract blindly: writeSessionFile only ever receives an RPC
// response already checked for a non-empty delegation_id and a non-nil
// granted_scope (runSessionStart, session_start.go), and loadSessionFile
// re-checks delegation_id itself on the way back in, because a session file
// is not code this binary controls end to end -- a user could hand-edit it,
// an old build could have written a different shape, or nothing may have
// ever written one at all.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"stratium/internal/pdpgrpc"
)

// sessionFileMode is the session file's permission bits from the instant it
// is created, not chmod'ed on afterward -- see writeSessionFile. It matches
// os.CreateTemp's own documented default (0600 before umask); the constant
// exists so that fact is asserted by name in this file rather than left
// implicit in a stdlib doc comment elsewhere.
const sessionFileMode = 0o600

// writeSessionFile atomically replaces path with resp's JSON encoding --
// delegation_id and granted_scope exactly as CreateDelegation returned them,
// including granted_scope.removed, so a later denial is legible against what
// this session actually holds rather than what it originally asked for.
//
// "Atomically" is the mechanism behind two requirements at once: path is
// never observed half-written (the encoding is built up in a temp file in
// the same directory first, and only replaces path via a single rename once
// that write is known-good, so a write failure midway never leaves a
// truncated or partial file at path), and path is mode sessionFileMode from
// the instant it exists rather than chmod'ed after (os.CreateTemp already
// creates with exactly that mode, before umask). Any failure here removes
// the temp file and leaves path untouched; the caller (runSessionStart)
// removes path itself on this or any other failure, per session_start.go's
// package doc's fail-closed rule.
func writeSessionFile(path string, resp *pdpgrpc.CreateDelegationResponse) error {
	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("encode session file: %w", err)
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(filepath.Dir(path), ".stratium-pep-session-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp session file: %w", err)
	}
	// A successful rename below moves tmp's name to path, so this Remove is
	// a harmless no-op (ENOENT) on the success path -- it only ever does real
	// work on an error return, where it discards the half-written temp file
	// rather than leaving it behind as debris in the session directory.
	defer func() { _ = os.Remove(tmp.Name()) }()

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp session file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp session file: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("rename temp session file into place: %w", err)
	}
	return nil
}

// loadSessionFile reads and decodes the session file writeSessionFile wrote,
// or reports why it could not: absent, malformed JSON, or structurally
// invalid (empty delegation_id).
//
// Every error here is a fail-closed reason, not a fatal one -- the caller
// (runHook, hook.go) turns any non-nil error into a deny -- and each message
// is written for the person seeing that deny, not just for a log: it says
// what to do ("run session-start") or names what is wrong (a corrupt file),
// rather than a single flat "session invalid" that would leave a developer
// guessing whether this is a misconfiguration, a stale session, or a bug.
// No session file (never started, or already ended) and a corrupt one
// deliberately produce different text for exactly that reason, even though
// both deny -- see hook.go's fail-closed test matrix.
func loadSessionFile(path string) (*pdpgrpc.CreateDelegationResponse, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: path is operator configuration (STRATIUM_PEP_SESSION_FILE), not attacker-supplied request data -- the same trust level as internal/config.Config's own file/URL fields
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no session file at %s -- run 'stratium-pep session-start' first", path)
		}
		return nil, fmt.Errorf("could not read session file %s: %w", path, err)
	}

	var resp pdpgrpc.CreateDelegationResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("session file %s is malformed: %w", path, err)
	}
	if resp.GetDelegationId() == "" {
		return nil, fmt.Errorf("session file %s does not name a delegation", path)
	}
	return &resp, nil
}
