// session_file.go is where "hook" (hook.go) and "session-start"
// (session_start.go) meet: writeSessionFile is the only producer of a
// session file, loadSessionFile is the only consumer, and both operate on
// exactly one shape -- *pdpgrpc.CreateDelegationResponse's JSON encoding --
// because a session file is nothing more than a cached copy of what
// CreateDelegation returned. Neither function trusts the other's side of
// that contract blindly: writeSessionFile only ever receives an RPC
// response already checked for a non-empty delegation_id, a non-nil
// granted_scope, and (as of Phase 9 Task 4) a non-empty token
// (runSessionStart, session_start.go), and loadSessionFile re-checks both
// the token and delegation_id itself on the way back in, because a session
// file is not code this binary controls end to end -- a user could hand-edit
// it, an old build could have written a different shape, or nothing may have
// ever written one at all.
//
// The token is what hook and mcp now send to Decide (spec §4.7.1 K4); the
// delegation_id travels alongside it, unused on that path, for exactly one
// other purpose -- reissue.go's reissueAndRetryDecide names it in an
// IssueToken call when the cached token has expired. Reading a delegation id
// back out of the token's own claims instead (it is the token's "sub")
// would mean decoding the token client-side, which is precisely the local
// inspection the phase's own constraints rule out for this binary -- see
// hook.go's package doc. Caching both fields side by side, exactly as
// CreateDelegation returned them, avoids that without adding a second RPC
// shape or a second file.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/stratiumdata/stratium/internal/pdpgrpc"
)

// sessionFileMode is the session file's permission bits from the instant it
// is created, not chmod'ed on afterward -- see writeSessionFile. It matches
// os.CreateTemp's own documented default (0600 before umask); the constant
// exists so that fact is asserted by name in this file rather than left
// implicit in a stdlib doc comment elsewhere.
const sessionFileMode = 0o600

// writeSessionFile atomically replaces path with resp's JSON encoding --
// delegation_id, granted_scope (including granted_scope.removed, so a later
// denial is legible against what this session actually holds rather than
// what it originally asked for), and token, exactly as CreateDelegation
// returned them. As of Phase 9 Task 4, token is the field that matters most:
// it is what hook and mcp now present to Decide, and everything path holds
// is therefore live bearer authority, not merely a record of a grant --
// anyone who can read this file can act as this session's agent until the
// token expires. sessionFileMode below is the enforcement of that; see also
// docs/pep.md for what it means for where this file may be written.
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
// invalid (empty token or empty delegation_id).
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
//
// The token check runs before the delegation_id check, not after: as of
// Phase 9 Task 4 the token is what a caller actually sends to Decide (K4),
// so an empty one is the more fundamental defect -- a session file with a
// token but no delegation_id can still authenticate every ordinary call and
// only loses the ability to reissue; one with a delegation_id but no token
// cannot even make the ordinary call. Checking token first means that more
// serious failure is never masked by the second message.
func loadSessionFile(path string) (*pdpgrpc.CreateDelegationResponse, error) {
	f, err := os.Open(path) //nolint:gosec // G304: path is operator configuration (STRATIUM_PEP_SESSION_FILE), not attacker-supplied request data
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no session file at %s -- run 'stratium-pep session-start' first", path)
		}
		return nil, fmt.Errorf("could not read session file %s: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	// writeSessionFile creates the file readable by its owner alone. A file
	// anyone else can read or write was not left that way by session-start,
	// and a file only its owner can read is, since this process just opened
	// it, this user's own. Checked on the open file, so it cannot be swapped
	// between the check and the read. Windows reports no such bits.
	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("could not read session file %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("session file %s is not a regular file", path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("session file %s is open to other users (mode %04o) -- run 'stratium-pep session-start' again",
			path, info.Mode().Perm())
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("could not read session file %s: %w", path, err)
	}

	var resp pdpgrpc.CreateDelegationResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("session file %s is malformed: %w", path, err)
	}
	if resp.GetToken() == "" {
		return nil, fmt.Errorf("session file %s has no token -- run 'stratium-pep session-start' again", path)
	}
	if resp.GetDelegationId() == "" {
		return nil, fmt.Errorf("session file %s does not name a delegation", path)
	}
	return &resp, nil
}
