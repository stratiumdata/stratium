// session_start.go implements the "session-start" subcommand: creates a
// delegation for an agent session via the PDP's CreateDelegation RPC and
// caches the result -- delegation ID and *granted* scope -- to a session
// file. "hook" (hook.go) reads that file on every tool call once Task 3
// wires that read path (and hardens it: a missing or malformed session
// file, a connect timeout). This file only writes it.
//
// Two rules from the task brief, both enforced by construction below rather
// than by convention:
//
// Cache the GRANTED scope, not the requested one. CreateDelegation clamps a
// request to what the principal actually holds (internal/authz.Clamp) -- a
// session that asked for DESTRUCTIVE with three tools can come back
// INTERNAL_MODIFY with one. writeSessionFile is only ever handed the RPC
// *response*, never the request, so there is no code path in runSessionStart
// that could write what was asked for instead of what was granted -- not "we
// remembered to," but "the request is never in scope where the file gets
// written."
//
// Fail closed on creation failure: write no session file, and remove any
// file already there. A stale file left in place after a failed
// CreateDelegation call would be a delegation the operator believes expired,
// still authorizing work -- worse than no file at all, because hook.go
// cannot tell "no session started" from "session started yesterday" by
// looking at the same absent-file signal. removeStaleSessionFile runs on
// every failure path below, including a structurally malformed success
// response (empty delegation_id or a nil granted_scope): the real PDP
// should never send one, but a session file is exactly the kind of thing
// not to trust blindly from the wire.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"stratium/internal/pdpgrpc"
)

// createDelegationTimeout bounds the CreateDelegation RPC the same way
// decideTimeout (hook.go) bounds Decide: an unreachable or hung PDP fails
// closed in finite time instead of wedging session start forever. Task 3
// makes this configurable; this is a conservative fixed default until then.
const createDelegationTimeout = 5 * time.Second

// sessionFileMode is the session file's permission bits from the instant it
// is created, not chmod'ed on afterward -- see writeSessionFile. It matches
// os.CreateTemp's own documented default (0600 before umask); the constant
// exists so that fact is asserted by name in this file rather than left
// implicit in a stdlib doc comment elsewhere.
const sessionFileMode = 0o600

// sessionStartConfig is what runSessionStart needs beyond the PDP client:
// the delegation to request, and where to cache what comes back.
//
// Task 3 owns loading the pieces this shares with hook's own config (PDP
// address, agent ID, subject, session-file path, a connect timeout) for
// real -- see hookConfig's doc comment (hook.go) for the same rule applied
// there. loadSessionStartConfigFromEnv below is this subcommand's own
// honestly-scoped stand-in in the meantime: every value is required, with
// no default, the same rule internal/config.Load and hookConfig both use --
// a session started with a guessed identity or a guessed scope is worse
// than one that refuses to start.
type sessionStartConfig struct {
	PDPAddr         string
	AgentID         string
	Subject         string
	SessionFilePath string
	RequestedTier   int32
	RequestedTools  []string
	Purpose         string
	TTLSeconds      int64
}

// loadSessionStartConfigFromEnv reads sessionStartConfig from the
// environment, or returns an error naming every missing variable at once
// rather than stopping at the first -- see loadHookConfigFromEnv (hook.go)
// for the same convention applied to hook's config.
//
// STRATIUM_PEP_REQUESTED_TIER is deliberately not range-checked here:
// CreateDelegation already validates it (models.ParseActionTier) and a
// request outside 0-4 fails that RPC call, which runSessionStart already
// treats as any other creation failure -- fail closed, no session file.
// Duplicating the range check client-side would only be a second place for
// the two to drift apart.
func loadSessionStartConfigFromEnv() (sessionStartConfig, error) {
	cfg := sessionStartConfig{
		PDPAddr:         os.Getenv("STRATIUM_PEP_PDP_ADDR"),
		AgentID:         os.Getenv("STRATIUM_PEP_AGENT_ID"),
		Subject:         os.Getenv("STRATIUM_PEP_SUBJECT"),
		SessionFilePath: os.Getenv("STRATIUM_PEP_SESSION_FILE"),
		Purpose:         os.Getenv("STRATIUM_PEP_PURPOSE"), // optional: CreateDelegation does not require one
	}

	var missing []string
	if cfg.PDPAddr == "" {
		missing = append(missing, "STRATIUM_PEP_PDP_ADDR")
	}
	if cfg.AgentID == "" {
		missing = append(missing, "STRATIUM_PEP_AGENT_ID")
	}
	if cfg.Subject == "" {
		missing = append(missing, "STRATIUM_PEP_SUBJECT")
	}
	if cfg.SessionFilePath == "" {
		missing = append(missing, "STRATIUM_PEP_SESSION_FILE")
	}

	tierRaw := os.Getenv("STRATIUM_PEP_REQUESTED_TIER")
	if tierRaw == "" {
		missing = append(missing, "STRATIUM_PEP_REQUESTED_TIER")
	}

	cfg.RequestedTools = splitAndTrim(os.Getenv("STRATIUM_PEP_REQUESTED_TOOLS"))
	if len(cfg.RequestedTools) == 0 {
		missing = append(missing, "STRATIUM_PEP_REQUESTED_TOOLS")
	}

	ttlRaw := os.Getenv("STRATIUM_PEP_TTL_SECONDS")
	if ttlRaw == "" {
		missing = append(missing, "STRATIUM_PEP_TTL_SECONDS")
	}

	if len(missing) > 0 {
		return sessionStartConfig{}, fmt.Errorf("missing required configuration: %s", strings.Join(missing, ", "))
	}

	tier, err := strconv.ParseInt(tierRaw, 10, 32)
	if err != nil {
		return sessionStartConfig{}, fmt.Errorf("STRATIUM_PEP_REQUESTED_TIER: %w", err)
	}
	cfg.RequestedTier = int32(tier)

	ttl, err := strconv.ParseInt(ttlRaw, 10, 64)
	if err != nil {
		return sessionStartConfig{}, fmt.Errorf("STRATIUM_PEP_TTL_SECONDS: %w", err)
	}
	if ttl <= 0 {
		return sessionStartConfig{}, fmt.Errorf("STRATIUM_PEP_TTL_SECONDS must be positive, got %d", ttl)
	}
	cfg.TTLSeconds = ttl

	return cfg, nil
}

// splitAndTrim splits a comma-separated env var into trimmed, non-empty
// entries. An unset or blank variable yields a zero-length (nil) slice, so
// it reads back as "missing" the same way an unset string field does.
func splitAndTrim(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if t := strings.TrimSpace(part); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// runSessionStartCmd wires the real PDP client from environment
// configuration and runs session start. It is the only function in this
// file main's dispatch calls; everything it wires is exercised directly by
// session_start_test.go against a fake PDP server instead.
func runSessionStartCmd(stderr io.Writer) int {
	cfg, err := loadSessionStartConfigFromEnv()
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "stratium-pep: %s\n", err)
		return 1
	}

	conn, err := grpc.NewClient(cfg.PDPAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "stratium-pep: could not create PDP client: %s\n", err)
		return 1
	}
	defer func() { _ = conn.Close() }()

	return runSessionStart(pdpgrpc.NewPDPServiceClient(conn), cfg, stderr)
}

// runSessionStart calls CreateDelegation and caches the result to
// cfg.SessionFilePath. Every failure path -- the RPC itself failing, or the
// RPC succeeding with a response too malformed to trust -- removes any
// session file already at that path before returning: hook.go then finds no
// file and denies everything, the correct outcome, rather than a developer's
// laptop quietly continuing to run under a delegation the PDP never actually
// renewed. See the package doc for why that matters more than it looks.
func runSessionStart(client pdpgrpc.PDPServiceClient, cfg sessionStartConfig, stderr io.Writer) int {
	req := &pdpgrpc.CreateDelegationRequest{
		Subject: cfg.Subject,
		AgentId: cfg.AgentID,
		RequestedScope: &pdpgrpc.RequestedScope{
			MaxActionTier: cfg.RequestedTier,
			Tools:         cfg.RequestedTools,
		},
		Purpose:    cfg.Purpose,
		TtlSeconds: cfg.TTLSeconds,
	}

	ctx, cancel := context.WithTimeout(context.Background(), createDelegationTimeout)
	defer cancel()

	resp, err := client.CreateDelegation(ctx, req)
	if err != nil {
		removeStaleSessionFile(cfg.SessionFilePath, stderr)
		_, _ = fmt.Fprintf(stderr, "stratium-pep: could not create delegation: %s\n", err)
		return 1
	}

	// Defense at the wire boundary, not a re-check of policy: the real PDP
	// (internal/pdpgrpc/delegation.go) never returns err == nil alongside an
	// empty delegation_id or a nil granted_scope -- CreateDelegationResponse's
	// own doc comment states granted_scope.tools is never empty on a response
	// that reaches a caller either. A response that violates that invariant
	// anyway is not safe to cache, whatever produced it.
	if resp.GetDelegationId() == "" || resp.GetGrantedScope() == nil {
		removeStaleSessionFile(cfg.SessionFilePath, stderr)
		_, _ = fmt.Fprintln(stderr, "stratium-pep: PDP returned a malformed CreateDelegation response")
		return 1
	}

	if err := writeSessionFile(cfg.SessionFilePath, resp); err != nil {
		removeStaleSessionFile(cfg.SessionFilePath, stderr)
		_, _ = fmt.Fprintf(stderr, "stratium-pep: could not write session file: %s\n", err)
		return 1
	}

	return 0
}

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
// removes path itself on this or any other failure, per the package doc's
// fail-closed rule.
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

// removeStaleSessionFile removes any session file left at path, reporting
// (not failing on) an error doing so. The caller is already on a failure
// path when it calls this; a second, different failure here must not mask
// the first or change the exit code -- only be visible on stderr alongside
// it.
func removeStaleSessionFile(path string, stderr io.Writer) {
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		_, _ = fmt.Fprintf(stderr, "stratium-pep: could not remove stale session file %s: %s\n", path, err)
	}
}
