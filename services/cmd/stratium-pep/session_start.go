// session_start.go implements the "session-start" subcommand: creates a
// delegation for an agent session via the PDP's CreateDelegation RPC and
// caches the result -- delegation ID, *granted* scope, and (Phase 9 Task 4)
// the token naming that delegation -- to a session file (session_file.go's
// writeSessionFile). "hook" (hook.go) and "mcp" (mcp_authorize.go) read that
// file fresh on every tool call via session_file.go's loadSessionFile, so a
// session-start or a revocation between tool calls takes effect on the very
// next one rather than waiting on a cache to expire. Of the three cached
// fields, the token is now the one an enforcement surface actually presents
// to Decide (K4); delegation ID survives alongside it only to support
// reissue.go's reissueAndRetryDecide, never sent on the wire itself.
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
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/stratiumdata/stratium/internal/pdpgrpc"
)

// sessionStartConfig is what runSessionStart needs beyond the PDP client:
// the delegation to request, and where to cache what comes back.
//
// PDPAddr, AgentID, Subject, SessionFilePath, and ConnectTimeout are the
// same five values hookConfig (hook.go) loads, by the same rule
// internal/config.Load uses for the PDP itself: every one is required, with
// no default -- a session started with a guessed identity, a guessed scope,
// or no bound on how long to wait for the PDP is worse than one that
// refuses to start. loadSessionStartConfigFromEnv below and
// loadHookConfigFromEnv (hook.go) share the small helpers in config.go
// rather than duplicating the presence-checking and parsing twice.
type sessionStartConfig struct {
	PDPAddr         string
	AgentID         string
	Subject         string
	SessionFilePath string
	ConnectTimeout  time.Duration
	RequestedTier   int32
	RequestedTools  []string
	Purpose         string
	TTLSeconds      int64

	// PrincipalToken is the principal's OIDC token, read from the file named
	// by STRATIUM_PEP_PRINCIPAL_TOKEN_FILE. Optional here: a PDP that
	// verifies principals (the default) refuses a session without it, and a
	// PDP running with that check off ignores it. A file, not an environment
	// variable, so the token is not copied into every child process's
	// environment or a crash report. Never logged.
	PrincipalToken string

	// EscalateAt is optional (STRATIUM_PEP_ESCALATE_AT). nil asks for
	// nothing, which leaves the agent's own threshold in force: a request can
	// only LOWER it (internal/pdpgrpc/escalate_at.go), never remove it.
	EscalateAt *int32
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
	var missing []string
	cfg := sessionStartConfig{
		PDPAddr:         requiredEnv("STRATIUM_PEP_PDP_ADDR", &missing),
		AgentID:         requiredEnv("STRATIUM_PEP_AGENT_ID", &missing),
		Subject:         requiredEnv("STRATIUM_PEP_SUBJECT", &missing),
		SessionFilePath: requiredEnv("STRATIUM_PEP_SESSION_FILE", &missing),
		Purpose:         os.Getenv("STRATIUM_PEP_PURPOSE"), // optional: CreateDelegation does not require one
	}

	timeoutRaw := requiredEnv("STRATIUM_PEP_CONNECT_TIMEOUT", &missing)
	tierRaw := requiredEnv("STRATIUM_PEP_REQUESTED_TIER", &missing)

	cfg.RequestedTools = splitAndTrim(os.Getenv("STRATIUM_PEP_REQUESTED_TOOLS"))
	if len(cfg.RequestedTools) == 0 {
		missing = append(missing, "STRATIUM_PEP_REQUESTED_TOOLS")
	}

	ttlRaw := requiredEnv("STRATIUM_PEP_TTL_SECONDS", &missing)

	if len(missing) > 0 {
		return sessionStartConfig{}, missingConfigError(missing)
	}

	timeout, err := requiredDuration("STRATIUM_PEP_CONNECT_TIMEOUT", timeoutRaw)
	if err != nil {
		return sessionStartConfig{}, err
	}
	cfg.ConnectTimeout = timeout

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

	// Optional, so it is not in the missing-variable sweep above. Not
	// range-checked here for the reason REQUESTED_TIER is not: CreateDelegation
	// validates it, and a second check would be a second place to drift.
	if raw := strings.TrimSpace(os.Getenv("STRATIUM_PEP_ESCALATE_AT")); raw != "" {
		v, err := strconv.ParseInt(raw, 10, 32)
		if err != nil {
			return sessionStartConfig{}, fmt.Errorf("STRATIUM_PEP_ESCALATE_AT: %w", err)
		}
		esc := int32(v)
		cfg.EscalateAt = &esc
	}

	if path := os.Getenv("STRATIUM_PEP_PRINCIPAL_TOKEN_FILE"); path != "" {
		data, err := os.ReadFile(path) //nolint:gosec // G304: operator configuration, the same trust boundary as STRATIUM_PEP_SESSION_FILE
		if err != nil {
			return sessionStartConfig{}, fmt.Errorf("STRATIUM_PEP_PRINCIPAL_TOKEN_FILE: %w", err)
		}
		cfg.PrincipalToken = strings.TrimSpace(string(data))
		if cfg.PrincipalToken == "" {
			return sessionStartConfig{}, fmt.Errorf("STRATIUM_PEP_PRINCIPAL_TOKEN_FILE: %s is empty", path)
		}
	}
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

	conn, err := dialPDP(cfg.PDPAddr)
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
			EscalateAt:    cfg.EscalateAt,
		},
		Purpose:        cfg.Purpose,
		TtlSeconds:     cfg.TTLSeconds,
		PrincipalToken: cfg.PrincipalToken,
	}

	ctx, cancel := context.WithTimeout(context.Background(), cfg.ConnectTimeout)
	defer cancel()

	resp, err := client.CreateDelegation(ctx, req)
	if err != nil {
		removeStaleSessionFile(cfg.SessionFilePath, stderr)
		_, _ = fmt.Fprintf(stderr, "stratium-pep: could not create delegation: %s\n", err)
		return 1
	}

	// Defense at the wire boundary, not a re-check of policy: the real PDP
	// (internal/pdpgrpc/delegation.go) never returns err == nil alongside an
	// empty delegation_id, a nil granted_scope, or an empty token --
	// CreateDelegationResponse's own doc comment states granted_scope.tools
	// is never empty on a response that reaches a caller, and that a
	// delegation_id reaches a caller only paired with the token that names
	// it (a signing failure fails the whole call). A response that violates
	// either invariant anyway is not safe to cache, whatever produced it --
	// and as of Phase 9 Task 4, an empty token is the one of these three that
	// matters most: it is what every later hook/mcp call actually sends to
	// Decide, so caching one anyway would not merely under-record this
	// session, it would make every subsequent tool call deny for a reason
	// this process could have caught right here instead.
	if resp.GetDelegationId() == "" || resp.GetGrantedScope() == nil || resp.GetToken() == "" {
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
