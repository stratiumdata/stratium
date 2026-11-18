//go:build integration

// cache_e2e_integration_test.go is the live-stack proof that the "hook"
// command has NO decision cache: every call is decided by the PDP, and
// nothing on disk can stand in for it. It runs the REAL compiled stratium-pep
// binary, exec'd as a subprocess exactly as Claude Code's PreToolUse hook and
// a real session-start would run it, against a REAL, containerized PDP
// (deploy/docker/docker-compose.yml's pdp-cache service) -- and stops that
// container for real where a proof needs an outage, never a bad address
// standing in for one (stopPDPCache/startPDPCache).
//
// What it proves:
//
//   - PDP up, a cache file beside the session file holding an ALLOW for a call
//     the PDP denies: the hook denies, and the PDP's own audit shows it made
//     that decision.
//   - A call allowed while the PDP is up is DENIED once the PDP is stopped --
//     nothing is replayed -- and the hook never creates a cache file.
//   - PDP stopped, a cache file holding an ALLOW for the call: denied.
//
// The cache that does exist -- mcp's, in process memory -- has its validity
// rules (epoch, token expiry, staleness window) covered at the unit level in
// cmd/stratium-pep; they have no hook-mode behavior left to prove here.
//
// package main (cmd/stratium-pep) cannot be imported -- Go forbids importing
// package main from anywhere -- so exec'ing the real compiled artifact is the
// only way anything in this package could drive hook.go's runHook or
// session_start.go's runSessionStart at all. Every fixture below is built
// through THIS package's own existing seedAgent/seedPolicy/withTenantTx
// (store_integration_test.go).
//
// pdp-cache (docker-compose.yml) is the first PDP instance in this whole
// stack any test is allowed to actually stop -- see that service's own
// comment for why every PDP instance before it is off limits.
//
// Every proof below uses tool "Read" only: internal/authz's DefaultCatalog
// (catalog.go) fixes "Read" at READ_ONLY regardless of RawInput content, so
// every hook call derives the identical, known-safe tier no matter what
// tool_input JSON body it carries.
package store_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/stratiumdata/stratium/internal/pdpgrpc"
	"github.com/stratiumdata/stratium/pkg/models"
)

// ---------------------------------------------------------------------------
// Building and running the real stratium-pep binary.

var (
	pepBinaryOnce sync.Once
	pepBinaryPath string
	pepBinaryErr  error
)

// servicesModuleRoot returns the absolute path to the services/ module root
// (the directory holding go.mod), resolved via runtime.Caller rather than
// os.Getwd -- go test sets the working directory to this package
// (internal/store), not the module root -- mirroring conformance_pointer_test.go's
// own servicesRoot() in internal/authz. This file lives two directories below
// services/ (internal/store), the same depth as internal/authz, so climbing
// two levels reaches it identically.
func servicesModuleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not resolve this file's own path")
	}
	return filepath.Join(filepath.Dir(file), "..", "..")
}

// composeFilePath returns the absolute path to deploy/docker/docker-compose.yml
// -- one level above servicesModuleRoot, the same repo-root-relative location
// the Makefile's own COMPOSE variable names.
func composeFilePath(t *testing.T) string {
	t.Helper()
	return filepath.Join(servicesModuleRoot(t), "..", "deploy", "docker", "docker-compose.yml")
}

// stratiumPEPBinary builds cmd/stratium-pep once for this whole test binary
// run (sync.Once -- nothing about which proof below runs first, or how many
// run, changes what gets built) and returns its path.
//
// Built into the OS temp directory, not t.TempDir(): the first caller's own
// t.TempDir() is removed the instant THAT test finishes, which would take
// the binary down with it for every proof after it -- this file needs the
// SAME binary reachable from five independent top-level Test functions.
//
// ponytail: the build directory is never removed. A few-megabyte static Go
// binary left in the OS temp dir costs nothing on an ephemeral CI runner or a
// developer machine that already clears /tmp on its own schedule, and
// threading a package-scoped cleanup through TestMain for one test file's own
// build artifact is more machinery than the problem is worth.
func stratiumPEPBinary(t *testing.T) string {
	t.Helper()
	pepBinaryOnce.Do(func() {
		dir, err := os.MkdirTemp("", "stratium-pep-cache-e2e-*")
		if err != nil {
			pepBinaryErr = fmt.Errorf("create build dir: %w", err)
			return
		}
		out := filepath.Join(dir, "stratium-pep")

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", "build", "-o", out, "./cmd/stratium-pep")
		cmd.Dir = servicesModuleRoot(t)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			pepBinaryErr = fmt.Errorf("go build ./cmd/stratium-pep: %w: %s", err, stderr.String())
			return
		}
		pepBinaryPath = out
	})
	if pepBinaryErr != nil {
		t.Fatalf("stratium-pep binary: %v", pepBinaryErr)
	}
	return pepBinaryPath
}

// runPEPSubcommand execs the real compiled stratium-pep binary with the given
// subcommand, env layered over this test process's own environment
// (os.Environ() -- the binary needs nothing else from it, but starting from a
// clean slate risks missing something the OS or Go runtime itself expects for
// no benefit this task needs). stdin is fed verbatim; stdout is captured and
// returned alongside the real process exit code -- 0/2 for "hook" (hook.go's
// own contract), 0/1 for "session-start" (session_start.go's own contract).
//
// stderr is RETURNED rather than discarded, which it was until Phase 15 Task
// 7. "session-start" writes its diagnostics there; "hook" does not — dispatch
// hands it no stderr writer (main.go) and every failure it has a contract for
// goes through writeDeny to stdout. What lands here for "hook" is what escapes
// that contract: a panic, a loader failure, a runtime message. Those are
// exactly the failures worth reading, and they were the ones being discarded.
// A caller that fatalled
// on an unexpected exit code could previously report only "exit = 1; stdout: "
// -- with an empty stdout and no cause at all. That is not hypothetical: a
// session-start failed exactly that way during one integration sweep and left
// nothing to diagnose it with. It stays a separate return value rather than
// being folded into stdout because callHook parses stdout as JSON and must not
// have diagnostics mixed into it.
func runPEPSubcommand(t *testing.T, subcommand string, env map[string]string, stdin string) (stdout, stderr string, exitCode int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, stratiumPEPBinary(t), subcommand)
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut

	err := cmd.Run()
	if err == nil {
		return out.String(), errOut.String(), 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return out.String(), errOut.String(), exitErr.ExitCode()
	}
	t.Fatalf("stratium-pep %s: %v (stderr: %s)", subcommand, err, errOut.String())
	return "", "", -1
}

// ---------------------------------------------------------------------------
// Stopping and restarting pdp-cache for real.

// dockerComposePDPCache runs `docker compose -f <compose file> <args...>`
// against the exact project `make integration` already brought up -- the
// project name is the compose file's own directory basename ("docker" --
// deploy/docker/docker-compose.yml carries no `name:` override), which
// depends only on the resolved path to that file, not this test binary's own
// working directory -- so this targets the SAME running containers
// regardless of where `go test` happens to execute from -- and returns its
// combined output for the one caller that needs to parse it (pdpCacheHostPort,
// below).
//
// context.Background(), not t.Context(): startPDPCache (below) calls this
// from a t.Cleanup callback, which runs after t's own context is canceled --
// a docker command that needed t's context to still be live would fail
// exactly there, the one place it is not allowed to.
func dockerComposePDPCache(t *testing.T, args ...string) string {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Fatalf("docker not found on PATH: %v -- these proofs need docker compose to stop/start a real container", err)
	}
	full := append([]string{"compose", "-f", composeFilePath(t)}, args...)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", full...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker %s: %v: %s", strings.Join(full, " "), err, out)
	}
	return string(out)
}

// pdpCacheHostPort queries the CURRENT host address pdp-cache's container
// port 50051 is published on, in the identical "host:port" shape the
// Makefile's own integration target already builds (STRATIUM_IT_PDP_CACHE_ADDR).
//
// Re-queried after every restart, never trusted from an earlier call:
// confirmed live, not assumed, that Docker does NOT preserve a dynamically
// assigned host port (this compose file's own deliberate choice -- see its
// header comment -- to avoid colliding with a developer's own services)
// across a stop/start cycle on the SAME container. A stopped container's
// ephemeral port mapping is released, and `docker compose start` allocates a
// fresh one on the very next start; a run that stopped pdp-cache at
// 0.0.0.0:58907 came back at 0.0.0.0:58916, not the same port, the first
// time this file actually ran against the real stack. cacheAddr (store_
// integration_test.go's own package var, set once by TestMain's initial
// dial) is therefore only ever accurate up to the FIRST restart; every proof
// below that stops pdp-cache re-resolves this afterward instead of trusting
// what TestMain captured before any of them ran.
func pdpCacheHostPort(t *testing.T) string {
	t.Helper()
	out := dockerComposePDPCache(t, "port", "pdp-cache", "50051")
	addr := strings.TrimSpace(out)
	idx := strings.LastIndex(addr, ":")
	if idx < 0 {
		t.Fatalf("docker compose port pdp-cache 50051 returned unparseable output: %q", addr)
	}
	return "localhost:" + addr[idx+1:]
}

// stopPDPCache stops the pdp-cache container entirely -- a real
// `docker compose stop`, never a bad address, per this task's own
// requirement that outage tolerance be proven by actually removing the PDP's
// ability to answer. -t 2 keeps the grace period short: stratium-pdp's own
// shutdown handling is not what these proofs are about, and a fast SIGKILL
// after a brief SIGTERM window still counts as "stopped" for everything
// below.
//
// t.Cleanup is registered BEFORE stopping, not after, so a t.Fatal partway
// through the calling proof still restarts pdp-cache for whatever test runs
// next in this file. `docker compose down -v --remove-orphans` (the
// Makefile's own integration target) tears this container down regardless of
// whether it happens to be running or stopped when that runs -- this restart
// is about keeping OTHER proofs in this file unaffected, not about final
// teardown.
func stopPDPCache(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { startPDPCache(t) })
	dockerComposePDPCache(t, "stop", "-t", "2", "pdp-cache")
}

// startPDPCache starts pdp-cache back up, re-resolves its (possibly new --
// pdpCacheHostPort's own doc comment) host address, redials, and blocks
// until its health service reports SERVING again (waitForServing,
// store_integration_test.go -- the same function TestMain's own initial dial
// already uses). Updates the package-level cacheConn/cacheAddr (store_
// integration_test.go) so every proof after this one -- via
// cacheProofBaseEnv's own read of cacheAddr -- reaches the container that is
// actually listening, not the port it happened to be listening on before
// this restart. A proof that called this can rely on pdp-cache being
// genuinely reachable at cacheAddr the moment it returns, not merely that
// the `start` command exited.
func startPDPCache(t *testing.T) {
	t.Helper()
	dockerComposePDPCache(t, "start", "pdp-cache")
	newAddr := pdpCacheHostPort(t)

	conn, err := grpc.NewClient(newAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("re-dial pdp-cache at %s: %v", newAddr, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := waitForServing(ctx, conn); err != nil {
		t.Fatalf("pdp-cache at %s did not report SERVING after restart: %v", newAddr, err)
	}

	old := cacheConn
	cacheConn = conn
	cacheAddr = newAddr
	if old != nil {
		_ = old.Close()
	}
}

// ---------------------------------------------------------------------------
// Fixtures: a real session (via the real "session-start" subcommand) and a
// real hook decision (via the real "hook" subcommand).

// cacheProofBaseEnv is every env var both "session-start" and "hook" need,
// common across every proof below: identity (agentID/subject), where to
// reach pdp-cache (its HOST-published port, from STRATIUM_IT_PDP_CACHE_ADDR
// -- see the Makefile's own integration target), the session file this proof
// owns alone (t.TempDir()), and a connect timeout short enough that a stopped
// pdp-cache fails fast rather than risking this test's own subprocess
// budget.
func cacheProofBaseEnv(agentID uuid.UUID, subject, sessionFile string) map[string]string {
	return map[string]string{
		"STRATIUM_PEP_PDP_ADDR":               cacheAddr,
		"STRATIUM_PEP_PDP_INSECURE":           "true", // the compose PDPs serve plaintext
		"STRATIUM_PEP_AGENT_ID":               agentID.String(),
		"STRATIUM_PEP_SUBJECT":                subject,
		"STRATIUM_PEP_SESSION_FILE":           sessionFile,
		"STRATIUM_PEP_CONNECT_TIMEOUT":        "5s",
		"STRATIUM_PEP_APPROVAL_POLL_INTERVAL": "200ms",
		"STRATIUM_PEP_APPROVAL_TIMEOUT":       "5s",
	}
}

// newCacheSessionFile returns a fresh path for a session file this test
// alone owns (t.TempDir()).
func newCacheSessionFile(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "session.json")
}

// startCacheSession runs the real "session-start" subcommand against
// sessionFile -- a real CreateDelegation call against pdp-cache -- and
// returns the delegation id from that same response, read back exactly as
// session_file.go's own loadSessionFile would (without importing package
// main -- see the package doc for why that import is impossible, not merely
// avoided).
//
// MaxActionTier/Tools match revocation_epoch_e2e_integration_test.go's own
// proven-safe combination (models.ActionTierInternalModify, an agent seeded
// at models.TrustTierUnverified, tool "Read") exactly, rather than a fresh
// choice this file would have to re-justify.
func startCacheSession(t *testing.T, sessionFile string, agentID uuid.UUID, subject string, ttlSeconds int64) (delegationID string) {
	t.Helper()
	env := cacheProofBaseEnv(agentID, subject, sessionFile)
	env["STRATIUM_PEP_REQUESTED_TIER"] = fmt.Sprintf("%d", int32(models.ActionTierInternalModify))
	env["STRATIUM_PEP_REQUESTED_TOOLS"] = "Read"
	env["STRATIUM_PEP_TTL_SECONDS"] = fmt.Sprintf("%d", ttlSeconds)
	env["STRATIUM_PEP_PURPOSE"] = "integration test: hook has no decision cache"

	stdout, stderr, code := runPEPSubcommand(t, "session-start", env, "")
	if code != 0 {
		t.Fatalf("stratium-pep session-start exit = %d, want 0; stdout: %q; stderr: %s", code, stdout, stderr)
	}

	data, err := os.ReadFile(sessionFile) //nolint:gosec // G304: sessionFile is this test's own t.TempDir() path, not attacker input
	if err != nil {
		t.Fatalf("read session file written by session-start: %v", err)
	}
	var resp pdpgrpc.CreateDelegationResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("decode session file: %v", err)
	}
	if resp.GetDelegationId() == "" {
		t.Fatal("session file has no delegation_id")
	}
	return resp.GetDelegationId()
}

// callHook runs the real "hook" subcommand once, exactly as Claude Code's
// PreToolUse contract does: JSON on stdin naming tool_name and tool_input,
// exit 0 (ALLOW, nothing on stdout) or 2 (DENY, hookSpecificOutput JSON) on
// stdout.
func callHook(t *testing.T, agentID uuid.UUID, subject, sessionFile, tool, input string) (exitCode int, reason string) {
	t.Helper()
	env := cacheProofBaseEnv(agentID, subject, sessionFile)
	stdin := fmt.Sprintf(`{"tool_name":%q,"tool_input":%s}`, tool, input)

	stdout, stderr, code := runPEPSubcommand(t, "hook", env, stdin)
	if code == 0 {
		return 0, ""
	}
	var out struct {
		HookSpecificOutput struct {
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("decode hook deny output %q (exit %d; stderr: %s): %v", stdout, code, stderr, err)
	}
	return code, out.HookSpecificOutput.PermissionDecisionReason
}

// legacyCacheFilePath is where versions before the in-memory cache kept
// decisions: beside the session file.
func legacyCacheFilePath(sessionFile string) string {
	return sessionFile + ".cache.json"
}

// writeForgedAllowCacheFile writes a cache file, in the JSON shape those
// older versions read, holding one fresh ALLOW for exactly (delegationID,
// tool, input). Written AFTER session-start, which removes any such file.
func writeForgedAllowCacheFile(t *testing.T, sessionFile, delegationID, tool, input string) {
	t.Helper()
	now := time.Now()
	data, err := json.Marshal([]map[string]any{{
		"delegation_id":         delegationID,
		"tool":                  tool,
		"input_digest":          sha256.Sum256([]byte(input)),
		"decision":              int32(pdpgrpc.Effect_EFFECT_ALLOW),
		"epoch":                 1,
		"delegation_expires_at": now.Add(48 * time.Hour),
		"cached_at":             now.Add(-time.Minute),
	}})
	if err != nil {
		t.Fatalf("marshal forged cache file: %v", err)
	}
	if err := os.WriteFile(legacyCacheFilePath(sessionFile), data, 0o600); err != nil {
		t.Fatalf("write forged cache file: %v", err)
	}
}

// hookDecisions returns the decision the PDP itself recorded for each Decide
// it received from agentID, oldest first -- the PDP's own account of what it
// decided, independent of anything the hook reported.
func hookDecisions(t *testing.T, agentID uuid.UUID) []string {
	t.Helper()
	var out []string
	withTenantTx(t, cacheTenant, func(tx *sql.Tx) {
		rows, err := tx.QueryContext(t.Context(),
			`SELECT decision FROM audit_chain WHERE event_type = 'decision' AND agent_id = $1 ORDER BY seq ASC`,
			agentID.String())
		if err != nil {
			t.Fatalf("query audit_chain: %v", err)
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var decision string
			if err := rows.Scan(&decision); err != nil {
				t.Fatalf("scan audit_chain row: %v", err)
			}
			out = append(out, decision)
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("iterate audit_chain: %v", err)
		}
	})
	return out
}

// assertPDPUnreachableReason checks a deny reason names a PDP that could not
// be consulted. It accepts both transport outcomes a stopped container
// produces, because which one occurs depends on how Docker tears the socket
// down, not on this system: a refused connection is codes.Unavailable ("could
// not reach PDP"), a dropped one hangs until the PEP's ConnectTimeout and is
// codes.DeadlineExceeded ("PDP did not respond in time"). Both were measured
// on one host. Asserting a single wording made this flake on a real clock.
// Anything else (an unknown agent, a generic application error) would mean
// the call reached a PDP that ANSWERED.
func assertPDPUnreachableReason(t *testing.T, reason string) {
	t.Helper()
	if !strings.Contains(reason, "could not reach PDP") && !strings.Contains(reason, "PDP did not respond in time") {
		t.Errorf("reason = %q, want it to name a PDP that could not be reached or did not respond in time", reason)
	}
	if strings.Contains(strings.ToLower(reason), "cache") {
		t.Errorf("reason = %q, want no mention of a cache -- hook mode has none", reason)
	}
}

// ---------------------------------------------------------------------------
// The proofs.

// TestIntegration_Hook_E2E_ForgedCacheFile_PDPUp_PDPDecides: the PDP denies
// a call (its delegation is revoked -- a raw SQL UPDATE, the only way a real
// revocation happens in this system today) while a cache file beside the
// session file holds an ALLOW for exactly that call. The hook must deny, and
// the PDP's own audit must show a DENY for this agent: the decision was the
// PDP's, not the file's.
func TestIntegration_Hook_E2E_ForgedCacheFile_PDPUp_PDPDecides(t *testing.T) {
	const subject = "cache-proof-a@example.com"
	agentID := uuid.New()
	seedAgent(t, cacheTenant, agentID, "integration-agent-cache-proof-a", models.TrustTierUnverified)
	seedPolicy(t, cacheTenant, "cache-proof-a-permit",
		fmt.Sprintf(`permit(principal == User::"%s", action, resource);`, subject), "allow")
	sessionFile := newCacheSessionFile(t)
	delegationID := startCacheSession(t, sessionFile, agentID, subject, 3600)
	const input = `{"path":"/tmp/cache-proof-a.txt"}`

	withTenantTx(t, cacheTenant, func(tx *sql.Tx) {
		if _, err := tx.ExecContext(t.Context(),
			`UPDATE delegations SET revoked = true, revoked_at = NOW() WHERE id = $1`, delegationID); err != nil {
			t.Fatalf("UPDATE delegations (revoke): %v", err)
		}
	})
	writeForgedAllowCacheFile(t, sessionFile, delegationID, "Read", input)

	code, reason := callHook(t, agentID, subject, sessionFile, "Read", input)
	if code != 2 {
		t.Fatalf("hook exit = %d, want 2 (DENY) -- the PDP denies this call, and a cache file holding an "+
			"ALLOW for it must change nothing; reason: %q", code, reason)
	}
	decisions := hookDecisions(t, agentID)
	if len(decisions) == 0 {
		t.Fatalf("the PDP recorded no decision for this agent -- the hook denied without asking it")
	}
	for _, d := range decisions {
		if d != "DENY" {
			t.Errorf("the PDP recorded decision %q for this agent, want only DENY; all: %v", d, decisions)
		}
	}
}

// TestIntegration_Hook_E2E_PDPStopped_DeniesACallAllowedWhileUp: the same
// call the PDP allowed a moment ago is denied once the PDP is stopped.
// Nothing is replayed, and the hook leaves no cache file behind to replay
// from.
func TestIntegration_Hook_E2E_PDPStopped_DeniesACallAllowedWhileUp(t *testing.T) {
	const subject = "cache-proof-b@example.com"
	agentID := uuid.New()
	seedAgent(t, cacheTenant, agentID, "integration-agent-cache-proof-b", models.TrustTierUnverified)
	seedPolicy(t, cacheTenant, "cache-proof-b-permit",
		fmt.Sprintf(`permit(principal == User::"%s", action, resource);`, subject), "allow")
	sessionFile := newCacheSessionFile(t)
	startCacheSession(t, sessionFile, agentID, subject, 3600)
	const input = `{"path":"/tmp/cache-proof-b.txt"}`

	code, reason := callHook(t, agentID, subject, sessionFile, "Read", input)
	if code != 0 {
		t.Fatalf("call 1 (PDP up) exit = %d, want 0 (ALLOW); reason: %q", code, reason)
	}
	entries, err := os.ReadDir(filepath.Dir(sessionFile))
	if err != nil {
		t.Fatalf("read session dir: %v", err)
	}
	for _, e := range entries {
		if e.Name() != filepath.Base(sessionFile) {
			t.Errorf("the hook left %q beside the session file, want nothing written -- hook mode keeps no cache", e.Name())
		}
	}

	stopPDPCache(t)

	code, reason = callHook(t, agentID, subject, sessionFile, "Read", input)
	if code != 2 {
		t.Fatalf("call 2 (SAME request, pdp-cache stopped) exit = %d, want 2 (DENY) -- a hook call is "+
			"decided by the PDP or not at all; reason: %q", code, reason)
	}
	assertPDPUnreachableReason(t, reason)
}

// TestIntegration_Hook_E2E_ForgedCacheFile_PDPStopped_Denies: with the PDP
// stopped, a cache file holding an ALLOW for the call still buys nothing.
func TestIntegration_Hook_E2E_ForgedCacheFile_PDPStopped_Denies(t *testing.T) {
	const subject = "cache-proof-c@example.com"
	agentID := uuid.New()
	seedAgent(t, cacheTenant, agentID, "integration-agent-cache-proof-c", models.TrustTierUnverified)
	seedPolicy(t, cacheTenant, "cache-proof-c-permit",
		fmt.Sprintf(`permit(principal == User::"%s", action, resource);`, subject), "allow")
	sessionFile := newCacheSessionFile(t)
	delegationID := startCacheSession(t, sessionFile, agentID, subject, 3600)
	const input = `{"path":"/tmp/cache-proof-c.txt"}`
	writeForgedAllowCacheFile(t, sessionFile, delegationID, "Read", input)

	stopPDPCache(t)

	code, reason := callHook(t, agentID, subject, sessionFile, "Read", input)
	if code != 2 {
		t.Fatalf("hook exit = %d, want 2 (DENY) -- pdp-cache is stopped, and a cache file holding an ALLOW "+
			"for this call must not be served; reason: %q", code, reason)
	}
	assertPDPUnreachableReason(t, reason)
}
