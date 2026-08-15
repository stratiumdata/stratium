//go:build integration

// cache_e2e_integration_test.go is Task 4's live-stack proof for the PEP
// decision cache (Phase 13 Tasks 1-3; spec §4.8, §4.8.2, §4.8.3 W6):
// .superpowers/sdd/2026-08-14-phase-13-decision-cache/task-4-brief.md's six
// numbered proofs, run against a REAL, containerized PDP (deploy/docker/
// docker-compose.yml's pdp-cache service) and the REAL compiled stratium-pep
// binary, exec'd as a subprocess exactly as Claude Code's PreToolUse hook and
// a real session-start would run it -- not runHook called in-process against
// a fake PDP (cmd/stratium-pep's own hook_cache_test.go/local_cache_test.go
// already do that at the unit level, and Task 3's own report cites those as
// the mutation-tested proof the WIRING is correct), and never a bad address
// standing in for an outage, which proves the client's error path and
// nothing about the feature itself (this task's own brief, restated at every
// proof below that stops pdp-cache).
//
// package main (cmd/stratium-pep) cannot be imported -- Go forbids importing
// package main from anywhere -- so exec'ing the real compiled artifact is not
// a workaround, it is the only way anything in this package could drive
// hook.go's runHook or session_start.go's runSessionStart at all. That also
// means every fixture below is built through THIS package's own existing
// seedAgent/seedPolicy/withTenantTx (store_integration_test.go), exactly like
// every one of this file's seven sibling PDP instances -- no second, cache-
// specific copy of any of them exists in cmd/stratium-pep.
//
// pdp-cache (docker-compose.yml) is the first PDP instance in this whole
// stack any test is allowed to actually stop -- see that service's own
// comment for why every PDP instance before it is off limits. Proofs 2, 3, 5,
// and 6 below do exactly that, always via a real `docker compose stop`, never
// a bad address (stopPDPCache/startPDPCache).
//
// Sorts before store_integration_test.go alphabetically, deliberately, for
// the identical reason catalog_/escalation_/extauthz_/proxy_/revocation_epoch_e2e_
// already do (see revocation_epoch_e2e_integration_test.go's own package doc
// for the fullest account): TestEndToEnd's own last subtest permanently
// revokes the serving role's INSERT on audit_chain for the rest of that
// postgres instance's life -- role-level, not tenant-scoped -- which would
// turn every live Decide/CreateDelegation call this file makes, on
// tenant-cache-integration included, into an audit-write failure instead of a
// real decision, if this file's name sorted after it.
//
// Phase 14 Task 8 removed that constraint: proof6 now restores both grants
// in a t.Cleanup and verifies they came back (restoreAuditChainInsert,
// store_integration_test.go), so the revoke lasts only for that subtest and
// this file's name is no longer load-bearing. Kept as it is because there is
// no reason to churn it.
//
// Every proof below uses tool "Read" only, deliberately, never a second tool
// name: internal/authz's DefaultCatalog (catalog.go) fixes "Read" at
// READ_ONLY regardless of RawInput content (the catalog step runs before
// BuiltinTier in DeriveTier's resolution order), so every hook call below
// derives the identical, known-safe tier no matter what tool_input JSON body
// it carries -- a second cache key never needs a second tool, only a
// different tool_input.
package store_test

import (
	"bytes"
	"context"
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

	"stratium/internal/pdpgrpc"
	"stratium/pkg/models"
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
func runPEPSubcommand(t *testing.T, subcommand string, env map[string]string, stdin string) (stdout string, exitCode int) {
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
		return out.String(), 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return out.String(), exitErr.ExitCode()
	}
	t.Fatalf("stratium-pep %s: %v (stderr: %s)", subcommand, err, errOut.String())
	return "", -1
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
// owns alone (t.TempDir(), so no proof's cache file -- cacheFilePathFor
// derives it from the session file's own path, local_cache.go -- can ever
// collide with another's), and a connect timeout short enough that a stopped
// pdp-cache fails fast rather than risking this test's own subprocess
// budget.
func cacheProofBaseEnv(agentID uuid.UUID, subject, sessionFile string) map[string]string {
	return map[string]string{
		"STRATIUM_PEP_PDP_ADDR":               cacheAddr,
		"STRATIUM_PEP_AGENT_ID":               agentID.String(),
		"STRATIUM_PEP_SUBJECT":                subject,
		"STRATIUM_PEP_SESSION_FILE":           sessionFile,
		"STRATIUM_PEP_CONNECT_TIMEOUT":        "5s",
		"STRATIUM_PEP_APPROVAL_POLL_INTERVAL": "200ms",
		"STRATIUM_PEP_APPROVAL_TIMEOUT":       "5s",
	}
}

// newCacheSessionFile returns a fresh path for a session file this test
// alone owns (t.TempDir(), so no proof's cache file -- cacheFilePathFor
// derives it from the session file's own path, local_cache.go -- can ever
// collide with another's), for the common case of one proof, one delegation.
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
// sessionFile is a caller-supplied path, not always a fresh one: proof 4
// (TestIntegration_Cache_E2E_EpochBumpInvalidatesCachedEntry) deliberately
// calls this TWICE at the SAME path, for two DIFFERENT delegations, and
// needs its own doc comment there for why -- cacheFilePathFor derives the
// cache file from this path alone, so two delegations sharing one path is
// the only way to land both of their entries in the SAME cache file.
//
// ttlSeconds is a parameter, not a fixed constant: proof 5 (expired token)
// needs a real, short-lived token that actually expires in wall-clock time;
// every other proof needs one that outlives the whole test.
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
	env["STRATIUM_PEP_PURPOSE"] = "integration test: Task 4 decision-cache live proof"

	stdout, code := runPEPSubcommand(t, "session-start", env, "")
	if code != 0 {
		t.Fatalf("stratium-pep session-start exit = %d, want 0; stdout: %s", code, stdout)
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
// stdout. staleness is a parameter for the identical reason ttlSeconds is on
// startCacheSession above: proof 6 needs a staleness window short enough to
// actually elapse in wall-clock time within this test.
func callHook(t *testing.T, agentID uuid.UUID, subject, sessionFile, staleness, tool, input string) (exitCode int, reason string) {
	t.Helper()
	env := cacheProofBaseEnv(agentID, subject, sessionFile)
	env["STRATIUM_PEP_CACHE_STALENESS_WINDOW"] = staleness
	stdin := fmt.Sprintf(`{"tool_name":%q,"tool_input":%s}`, tool, input)

	stdout, code := runPEPSubcommand(t, "hook", env, stdin)
	if code == 0 {
		return 0, ""
	}
	var out struct {
		HookSpecificOutput struct {
			PermissionDecisionReason string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil {
		t.Fatalf("decode hook deny output %q: %v", stdout, err)
	}
	return code, out.HookSpecificOutput.PermissionDecisionReason
}

// ---------------------------------------------------------------------------
// The six proofs (task-4-brief.md).

// TestIntegration_Cache_E2E_HitServesWithPDPStopped is proofs 1 AND 2
// together. The task brief allows proof 1's "not merely that the answer
// matched" bar to be met either by asserting the PDP's own call count or by
// stopping its container -- and against a REAL pdp-cache, which exposes no
// call-count instrumentation the way pdp_fake_test.go's fake PDP does for
// cmd/stratium-pep's own unit-level cache tests, a stopped container is the
// ONLY mechanism available here, which is exactly the mechanism proof 2
// requires anyway (the brief's own words: "actually stopping the container
// rather than simulating unreachability with a bad address"). One test
// proves both, honestly, rather than manufacturing a second, weaker
// mechanism (log scraping, say) for proof 1 alone just to keep the two
// visibly separate.
func TestIntegration_Cache_E2E_HitServesWithPDPStopped(t *testing.T) {
	const subject = "cache-proof-a@example.com"
	agentID := uuid.New()
	seedAgent(t, cacheTenant, agentID, "integration-agent-cache-proof-a", models.TrustTierUnverified)
	seedPolicy(t, cacheTenant, "cache-proof-a-permit",
		fmt.Sprintf(`permit(principal == User::"%s", action, resource);`, subject), "allow")
	sessionFile := newCacheSessionFile(t)
	startCacheSession(t, sessionFile, agentID, subject, 3600)
	const input = `{"path":"/tmp/cache-proof-a.txt"}`

	code, reason := callHook(t, agentID, subject, sessionFile, "1h", "Read", input)
	if code != 0 {
		t.Fatalf("call 1 (PDP up, populates the cache) exit = %d, want 0 (ALLOW); reason: %q", code, reason)
	}

	stopPDPCache(t)

	code, reason = callHook(t, agentID, subject, sessionFile, "1h", "Read", input)
	if code != 0 {
		t.Fatalf("call 2 (SAME request, pdp-cache fully stopped) exit = %d, want 0 -- a valid cache entry "+
			"must serve with the PDP genuinely unreachable, proving both that this call never contacted it "+
			"(proof 1) and that the outage-tolerance promise holds (proof 2); reason: %q", code, reason)
	}
}

// TestIntegration_Cache_E2E_NoEntry_PDPStopped_Denies is proof 3, and C19's
// most direct live-stack evidence: a fresh delegation, a fresh (therefore
// EMPTY) cache file, and pdp-cache stopped before the only hook call this
// proof ever makes -- there is no entry to be valid or invalid, and no PDP to
// fall back on either.
func TestIntegration_Cache_E2E_NoEntry_PDPStopped_Denies(t *testing.T) {
	const subject = "cache-proof-b@example.com"
	agentID := uuid.New()
	seedAgent(t, cacheTenant, agentID, "integration-agent-cache-proof-b", models.TrustTierUnverified)
	seedPolicy(t, cacheTenant, "cache-proof-b-permit",
		fmt.Sprintf(`permit(principal == User::"%s", action, resource);`, subject), "allow")
	sessionFile := newCacheSessionFile(t)
	startCacheSession(t, sessionFile, agentID, subject, 3600)

	stopPDPCache(t)

	code, reason := callHook(t, agentID, subject, sessionFile, "1h", "Read", `{"path":"/tmp/cache-proof-b.txt"}`)
	if code != 2 {
		t.Fatalf("hook call (no cache entry, pdp-cache stopped) exit = %d, want 2 (DENY) -- C19: every surface "+
			"must deny with the PDP unreachable and no valid cache entry; reason: %q", code, reason)
	}
	if !strings.Contains(reason, "no cached decision") {
		t.Errorf("reason = %q, want it to say no cached decision was available", reason)
	}
	if !strings.Contains(strings.ToLower(reason), "could not reach") {
		t.Errorf("reason = %q, want it to also say the PDP could not be reached", reason)
	}
}

// TestIntegration_Cache_E2E_EpochBumpInvalidatesCachedEntry is proof 4 and
// C20, end to end: a real control-plane write (revoking the one delegation
// this proof's session presents -- a raw SQL UPDATE, the only way a real
// revocation happens in this system today; see revocation_epoch_e2e_
// integration_test.go's own proof1 for the identical technique) bumps
// tenant-cache-integration's epoch. The revoke is deliberately what ALSO
// flips the request's own answer from ALLOW to DENY: a stale-epoch cache
// entry that were WRONGLY served would read back as the OLD value (exit 0),
// not merely "some value" -- so the exit code itself, not only the reason
// text, is the discriminator between "the stale entry served" and "the PDP
// was asked fresh."
//
// Needs TWO cache keys, not one, to actually exercise epochCurrent:
// local_cache.go's own package doc ("WHERE THE EPOCH COMES FROM") computes
// lastKnownEpoch as the max epoch already recorded in the cache FILE, which
// trivially equals a single entry's own epoch when that entry is the only
// one present. A second entry, cached AFTER the revoke, is what makes the
// file's own true max newer than the first entry -- the same shape
// cmd/stratium-pep/hook_cache_test.go's own TestRunHook_CacheHit_StaleEpoch_
// FallsThroughToPDP uses at the unit level (a different key, same
// delegation, since its fake PDP enforces nothing and will answer anything
// the test hands it).
//
// A live PDP will not: this proof's SECOND key belongs to a SECOND,
// deliberately un-revoked delegation on the same tenant, not a second key on
// the SAME (now-revoked) delegation -- found live, not assumed. Reusing the
// revoked delegation for the second key looked equivalent on paper (call 2
// still gets denied, exit 2, satisfying its own assertion) but silently
// produces the WRONG cache state: hook.go's runHook attempts exactly one
// reissueAndRetryDecide on any DENY (reissue.go's own doc comment -- it does
// not distinguish "token expired" from "policy denied" first), and
// IssueToken itself refuses a revoked delegation outright (internal/pdpgrpc/
// token.go: "if d.Revoked { return ... PermissionDenied }") -- so
// reissueAndRetryDecide returns an error, and runHook's own reissue-error
// branch returns via writeDeny BEFORE ever reaching storeCacheResult. Call 2
// still denies, correctly, but nothing is ever cached for it, so the cache
// file never gains a second entry and maxCacheEpoch never moves past the
// first one -- the stale K1 entry then reads back as current by the cache's
// own honest bookkeeping (it has genuinely never observed a newer epoch),
// and this proof would falsely appear to fail C20 for a reason that has
// nothing to do with epoch invalidation. The epoch is tenant-wide, not
// delegation-scoped, so a second, healthy delegation's own successful ALLOW
// carries the identical post-revoke epoch just as well, without detouring
// through a reissue path a revoked delegation can never complete.
func TestIntegration_Cache_E2E_EpochBumpInvalidatesCachedEntry(t *testing.T) {
	const subject = "cache-proof-c@example.com"
	agentID := uuid.New()
	seedAgent(t, cacheTenant, agentID, "integration-agent-cache-proof-c", models.TrustTierUnverified)
	seedPolicy(t, cacheTenant, "cache-proof-c-permit",
		fmt.Sprintf(`permit(principal == User::"%s", action, resource);`, subject), "allow")

	// ONE session file path, TWO delegations in succession, deliberately:
	// cacheFilePathFor derives the cache file from the session file's path
	// alone (local_cache.go), so this is the only way to land two DIFFERENT
	// delegations' own cache entries in the SAME file -- see the doc comment
	// above for why a second delegation is unavoidable here, and why a
	// second session file (its own, separate cache file) would not work
	// either. sessionFileOneBytes backs up delegation one's own session data
	// before it gets overwritten below, so it can be restored before call 3
	// presents delegation one again.
	sessionFile := newCacheSessionFile(t)
	delegationOne := startCacheSession(t, sessionFile, agentID, subject, 3600)
	sessionFileOneBytes, err := os.ReadFile(sessionFile) //nolint:gosec // G304: this test's own t.TempDir() path
	if err != nil {
		t.Fatalf("back up delegation one's session file: %v", err)
	}

	const input = `{"path":"/tmp/cache-proof-c.txt"}`
	code, reason := callHook(t, agentID, subject, sessionFile, "1h", "Read", input)
	if code != 0 {
		t.Fatalf("call 1 (before the revoke) exit = %d, want 0 (ALLOW); reason: %q", code, reason)
	}

	before, exists := readTenantEpoch(t, cacheTenant)
	if !exists {
		t.Fatalf("tenant_epoch row for %s does not exist before the revoke", cacheTenant)
	}
	withTenantTx(t, cacheTenant, func(tx *sql.Tx) {
		if _, err := tx.ExecContext(t.Context(),
			`UPDATE delegations SET revoked = true, revoked_at = NOW() WHERE id = $1`, delegationOne); err != nil {
			t.Fatalf("UPDATE delegations (revoke): %v", err)
		}
	})
	assertEpochBumped(t, cacheTenant, before)

	// Delegation two, session-started at the SAME path: overwrites
	// sessionFile with its own data. Its call below is un-revoked and
	// ALLOWs, carrying the post-bump epoch into the SAME cache file
	// delegation one's own (now stale) entry already lives in.
	startCacheSession(t, sessionFile, agentID, subject, 3600)
	code, reason = callHook(t, agentID, subject, sessionFile, "1h", "Read", input)
	if code != 0 {
		t.Fatalf("call 2 (second, un-revoked delegation at the same session path, after the epoch bump) "+
			"exit = %d, want 0 (ALLOW) -- this is what gives the cache file a newer-epoch entry to compare "+
			"the stale one against; reason: %q", code, reason)
	}

	// Restore delegation one's own session data before presenting it again.
	if err := os.WriteFile(sessionFile, sessionFileOneBytes, 0o600); err != nil {
		t.Fatalf("restore delegation one's session file: %v", err)
	}
	code, reason = callHook(t, agentID, subject, sessionFile, "1h", "Read", input)
	if code != 2 {
		t.Fatalf("call 3 (SAME request as call 1, after the epoch bump) exit = %d, want 2 (DENY) -- C20: the "+
			"pre-revoke ALLOW cached at the old epoch must not be served; reason: %q", code, reason)
	}
	if strings.Contains(reason, "served from cache") {
		t.Errorf("reason = %q, looks like the cache-hit reason -- the stale entry must fall through to a "+
			"LIVE PDP call, not be served (even as a DENY, that would be the wrong mechanism producing the "+
			"right-looking answer)", reason)
	}
	if !strings.Contains(reason, "revoked") {
		t.Errorf("reason = %q, want it to name the real, live reason (the delegation is revoked) -- confirming "+
			"call 3 actually reached the PDP rather than merely denying for some unrelated reason", reason)
	}
}

// TestIntegration_Cache_E2E_ExpiredTokenDeniedDespiteValidEntry is proof 5
// and C24: a genuinely short-lived, real signed token (STRATIUM_PEP_TTL_SECONDS,
// not a synthetic tampered claim) that actually passes its own real "exp" in
// wall-clock time, checked against a cache entry that is otherwise valid on
// every other axis (current epoch, delegation not revoked, well within the
// staleness window). pdp-cache is stopped before the second call so there is
// no possibility of a rescue: reissueAndRetryDecide (reissue.go) would
// otherwise mint a fresh token on the fallback Decide call and this request
// would come back ALLOWED again, which would prove nothing about the cache's
// OWN token check -- see this file's own package doc, and the task brief's
// identical reasoning for why proofs 2/3/6 also insist on a genuinely
// stopped container rather than a bad address.
func TestIntegration_Cache_E2E_ExpiredTokenDeniedDespiteValidEntry(t *testing.T) {
	const subject = "cache-proof-d@example.com"
	agentID := uuid.New()
	seedAgent(t, cacheTenant, agentID, "integration-agent-cache-proof-d", models.TrustTierUnverified)
	seedPolicy(t, cacheTenant, "cache-proof-d-permit",
		fmt.Sprintf(`permit(principal == User::"%s", action, resource);`, subject), "allow")
	// A short but real TTL: session-start's own token is what tokenNotExpired
	// (cache.go) later decodes -- there is no signature to forge or clock to
	// fake here, only real wall-clock time to wait out below.
	sessionFile := newCacheSessionFile(t)
	startCacheSession(t, sessionFile, agentID, subject, 2)
	const input = `{"path":"/tmp/cache-proof-d.txt"}`

	code, reason := callHook(t, agentID, subject, sessionFile, "1h", "Read", input)
	if code != 0 {
		t.Fatalf("call 1 (token still valid) exit = %d, want 0 (ALLOW); reason: %q", code, reason)
	}

	time.Sleep(4 * time.Second) // past the 2s TTL above -- the token has now genuinely expired

	stopPDPCache(t)

	code, reason = callHook(t, agentID, subject, sessionFile, "1h", "Read", input)
	if code != 2 {
		t.Fatalf("call 2 (SAME request, token now expired, pdp-cache stopped) exit = %d, want 2 (DENY) -- "+
			"C24: an expired token must deny despite an otherwise-valid cache entry; reason: %q", code, reason)
	}
	if !strings.Contains(reason, "no cached decision") {
		t.Errorf("reason = %q, want it to say no cached decision was available -- the entry is present but "+
			"the caller's own token has expired, which must read as a miss, not a hit", reason)
	}
}

// TestIntegration_Cache_E2E_PastStalenessWindow_StopsServing is proof 6: a
// cache entry that is valid on every axis EXCEPT staleness -- current epoch,
// a long-lived token and delegation, pdp-cache stopped throughout -- serves
// right up until a real staleness window (STRATIUM_PEP_CACHE_STALENESS_WINDOW,
// waited out in real wall-clock time, not simulated) elapses, and denies the
// instant after. cache.go's own doc ties withinStalenessWindow to C19
// directly (its "required config, no default" clause) -- this is that
// specific condition's own live-stack proof, distinct from proof 3's "no
// entry at all" case above.
func TestIntegration_Cache_E2E_PastStalenessWindow_StopsServing(t *testing.T) {
	const subject = "cache-proof-e@example.com"
	agentID := uuid.New()
	seedAgent(t, cacheTenant, agentID, "integration-agent-cache-proof-e", models.TrustTierUnverified)
	seedPolicy(t, cacheTenant, "cache-proof-e-permit",
		fmt.Sprintf(`permit(principal == User::"%s", action, resource);`, subject), "allow")
	sessionFile := newCacheSessionFile(t)
	startCacheSession(t, sessionFile, agentID, subject, 3600)
	const staleness = "5s"
	const input = `{"path":"/tmp/cache-proof-e.txt"}`

	code, reason := callHook(t, agentID, subject, sessionFile, staleness, "Read", input)
	if code != 0 {
		t.Fatalf("call 1 (PDP up, populates the cache) exit = %d, want 0 (ALLOW); reason: %q", code, reason)
	}

	stopPDPCache(t)

	code, reason = callHook(t, agentID, subject, sessionFile, staleness, "Read", input)
	if code != 0 {
		t.Fatalf("call 2 (within the staleness window, pdp-cache stopped) exit = %d, want 0 -- outage "+
			"tolerance must still hold before the window elapses; reason: %q", code, reason)
	}

	time.Sleep(6 * time.Second) // past the 5s staleness window above

	code, reason = callHook(t, agentID, subject, sessionFile, staleness, "Read", input)
	if code != 2 {
		t.Fatalf("call 3 (past the staleness window, pdp-cache still stopped) exit = %d, want 2 (DENY) -- an "+
			"entry that is valid on every OTHER axis must still stop serving once the staleness window "+
			"elapses; reason: %q", code, reason)
	}
	if !strings.Contains(reason, "no cached decision") {
		t.Errorf("reason = %q, want it to say no cached decision was available", reason)
	}
}
