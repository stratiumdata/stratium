//go:build integration

// mcp_e2e_integration_test.go is the `mcp` enforcement surface's live proof:
// the seven numbered proofs of
// .superpowers/sdd/2026-08-17-mcp-live-proof/task-2-brief.md, run against a
// REAL, containerized PDP (deploy/docker/docker-compose.yml's pdp-mcp
// service), the REAL compiled stratium-pep binary launched as `stratium-pep
// mcp`, and the REAL compiled mcp-upstream binary that binary launches as its
// own child.
//
// WHY THIS FILE EXISTS AT ALL. §3.2 A2 claims four enforcement surfaces ship.
// Three had already been run against the real thing -- hook via
// cache_e2e_integration_test.go, extauthz behind a real Envoy
// (extauthz_integration_test.go), proxy in front of a real gRPC service
// (proxy_integration_test.go). `mcp` had never been invoked by any integration
// test: it was proven at unit level and against a fake PDP client, and nowhere
// else. This file closes that.
//
// WHAT IS AND IS NOT "REAL" HERE, stated plainly because it is narrower than
// the other three surfaces' proofs. `mcp` is a stdio proxy, so JSON-RPC frames
// on stdin ARE its interface -- there is no handshake a "real" MCP client
// would perform differently, because the proxy does not participate in
// initialize, it relays it. The client side was therefore already real before
// this file existed. What was not real is the PDP (a fake client until now)
// and the upstream server whose process lifecycle the proxy owns. Both are
// real below.
//
// package main (cmd/stratium-pep) cannot be imported -- Go forbids importing
// package main -- so exec'ing the compiled artifact is not a workaround here
// any more than it is in cache_e2e_integration_test.go: it is the only way
// anything in this package could drive runMCPCmd at all. internal/mcpupstream
// IS imported, deliberately: see that package's own doc for why the record
// format is a shared type rather than a hand-mirrored one (an ABSENCE
// assertion read through a drifted format fails OPEN, silently, forever).
//
// Sorts before store_integration_test.go alphabetically, deliberately, for the
// identical reason cache_/catalog_/escalation_/extauthz_/proxy_ do -- see
// revocation_epoch_e2e_integration_test.go's package doc for the fullest
// account: TestEndToEnd's last subtest permanently revokes the serving role's
// INSERT on audit_chain for the rest of that postgres instance's life
// (role-level, not tenant-scoped), which would turn every live
// Decide/CreateDelegation call this file makes into an audit-write failure
// instead of a real decision if this file's name sorted after it.
package store_test

import (
	"bufio"
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"

	"stratium/internal/mcpupstream"
	"stratium/pkg/models"
)

// ---------------------------------------------------------------------------
// Building the upstream the proxy launches.

var (
	mcpUpstreamBinaryOnce sync.Once
	mcpUpstreamBinaryPath string
	mcpUpstreamBinaryErr  error
)

// mcpUpstreamBinary builds cmd/mcp-upstream once for this whole test binary
// run and returns its path -- the same shape, and the same reasoning, as
// stratiumPEPBinary (cache_e2e_integration_test.go): sync.Once so nothing
// about which proof runs first changes what gets built, and the OS temp
// directory rather than t.TempDir() so the first caller's cleanup does not
// take the binary down for every proof after it.
//
// A second builder rather than a parameter on the first: internal/mcpupstream
// has its own unexported build helper (upstream_test.go) that this package
// cannot reach, and stratiumPEPBinary's own sync.Once is bound to one output
// path. Two ~20-line builders is cheaper than a shared one that has to carry
// a per-target once/path/err triple.
//
// ponytail: the build directory is never removed, for the reason
// stratiumPEPBinary's own comment already gives for its own.
func mcpUpstreamBinary(t *testing.T) string {
	t.Helper()
	mcpUpstreamBinaryOnce.Do(func() {
		dir, err := os.MkdirTemp("", "stratium-mcp-upstream-e2e-*")
		if err != nil {
			mcpUpstreamBinaryErr = fmt.Errorf("create build dir: %w", err)
			return
		}
		out := filepath.Join(dir, "mcp-upstream")

		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		cmd := exec.CommandContext(ctx, "go", "build", "-o", out, "./cmd/mcp-upstream")
		cmd.Dir = servicesModuleRoot(t)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			mcpUpstreamBinaryErr = fmt.Errorf("go build ./cmd/mcp-upstream: %w: %s", err, stderr.String())
			return
		}
		mcpUpstreamBinaryPath = out
	})
	if mcpUpstreamBinaryErr != nil {
		t.Fatalf("mcp-upstream binary: %v", mcpUpstreamBinaryErr)
	}
	return mcpUpstreamBinaryPath
}

// ---------------------------------------------------------------------------
// The harness: a LIVE `stratium-pep mcp` process with its stdin held open.

// mcpFrameChannelDepth bounds how many unread reply frames the reader
// goroutine below may queue. It exists so that goroutine can always reach its
// own cmd.Wait() even when a proof stops reading early (a failing assertion,
// or a proof that deliberately expects nothing more) -- an unbuffered channel
// would leave it parked on a send nobody will ever receive, and the process
// would never be reaped. No proof here exchanges more than a handful of
// frames, so this is never the thing that fills.
const mcpFrameChannelDepth = 64

// mcpProxy is one live `stratium-pep mcp` subprocess, with its stdin held
// OPEN so a proof can send a frame, observe what came back, act on it, and
// only then hang up.
//
// THIS IS THE SIBLING runPEPSubcommand COULD NOT BE, and the reason is
// sharper than the task brief anticipated. runPEPSubcommand
// (cache_e2e_integration_test.go) is cmd.Run() with canned stdin: it hands
// the child every byte it will ever get and then closes stdin immediately.
// For "hook" and "session-start" -- one-shot subcommands that read one
// request and exit -- that is exactly right. For "mcp" it breaks the proofs
// that matter most, and not only the two the brief flagged:
//
//   - runMCP's agent->upstream goroutine closes the UPSTREAM'S stdin the
//     moment the agent's own stdin reaches EOF (mcp.go: `defer func() { _ =
//     upstreamIn.Close() }()`), because that is how this proxy tells its
//     child to shut down.
//   - A tools/call is not decided inline. intercept hands it to its own
//     goroutine (mcp_authorize.go) so a slow PDP cannot block the stream, and
//     that goroutine's forward() write happens WHENEVER the PDP answers.
//   - With canned stdin, EOF is immediate and the PDP round trip is not. So
//     upstreamIn is closed while the decision is still in flight, forward()'s
//     write fails, and the ALLOWED call never reaches the upstream. forward's
//     own doc comment documents that write as best-effort for exactly this
//     case ("the agent having already hung up... which makes the call moot").
//
// That is correct behaviour for a departed agent and this file does not
// change it -- but it means canned stdin cannot prove proof 1 (a permitted
// call REACHES the upstream), proof 2's positive control, proof 4's allow
// half, or proof 7's allow half, let alone proofs 5 and 6. Every proof below
// therefore uses this type. See the task report; the brief's handoff said
// proofs 1/2/3/4/7 were fine on the existing harness, and that is wrong for
// any proof that must observe an ALLOW arrive.
//
// runPEPSubcommand itself is deliberately untouched: five top-level tests in
// cache_e2e_integration_test.go depend on its exact contract.
type mcpProxy struct {
	t          *testing.T
	cmd        *exec.Cmd
	stdin      io.WriteCloser
	frames     chan []byte
	stderr     *lockedBuffer
	recordPath string

	// exited closes once the reader goroutine has seen stdout EOF AND
	// completed cmd.Wait(). waitErr and scanErr are written before that close
	// and read only after it, so the channel close is the happens-before edge
	// that makes them race-free.
	exited  chan struct{}
	waitErr error
	scanErr error
}

// lockedBuffer is a bytes.Buffer safe for the one concurrency os/exec
// actually creates: cmd.Stderr is written by a copying goroutine the exec
// package owns, while a proof reads it from the test goroutine to report a
// failure. os/exec only guarantees that buffer is settled after Wait, and
// every diagnostic below is printed BEFORE Wait (that is the point of
// printing it). A mutex is the whole fix.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// startMCPProxy launches the real compiled stratium-pep binary as
// `stratium-pep mcp`, wired to the real compiled mcp-upstream binary as its
// child, and returns a handle with the child's stdin still open.
//
// env is layered over this test process's own environment, the same choice
// runPEPSubcommand makes and for the same reason (the binary needs nothing
// else from it, but a clean slate risks missing something the OS or the Go
// runtime expects for no benefit here).
//
// stdout is read by ONE goroutine which, on EOF, calls cmd.Wait() itself.
// That ordering is required, not stylistic: os/exec documents that Wait
// closes a StdoutPipe once the process exits, so calling Wait from a second
// goroutine while this one is still reading is a documented race.
func startMCPProxy(t *testing.T, env map[string]string, recordPath string) *mcpProxy {
	t.Helper()

	cmd := exec.Command(stratiumPEPBinary(t), "mcp")
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("open mcp stdin pipe: %v", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("open mcp stdout pipe: %v", err)
	}
	stderr := &lockedBuffer{}
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start stratium-pep mcp: %v", err)
	}

	p := &mcpProxy{
		t:          t,
		cmd:        cmd,
		stdin:      stdin,
		frames:     make(chan []byte, mcpFrameChannelDepth),
		stderr:     stderr,
		recordPath: recordPath,
		exited:     make(chan struct{}),
	}

	go func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 0, 4096), 1<<20)
		for scanner.Scan() {
			// Copied before it crosses the channel: Scan reuses its buffer.
			p.frames <- append([]byte(nil), scanner.Bytes()...)
		}
		p.scanErr = scanner.Err()
		close(p.frames)
		p.waitErr = cmd.Wait()
		close(p.exited)
	}()

	t.Cleanup(func() {
		// Drain, so the reader goroutine can always reach cmd.Wait() even if
		// the proof stopped reading mid-session; then hang up and, only if
		// the process still refuses to leave, kill it. A stray
		// stratium-pep/mcp-upstream pair outliving a failed test would be a
		// real problem for whatever runs next.
		go func() {
			for range p.frames { //nolint:revive // draining, nothing to do with each frame
			}
		}()
		_ = p.stdin.Close()
		select {
		case <-p.exited:
		case <-time.After(15 * time.Second):
			_ = p.cmd.Process.Kill()
			<-p.exited
			t.Errorf("stratium-pep mcp had to be killed at cleanup -- it did not exit after its stdin closed; stderr: %s",
				p.stderr.String())
		}
	})

	return p
}

// send writes one JSON-RPC frame, newline-terminated, to the proxy's stdin.
func (p *mcpProxy) send(frame string) {
	p.t.Helper()
	if _, err := io.WriteString(p.stdin, frame+"\n"); err != nil {
		p.t.Fatalf("send frame to mcp: %v (stderr: %s)", err, p.stderr.String())
	}
}

// nextFrame returns the next frame the proxy wrote to stdout, or fails the
// test if none arrives within timeout or stdout closes first.
func (p *mcpProxy) nextFrame(timeout time.Duration) []byte {
	p.t.Helper()
	select {
	case line, ok := <-p.frames:
		if !ok {
			p.t.Fatalf("mcp stdout closed while waiting for a frame; stderr: %s", p.stderr.String())
		}
		return line
	case <-time.After(timeout):
		p.t.Fatalf("no frame from mcp within %s; stderr: %s", timeout, p.stderr.String())
	}
	return nil
}

// nextFrames returns the next n frames in arrival order. Order across n is
// NOT meaningful for tools/call: intercept decides each on its own goroutine
// precisely so one cannot block another (mcp.go's CONCURRENCY note), so two
// in-flight calls may answer in either order. Callers index by id
// (replyByID), never by position.
func (p *mcpProxy) nextFrames(n int, timeout time.Duration) [][]byte {
	p.t.Helper()
	out := make([][]byte, 0, n)
	for range n {
		out = append(out, p.nextFrame(timeout))
	}
	return out
}

// closeStdin hangs up as the agent, which is what tells the proxy to shut its
// child down (mcp.go closes upstreamIn when this direction ends).
func (p *mcpProxy) closeStdin() {
	p.t.Helper()
	if err := p.stdin.Close(); err != nil {
		p.t.Fatalf("close mcp stdin: %v", err)
	}
}

// waitForExit blocks until the proxy process has exited and been reaped, and
// returns its exit code. Fails the test if it does not exit within timeout --
// "the proxy exits rather than hanging" is itself one of the properties under
// proof (proof 6), so a timeout here is a real failure, never a flake budget.
func (p *mcpProxy) waitForExit(timeout time.Duration) int {
	p.t.Helper()
	select {
	case <-p.exited:
	case <-time.After(timeout):
		p.t.Fatalf("stratium-pep mcp did not exit within %s; stderr: %s", timeout, p.stderr.String())
	}
	if p.scanErr != nil {
		p.t.Fatalf("reading mcp stdout: %v; stderr: %s", p.scanErr, p.stderr.String())
	}
	var exitErr *exec.ExitError
	if p.waitErr != nil && !errors.As(p.waitErr, &exitErr) {
		p.t.Fatalf("waiting for mcp: %v; stderr: %s", p.waitErr, p.stderr.String())
	}
	return p.cmd.ProcessState.ExitCode()
}

// records reads every complete record the upstream has written so far,
// through mcpupstream's OWN reader -- never a local re-implementation. It is
// safe to call mid-session (ReadRecords skips an unterminated tail rather
// than mis-decoding it), which is what proofs 5 and 6 need.
func (p *mcpProxy) records() []mcpupstream.Record {
	p.t.Helper()
	recs, err := mcpupstream.ReadRecords(p.recordPath)
	if err != nil {
		p.t.Fatalf("read upstream records at %s: %v; mcp stderr: %s", p.recordPath, err, p.stderr.String())
	}
	return recs
}

// ---------------------------------------------------------------------------
// Frames and replies.

// mcpReply is the subset of a JSON-RPC reply these proofs read. ID stays
// json.RawMessage for the same reason mcp.go never decodes an id through a Go
// type: proof 4 compares the id's exact BYTES, and a large integer does not
// survive a float64 round trip. Result likewise stays raw so proof 3 can
// compare a relayed listing byte for byte against the upstream's own.
type mcpReply struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  json.RawMessage `json:"result"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func decodeReply(t *testing.T, line []byte) mcpReply {
	t.Helper()
	var r mcpReply
	if err := json.Unmarshal(line, &r); err != nil {
		t.Fatalf("decode reply %s: %v", line, err)
	}
	if r.JSONRPC != "2.0" {
		t.Errorf("reply jsonrpc = %q, want \"2.0\": %s", r.JSONRPC, line)
	}
	return r
}

// replyByID picks the reply carrying exactly id's bytes out of an unordered
// batch, failing if none does -- which is itself an id-fidelity assertion
// every proof below gets for free before it asserts anything else.
func replyByID(t *testing.T, lines [][]byte, id string) mcpReply {
	t.Helper()
	var seen []string
	for _, line := range lines {
		r := decodeReply(t, line)
		if string(r.ID) == id {
			return r
		}
		seen = append(seen, string(r.ID))
	}
	t.Fatalf("no reply carrying id %s; ids seen: %v", id, seen)
	return mcpReply{}
}

// toolCallFrame builds a tools/call request. id is spliced in as literal JSON
// so a proof can send an id shape Go would not round-trip through a typed
// field (proof 4's 2^53+1).
func toolCallFrame(id, tool, message string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"method":"tools/call","params":{"name":%q,"arguments":{"message":%q}}}`,
		id, tool, message)
}

func initializeFrame(id string) string {
	return fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`, id)
}

// assertCallSucceeded asserts a reply is the UPSTREAM'S OWN result for tool,
// not a proxy-authored anything. mcpupstream.callResult answers an
// unadvertised tool with isError:true, so "isError is false AND the text
// names the tool" is what tells a real relayed result from a fixture that
// would have said "ok" to anything.
func assertCallSucceeded(t *testing.T, r mcpReply, tool string) {
	t.Helper()
	if r.Error != nil {
		t.Fatalf("tools/call %q came back as error %+v, want the upstream's result", tool, r.Error)
	}
	var res struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(r.Result, &res); err != nil {
		t.Fatalf("decode tools/call result %s: %v", r.Result, err)
	}
	if res.IsError {
		t.Errorf("tools/call %q result isError = true (%+v) -- the upstream answers an unadvertised tool that "+
			"way, so this means the name did not survive the relay intact", tool, res.Content)
	}
	if len(res.Content) == 0 || !strings.Contains(res.Content[0].Text, tool) {
		t.Errorf("tools/call %q result content = %+v, want text naming %q", tool, res.Content, tool)
	}
}

// mcpErrorCodeAuthorizationDenied mirrors cmd/stratium-pep/mcp_authorize.go's
// own constant. Hand-mirrored deliberately, and safely: this is a PRESENCE
// assertion (a denial must carry exactly this code), so a drift between the
// two makes these proofs fail loudly rather than pass vacuously -- the
// distinction internal/mcpupstream's package doc draws between echo-upstream's
// safe hand-mirroring and a record format's unsafe one.
const mcpErrorCodeAuthorizationDenied = -31003

// assertDenied asserts a reply is this proxy's own denial, carrying reason
// text that names why. The reason must come from the PDP (or from a
// fail-closed path in the PEP), never be invented here.
func assertDenied(t *testing.T, r mcpReply, wantReasonSubstrings ...string) {
	t.Helper()
	if r.Error == nil {
		t.Fatalf("reply carried a result (%s), want a JSON-RPC error -- the call was supposed to be denied", r.Result)
	}
	if r.Error.Code != mcpErrorCodeAuthorizationDenied {
		t.Errorf("denial code = %d, want %d", r.Error.Code, mcpErrorCodeAuthorizationDenied)
	}
	for _, want := range wantReasonSubstrings {
		if !strings.Contains(r.Error.Message, want) {
			t.Errorf("denial message = %q, want it to contain %q", r.Error.Message, want)
		}
	}
}

// ---------------------------------------------------------------------------
// Fixtures: a real agent, a real policy, a real session, a real record file.

// mcpProofStaleness is the PEP decision cache's staleness window for every
// proof in this file, set so short that nothing can ever be served from
// cache.
//
// This is not a micro-optimisation, it is what keeps these proofs about the
// thing they claim to be about. `mcp` is one of the two surfaces permitted to
// consult the on-disk cache (spec §4.8.3 W6), keyed on
// (delegation, tool, raw_input). Proof 7 sends the IDENTICAL frame twice,
// either side of a revocation, and proof 2's fetch/purge pair shares a
// session file -- under any ordinary window the second call would be answered
// from a cached ALLOW and never reach the PDP at all, so a proof about "the
// full loop through a real PDP" would silently become a proof about the
// cache. Nor would the epoch check save it: revoking bumps tenant_epoch, but
// maxCacheEpoch is the max epoch in the cache FILE, which with one entry is
// that entry's own -- so a stale entry reads as current by the cache's own
// honest bookkeeping. The cache's real behaviour has its own live proofs, in
// cache_e2e_integration_test.go, and they are not this file's job.
const mcpProofStaleness = "1ns"

// mcpProofConnectTimeout is short enough that a genuinely unreachable pdp-mcp
// fails fast rather than eating a proof's own budget, and long enough that a
// real Decide round trip against a live container never trips it.
const mcpProofConnectTimeout = "5s"

// mcpFixture is one proof's own agent, subject, session file, and record
// file. Every field is per-proof: the session file must be, because
// cacheFilePathFor derives the PEP cache file from its path
// (cmd/stratium-pep/local_cache.go), and the record file must be, because two
// proofs sharing one would see each other's calls and turn every absence
// assertion into a coin flip.
type mcpFixture struct {
	agentID      uuid.UUID
	subject      string
	sessionFile  string
	recordPath   string
	delegationID string
	upstreamBin  string
}

// newMCPFixture seeds an agent and a permissive principal policy on
// mcpTenant, then starts a REAL session through the real "session-start"
// subcommand.
//
// TRUST TIER IS PLATFORM_TRUSTED, not the TrustTierUnverified every cache
// proof uses, and that is forced rather than cautious. Both tools below
// derive INTERNAL_MODIFY (see mcpApprovedTool's comment), and
// authz.DefaultTrustTable requires REGISTERED for that tier -- an unverified
// agent would be denied by the AGENT leg, for both tools alike, which would
// destroy the one distinction every proof here rests on. PLATFORM_TRUSTED
// clears it with margin and takes the agent leg out of the set of things any
// denial below could be attributed to.
func newMCPFixture(t *testing.T, name string) mcpFixture {
	t.Helper()
	f := mcpFixture{
		agentID:     uuid.New(),
		subject:     "mcp-proof-" + name + "@example.com",
		upstreamBin: mcpUpstreamBinary(t),
	}
	dir := t.TempDir()
	f.sessionFile = filepath.Join(dir, "session.json")
	f.recordPath = filepath.Join(dir, "records.jsonl")

	// The agent and policy NAMES carry the agent's own uuid, not just the
	// proof's name. agents has a UNIQUE(tenant_id, name) constraint, so a
	// fixed name makes a fixture seedable exactly once per database -- which
	// is fine under `make integration` (fresh volumes every run) and breaks
	// the moment anyone runs these proofs a second time against a stack
	// that is already up, or with -count=2. Found live, immediately, the
	// first time this file was re-run. Nothing asserts on either name, so
	// there is no cost to making them unique.
	unique := name + "-" + f.agentID.String()
	seedAgent(t, mcpTenant, f.agentID, "integration-agent-mcp-"+unique, models.TrustTierPlatformTrusted)
	seedPolicy(t, mcpTenant, "mcp-proof-"+unique+"-permit",
		fmt.Sprintf(`permit(principal == User::"%s", action, resource);`, f.subject), "allow")
	f.delegationID = f.startSession(t)
	return f
}

// mcpApprovedTool and mcpDeniedTool are how a permitted call is told from a
// denied one in every proof below, and the mechanism is the DELEGATION'S
// approved_tools -- not the tier, and not the agent's allowed_tools.
//
// NOT THE TIER, because it cannot be. Neither "fetch" nor "purge" appears in
// authz's builtin verb table (tier.go's verbTiers), neither has a
// tool_catalog row on this tenant, and DeriveTier's own resolution order
// therefore reaches BuiltinTier for both -- where RawInput is a JSON object
// matching no shell pattern, so classifyInput returns its "unrecognized ->
// assume it modifies" default. Both tools derive INTERNAL_MODIFY, identically.
// Seeding tiers cannot separate them.
//
// NOT THE AGENT'S allowed_tools, because seedAgent
// (store_integration_test.go) hardcodes an empty list -- which
// models.Agent.HasTool reads as UNRESTRICTED -- and it is a fixture ~20 other
// tests route through. Changing it to take a tool list would mean re-proving
// every one of them.
//
// SO: approved_tools, requested through the real "session-start" subcommand's
// STRATIUM_PEP_REQUESTED_TOOLS and enforced by authz.DelegationLeg. That is
// also the most honest choice available, not merely the cheapest: the
// delegation named by the session file is precisely the artifact this
// surface's trust model says authorizes the call, so the discriminator sits
// on the credential path being proven rather than beside it. Same design as
// grpc-target's Fetch/Purge pair on the proxy surface.
const (
	mcpApprovedTool = mcpupstream.ToolFetch
	mcpDeniedTool   = mcpupstream.ToolPurge
)

// startSession runs the real "session-start" subcommand against pdp-mcp --
// a real CreateDelegation call -- and returns the delegation id, read back
// from the session file exactly as loadSessionFile would.
//
// Its own function rather than a call to startCacheSession
// (cache_e2e_integration_test.go): that one is hardwired to cacheAddr and to
// tool "Read", and reshaping it would change a fixture five top-level tests
// in that file already depend on.
func (f mcpFixture) startSession(t *testing.T) string {
	t.Helper()
	env := f.baseEnv()
	env["STRATIUM_PEP_REQUESTED_TIER"] = fmt.Sprintf("%d", int32(models.ActionTierInternalModify))
	env["STRATIUM_PEP_REQUESTED_TOOLS"] = mcpApprovedTool // deliberately NOT mcpDeniedTool -- see that pair's comment
	env["STRATIUM_PEP_TTL_SECONDS"] = "3600"
	env["STRATIUM_PEP_PURPOSE"] = "integration test: mcp surface live proof"

	stdout, stderr, code := runPEPSubcommand(t, "session-start", env, "")
	if code != 0 {
		t.Fatalf("stratium-pep session-start exit = %d, want 0; stdout: %q; stderr: %s", code, stdout, stderr)
	}
	return f.readDelegationID(t)
}

// readDelegationID decodes the delegation id out of the session file the real
// session-start wrote.
func (f mcpFixture) readDelegationID(t *testing.T) string {
	t.Helper()
	data, err := os.ReadFile(f.sessionFile)
	if err != nil {
		t.Fatalf("read session file written by session-start: %v", err)
	}
	var resp struct {
		DelegationID string `json:"delegation_id"`
	}
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("decode session file: %v", err)
	}
	if resp.DelegationID == "" {
		t.Fatal("session file has no delegation_id")
	}
	return resp.DelegationID
}

// baseEnv is the identity/timing configuration group both "session-start" and
// "mcp" need -- the same seven variables hookConfig loads, which is exactly
// why mcp.go reuses hookConfig unchanged for its own half.
func (f mcpFixture) baseEnv() map[string]string {
	return map[string]string{
		"STRATIUM_PEP_PDP_ADDR":               mcpAddr,
		"STRATIUM_PEP_AGENT_ID":               f.agentID.String(),
		"STRATIUM_PEP_SUBJECT":                f.subject,
		"STRATIUM_PEP_SESSION_FILE":           f.sessionFile,
		"STRATIUM_PEP_CONNECT_TIMEOUT":        mcpProofConnectTimeout,
		"STRATIUM_PEP_APPROVAL_POLL_INTERVAL": "200ms",
		"STRATIUM_PEP_APPROVAL_TIMEOUT":       "5s",
	}
}

// proxyEnv is baseEnv plus the two variables only "mcp" has
// (STRATIUM_PEP_MCP_UPSTREAM_COMMAND/_ARGS) and the cache window every
// surface that may consult the cache requires.
func (f mcpFixture) proxyEnv() map[string]string {
	env := f.baseEnv()
	env["STRATIUM_PEP_CACHE_STALENESS_WINDOW"] = mcpProofStaleness
	env["STRATIUM_PEP_MCP_UPSTREAM_COMMAND"] = f.upstreamBin
	env["STRATIUM_PEP_MCP_UPSTREAM_ARGS"] = f.recordPath
	return env
}

// start launches one live proxy against this fixture.
func (f mcpFixture) start(t *testing.T) *mcpProxy {
	t.Helper()
	return startMCPProxy(t, f.proxyEnv(), f.recordPath)
}

// ---------------------------------------------------------------------------
// Reading the upstream's own record -- never what the caller observed.

// toolCallRecords returns only the tools/call records, in arrival order. Every
// absence assertion below is expressed over this, never over the raw slice:
// initialize and notifications land in the same file and would otherwise make
// a count assertion depend on how many housekeeping frames a proof happened to
// send.
func toolCallRecords(recs []mcpupstream.Record) []mcpupstream.Record {
	var out []mcpupstream.Record
	for _, r := range recs {
		if r.Method == "tools/call" {
			out = append(out, r)
		}
	}
	return out
}

// assertRecordedTools asserts the upstream received tools/call for exactly
// want, in order.
//
// It fails on a SHORTFALL as loudly as on an excess, and that asymmetry is
// the whole reason this helper exists rather than a bare "no purge record"
// check. An empty record file is a reachable state -- mcpupstream.Serve
// creates the file before reading its first frame, so a proxy that never
// forwarded ANYTHING leaves a present, empty, error-free file that
// ReadRecords reports as zero records. Against a bare absence assertion that
// state passes, permanently and silently. Naming the tools that MUST be
// there, beside the ones that must not, is what makes the absence mean
// something.
func assertRecordedTools(t *testing.T, recs []mcpupstream.Record, want ...string) {
	t.Helper()
	calls := toolCallRecords(recs)
	var got []string
	for _, r := range calls {
		got = append(got, r.Tool)
	}
	if len(got) != len(want) {
		t.Fatalf("upstream recorded tools/call for %v, want exactly %v -- asserted against the UPSTREAM'S OWN "+
			"record file (%d records total), never against what the caller observed", got, want, len(recs))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("upstream recorded tools/call for %v, want exactly %v", got, want)
		}
	}
}

// processAlive reports whether pid names a live process. Signal 0 performs
// permission and existence checking without delivering anything; EPERM means
// the process exists but is not ours to signal, which for a grandchild of
// this test process should never happen and is still the wrong answer to
// report as "gone".
func processAlive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}

// upstreamPID returns the pid every record carries -- the CHILD the proxy
// launched, chosen by the proxy and reported by nothing else. It also asserts
// the child is a genuinely separate process from both the proxy and this test
// binary, without which "the proxy launches a child" would be satisfied by a
// proxy that did the work itself.
func upstreamPID(t *testing.T, p *mcpProxy) int {
	t.Helper()
	recs := p.records()
	if len(recs) == 0 {
		t.Fatal("upstream has recorded nothing yet -- there is no pid to read, and no evidence a child exists at all")
	}
	pid := recs[0].PID
	switch {
	case pid <= 0:
		t.Fatalf("record pid = %d, want a real process id", pid)
	case pid == p.cmd.Process.Pid:
		t.Fatalf("record pid = %d, which is the PROXY's own pid -- the upstream must be a separate child process", pid)
	case pid == os.Getpid():
		t.Fatalf("record pid = %d, which is this test process's own pid", pid)
	}
	return pid
}

// ---------------------------------------------------------------------------
// The seven proofs (task-2-brief.md).

// Proof 1. A permitted tools/call reaches the upstream and its result returns
// to the caller -- the full loop through a real PDP, for the first time on
// this surface.
//
// BOTH halves are asserted, and they are different claims. "Its result
// returns" is read off the reply frame; "reaches the upstream" is read off
// the UPSTREAM'S OWN record file, out of band, never through a tools/call
// (which is the very thing being gated -- see internal/mcpupstream's package
// doc). A proxy that fabricated a plausible result would satisfy the first
// and fail the second.
func TestIntegration_MCP_E2E_PermittedCallReachesUpstreamAndReturns(t *testing.T) {
	f := newMCPFixture(t, "permitted")
	p := f.start(t)

	p.send(initializeFrame("1"))
	assertCallSucceededInit(t, decodeReply(t, p.nextFrame(15*time.Second)))

	p.send(toolCallFrame("2", mcpApprovedTool, "proof-1-payload"))
	assertCallSucceeded(t, decodeReply(t, p.nextFrame(15*time.Second)), mcpApprovedTool)

	p.closeStdin()
	if code := p.waitForExit(30 * time.Second); code != 0 {
		t.Errorf("stratium-pep mcp exit = %d, want 0 -- a clean session must end cleanly; stderr: %s",
			code, p.stderr.String())
	}

	assertRecordedTools(t, p.records(), mcpApprovedTool)
}

// assertCallSucceededInit asserts an initialize reply is the upstream's own,
// not a proxy invention: a serverInfo naming the fixture server is something
// only the upstream can produce.
func assertCallSucceededInit(t *testing.T, r mcpReply) {
	t.Helper()
	if r.Error != nil {
		t.Fatalf("initialize came back as error %+v, want the upstream's result", r.Error)
	}
	var res struct {
		ProtocolVersion string `json:"protocolVersion"`
		ServerInfo      struct {
			Name string `json:"name"`
		} `json:"serverInfo"`
	}
	if err := json.Unmarshal(r.Result, &res); err != nil {
		t.Fatalf("decode initialize result %s: %v", r.Result, err)
	}
	if res.ServerInfo.Name == "" || res.ProtocolVersion == "" {
		t.Fatalf("initialize result = %s, want the upstream's own serverInfo and protocolVersion", r.Result)
	}
}

// Proof 2. A denied tools/call does NOT reach the upstream, asserted against
// the upstream's own record rather than against the caller's error.
//
// THE POSITIVE CONTROL IS IN THIS TEST, not merely in this file, and it is
// load-bearing. "Present but empty" is a reachable state of the record file
// (mcpupstream.Serve creates it before reading its first frame), and a bare
// "no purge record" assertion passes against it for entirely the wrong
// reason: nothing arrived because nothing was ever forwarded, not because
// this one call was stopped. The permitted call in the same session, over the
// same proxy, into the same record file, is what makes the absence mean
// "purge specifically was stopped" -- assertRecordedTools fails on the
// shortfall as well as on the excess.
func TestIntegration_MCP_E2E_DeniedCallNeverReachesUpstream(t *testing.T) {
	f := newMCPFixture(t, "denied")
	p := f.start(t)

	p.send(initializeFrame("1"))
	assertCallSucceededInit(t, decodeReply(t, p.nextFrame(15*time.Second)))

	p.send(toolCallFrame("2", mcpApprovedTool, "proof-2-permitted"))
	p.send(toolCallFrame("3", mcpDeniedTool, "proof-2-denied"))

	// Two in-flight decisions may answer in either order -- see nextFrames.
	replies := p.nextFrames(2, 20*time.Second)
	assertCallSucceeded(t, replyByID(t, replies, "2"), mcpApprovedTool)
	denial := replyByID(t, replies, "3")
	if denial.Error != nil {
		// Logged, not merely asserted on: this is the live PDP's own text
		// reaching an agent through a JSON-RPC error frame for the first time
		// on this surface, and a future reader should be able to see what it
		// actually said rather than only which substrings a test demanded.
		t.Logf("live denial for %q -> code=%d message=%q", mcpDeniedTool, denial.Error.Code, denial.Error.Message)
	}
	assertDenied(t, denial, mcpDeniedTool, "approved_tools")

	p.closeStdin()
	if code := p.waitForExit(30 * time.Second); code != 0 {
		t.Errorf("stratium-pep mcp exit = %d, want 0; stderr: %s", code, p.stderr.String())
	}

	// The whole proof: the permitted call is THERE (so the file, the child,
	// and the forwarding path are all demonstrably working) and the denied
	// one is NOT.
	assertRecordedTools(t, p.records(), mcpApprovedTool)
}

// Proof 3. tools/list relays UNFILTERED, including a tool that would be
// denied if called -- pinned at both ends, in one test: the listing is
// unchanged, and calling the tool it advertises is then denied.
//
// "Unchanged" is asserted byte for byte against the upstream's own reply to
// the identical frame, produced by running mcpupstream.Serve IN-PROCESS
// (directUpstreamListing below). Asserting only "both tool names appear"
// would pass for a proxy that rewrote descriptions, dropped a schema, or
// re-encoded the result -- and re-encoding is exactly the failure mode mcp.go
// is built to avoid.
//
// THIS PINS A RULING, IT DOES NOT PROPOSE ONE. mcp.go's package doc explains
// why filtering tools/list would be D1 in a UX coat of paint (the PEP
// classifying locally, just earlier in the conversation) or one Decide per
// listed tool on a method this system does not enforce. Enforcement happens
// at call time, which is the second half of this test.
func TestIntegration_MCP_E2E_ToolsListRelaysUnfiltered(t *testing.T) {
	f := newMCPFixture(t, "toolslist")
	p := f.start(t)

	p.send(initializeFrame("1"))
	assertCallSucceededInit(t, decodeReply(t, p.nextFrame(15*time.Second)))

	const listFrame = `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
	p.send(listFrame)
	relayed := p.nextFrame(15 * time.Second)

	direct := directUpstreamListing(t, listFrame)
	if !bytes.Equal(relayed, direct) {
		t.Fatalf("tools/list relayed as\n  %s\nbut the upstream itself answers\n  %s\n-- the listing must pass "+
			"through unchanged, byte for byte", relayed, direct)
	}

	// And the listing genuinely advertises the tool that would be denied --
	// without which "unchanged" would be true of a listing that never
	// contained it.
	var listing struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal(relayed, &listing); err != nil {
		t.Fatalf("decode tools/list reply %s: %v", relayed, err)
	}
	var names []string
	for _, tool := range listing.Result.Tools {
		names = append(names, tool.Name)
	}
	for _, want := range []string{mcpApprovedTool, mcpDeniedTool} {
		if !slices.Contains(names, want) {
			t.Fatalf("tools/list advertised %v, want it to include %q -- an unfiltered listing must carry the "+
				"tool that would be denied if called, or this proof says nothing", names, want)
		}
	}

	// The other end of the ruling: the SAME tool the listing advertised is
	// denied at call time, with a real PDP-attributed reason.
	p.send(toolCallFrame("3", mcpDeniedTool, "proof-3-denied"))
	assertDenied(t, decodeReply(t, p.nextFrame(20*time.Second)), mcpDeniedTool, "approved_tools")

	p.closeStdin()
	if code := p.waitForExit(30 * time.Second); code != 0 {
		t.Errorf("stratium-pep mcp exit = %d, want 0; stderr: %s", code, p.stderr.String())
	}

	// tools/list itself is never gated, so it DID reach the upstream; the
	// tools/call for the tool it advertised did not.
	recs := p.records()
	if len(toolCallRecords(recs)) != 0 {
		t.Errorf("upstream recorded %d tools/call, want 0", len(toolCallRecords(recs)))
	}
	if !recordedMethod(recs, "tools/list") {
		t.Errorf("upstream recorded %+v, want a tools/list among them -- without it the absence above could "+
			"mean the relay never worked at all", recs)
	}
}

// directUpstreamListing runs mcpupstream.Serve in-process over frame and
// returns the single reply line it produces. This is the reference the
// relayed listing is compared against: same code, same server, no proxy in
// between. The reply is deterministic -- encoding/json sorts map keys and
// preserves slice order, and the tool schemas are fixed raw JSON for exactly
// this reason (see toolDescriptor's own comment in that package).
func directUpstreamListing(t *testing.T, frame string) []byte {
	t.Helper()
	var out bytes.Buffer
	recordPath := filepath.Join(t.TempDir(), "direct-records.jsonl")
	if err := mcpupstream.Serve(strings.NewReader(frame+"\n"), &out, recordPath); err != nil {
		t.Fatalf("mcpupstream.Serve directly: %v", err)
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n"))
}

func recordedMethod(recs []mcpupstream.Record, method string) bool {
	for _, r := range recs {
		if r.Method == method {
			return true
		}
	}
	return false
}

// Proof 4. The request id survives the relay unchanged in BOTH directions,
// for a denial as well as an allow.
//
// THE ALLOW proves both directions independently: the id in the upstream's
// own RECORD is what survived agent->upstream, and the id in the reply is
// what survived upstream->agent. THE DENIAL is the harder case and the reason
// this proof exists -- a denial is SYNTHESIZED by the proxy
// (mcp_authorize.go's jsonrpcErrorFrame), never relayed, so it is the one
// frame whose id could be reconstructed rather than carried.
//
// TWO DENIALS, WITH DIFFERENT ID SHAPES, AND THAT IS NOT SYMMETRY FOR ITS OWN
// SAKE -- it closes a hole this proof shipped with and mutation testing found.
// The first version sent the big integer on the ALLOW and a string id on the
// denial. A mutant that re-encoded the denial's id through interface{} -- the
// exact float64 round trip mcp.go's package doc says it avoids by never
// decoding an id at all -- SURVIVED it, because a JSON string round-trips
// through interface{} unharmed. The proof named the synthesized denial as the
// case "where correlation is easiest to lose" and then tested it with the one
// id shape that cannot lose. The numeric id below is what kills that mutant
// (it comes back as ...996); the string id stays, because a proxy that
// special-cased numbers would still have to carry a string through, and
// covering one shape is not covering ids.
//
// 9007199254740993 (2^53+1) and 9007199254740995 (2^53+3) are the two
// smallest odd integers above float64's exact-integer range: they re-encode
// as ...992 and ...996 respectively. A small-integer id would pass against
// every implementation, correct or not.
func TestIntegration_MCP_E2E_RequestIDSurvivesBothDirections(t *testing.T) {
	f := newMCPFixture(t, "idfidelity")
	p := f.start(t)

	const allowBigIntID = "9007199254740993"    // 2^53+1, re-encodes as ...992
	const denyBigIntID = "9007199254740995"     // 2^53+3, re-encodes as ...996
	const denyStringID = `"denial-correlation"` // a second id SHAPE, not merely a second value

	p.send(initializeFrame("1"))
	assertCallSucceededInit(t, decodeReply(t, p.nextFrame(15*time.Second)))

	p.send(toolCallFrame(allowBigIntID, mcpApprovedTool, "proof-4-permitted"))
	p.send(toolCallFrame(denyBigIntID, mcpDeniedTool, "proof-4-denied-number"))
	p.send(toolCallFrame(denyStringID, mcpDeniedTool, "proof-4-denied-string"))

	replies := p.nextFrames(3, 20*time.Second)
	// replyByID already fails unless a reply carries these EXACT bytes; the
	// assertions below name the property that makes that failure meaningful.
	allow := replyByID(t, replies, allowBigIntID)
	denyNumber := replyByID(t, replies, denyBigIntID)
	denyString := replyByID(t, replies, denyStringID)
	assertCallSucceeded(t, allow, mcpApprovedTool)
	assertDenied(t, denyNumber, mcpDeniedTool)
	assertDenied(t, denyString, mcpDeniedTool)

	if string(allow.ID) != allowBigIntID {
		t.Errorf("allowed reply id = %s, want the exact bytes %s -- a float64 round trip yields 9007199254740992",
			allow.ID, allowBigIntID)
	}
	if string(denyNumber.ID) != denyBigIntID {
		t.Errorf("denial id = %s, want the exact bytes %s -- a denial is synthesized by the proxy, so this is "+
			"where correlation is easiest to lose, and a re-encoded number is how it loses it",
			denyNumber.ID, denyBigIntID)
	}
	if string(denyString.ID) != denyStringID {
		t.Errorf("denial id = %s, want the exact bytes %s", denyString.ID, denyStringID)
	}

	p.closeStdin()
	if code := p.waitForExit(30 * time.Second); code != 0 {
		t.Errorf("stratium-pep mcp exit = %d, want 0; stderr: %s", code, p.stderr.String())
	}

	// The agent->upstream direction, read off the upstream's own record.
	calls := toolCallRecords(p.records())
	if len(calls) != 1 {
		t.Fatalf("upstream recorded %d tools/call, want exactly 1 (the allowed one): %+v", len(calls), calls)
	}
	if string(calls[0].ID) != allowBigIntID {
		t.Errorf("id that REACHED the upstream = %s, want the exact bytes %s", calls[0].ID, allowBigIntID)
	}
}

// Proof 5. The proxy launches and reaps its child: the upstream process
// exists while the session runs and is gone afterwards.
//
// The pid is written on every record, so it exists only once a frame has
// landed. This waits on the initialize REPLY rather than polling the record
// file, which is sound because mcpupstream records BEFORE it replies
// (serveRecording: appendRecord, then writeFrame) -- a reply in hand is proof
// the record is already on disk.
//
// upstreamPID additionally asserts the pid is neither the proxy's nor this
// test's, without which "launches a child" would be satisfied by a proxy that
// served the frames itself.
func TestIntegration_MCP_E2E_ProxyLaunchesAndReapsItsChild(t *testing.T) {
	f := newMCPFixture(t, "lifecycle")
	p := f.start(t)

	p.send(initializeFrame("1"))
	assertCallSucceededInit(t, decodeReply(t, p.nextFrame(15*time.Second)))

	pid := upstreamPID(t, p)
	if !processAlive(pid) {
		t.Fatalf("upstream pid %d is not alive while the session is running -- the proxy must keep its child "+
			"up for the life of the relay", pid)
	}

	p.closeStdin()
	if code := p.waitForExit(30 * time.Second); code != 0 {
		t.Errorf("stratium-pep mcp exit = %d, want 0; stderr: %s", code, p.stderr.String())
	}

	// Reaped, not merely told to go: runMCPCmd calls cmd.Wait() before it
	// returns, so once the proxy is gone its child is fully collected rather
	// than left as a zombie for init to inherit.
	//
	// A pid reused by an unrelated process between those two lines would
	// defeat this check; over the microseconds involved that is not a real
	// risk, and there is no portable way to ask "is THIS process still alive"
	// about a grandchild this process never owned.
	if processAlive(pid) {
		t.Errorf("upstream pid %d is still alive after the proxy exited -- the child must be reaped, not "+
			"orphaned", pid)
	}
}

// Proof 6. An upstream that dies mid-session fails closed: no result is
// invented, no call is allowed through, and the proxy exits rather than
// hanging.
//
// THE PERMITTED TOOL IS USED HERE, deliberately. A denied tool would make
// "no call reached the upstream" true for a reason that has nothing to do
// with the upstream being dead. The call sent after the kill is one the PDP
// would ALLOW, so the only thing standing between it and the upstream is the
// transport having failed closed.
//
// STDIN IS NEVER CLOSED before the exit assertion. "The proxy exits rather
// than hanging" is a claim about what the UPSTREAM'S death does on its own
// (runMCP cancels the shared context when the upstream direction ends);
// hanging up first would prove only that a proxy exits when told to.
func TestIntegration_MCP_E2E_UpstreamDiesMidSession_FailsClosed(t *testing.T) {
	f := newMCPFixture(t, "upstreamdeath")
	p := f.start(t)

	p.send(initializeFrame("1"))
	assertCallSucceededInit(t, decodeReply(t, p.nextFrame(15*time.Second)))
	pid := upstreamPID(t, p)

	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatalf("SIGKILL upstream pid %d: %v", pid, err)
	}

	p.send(toolCallFrame("2", mcpApprovedTool, "proof-6-after-death"))

	// Nothing may come back that looks like an answer. A denial (a
	// JSON-RPC error) would still be fail-closed and is tolerated; a RESULT
	// would mean a frame was invented for a call nothing could have served.
	// In practice the frame is usually never read at all -- the context is
	// already cancelled -- and this asserts the invariant that holds either
	// way.
	assertNoResultFrame(t, p, 3*time.Second)

	code := p.waitForExit(30 * time.Second)
	t.Logf("after SIGKILLing upstream pid %d: mcp exit = %d, stderr = %q", pid, code, p.stderr.String())
	if code == 0 {
		t.Errorf("stratium-pep mcp exit = 0 after its upstream was SIGKILLed, want non-zero -- a dead child "+
			"must be reported, not absorbed; stderr: %s", p.stderr.String())
	}

	// The upstream's own record, again: initialize is there (so the file and
	// the recording path were demonstrably working right up until the kill --
	// the same positive control proof 2 needs), and the tools/call that
	// followed the kill is not.
	recs := p.records()
	if !recordedMethod(recs, "initialize") {
		t.Fatalf("upstream recorded %+v, want the pre-kill initialize among them -- without it the absence "+
			"below would pass vacuously", recs)
	}
	if calls := toolCallRecords(recs); len(calls) != 0 {
		t.Errorf("upstream recorded %d tools/call after being SIGKILLed: %+v", len(calls), calls)
	}
}

// assertNoResultFrame asserts that any frame arriving within d is a
// JSON-RPC error, never a result. See proof 6 for why an error is acceptable
// here and a result is not.
func assertNoResultFrame(t *testing.T, p *mcpProxy, d time.Duration) {
	t.Helper()
	deadline := time.After(d)
	for {
		select {
		case line, ok := <-p.frames:
			if !ok {
				return
			}
			r := decodeReply(t, line)
			if r.Error == nil {
				t.Fatalf("mcp produced a RESULT frame with its upstream dead: %s -- no reply may be invented", line)
			}
		case <-deadline:
			return
		}
	}
}

// Proof 7. The token comes from the SESSION FILE, not from the frames: a
// session file naming a revoked delegation denies.
//
// The two runs send BYTE-IDENTICAL frames -- same method, same id, same tool,
// same arguments. Nothing in the JSON-RPC stream carries a credential at all,
// and nothing about it changes between the runs. The only thing that changes
// is the state of the delegation the SESSION FILE names. Run 1 allows and
// reaches the upstream; run 2 denies, naming the revocation, and does not.
// That is the credential path the trust model claims, demonstrated as the one
// actually being consulted.
//
// TWO PROCESSES, not one session with a revoke in the middle, because the
// revoke must be strictly ordered between the two calls and a single mcp
// process decides tools/call frames on independent goroutines by design. Both
// runs share ONE record file, so the count assertion at the end spans both.
//
// Run 2's own initialize is the positive control: its record proves run 2's
// upstream was up and writing, so the missing tools/call record is a
// statement about that call rather than about the process.
func TestIntegration_MCP_E2E_RevokedDelegationInSessionFileDenies(t *testing.T) {
	f := newMCPFixture(t, "sessionfile")

	// The one frame both runs send, verbatim.
	callFrame := toolCallFrame("2", mcpApprovedTool, "proof-7-identical-payload")

	run1 := f.start(t)
	run1.send(initializeFrame("1"))
	assertCallSucceededInit(t, decodeReply(t, run1.nextFrame(15*time.Second)))
	run1.send(callFrame)
	assertCallSucceeded(t, decodeReply(t, run1.nextFrame(15*time.Second)), mcpApprovedTool)
	run1.closeStdin()
	if code := run1.waitForExit(30 * time.Second); code != 0 {
		t.Fatalf("run 1 exit = %d, want 0; stderr: %s", code, run1.stderr.String())
	}
	afterRun1 := run1.records()
	assertRecordedTools(t, afterRun1, mcpApprovedTool)

	// A real revocation -- a raw SQL UPDATE, which is the only way a
	// revocation happens in this system today (the same technique
	// revocation_epoch_e2e_integration_test.go and cache_e2e_integration_test.go
	// both use). The session file is NOT touched: it still names this
	// delegation and still carries its token.
	withTenantTx(t, mcpTenant, func(tx *sql.Tx) {
		if _, err := tx.ExecContext(t.Context(),
			`UPDATE delegations SET revoked = true, revoked_at = NOW() WHERE id = $1`, f.delegationID); err != nil {
			t.Fatalf("UPDATE delegations (revoke): %v", err)
		}
	})

	run2 := f.start(t)
	run2.send(initializeFrame("1"))
	assertCallSucceededInit(t, decodeReply(t, run2.nextFrame(15*time.Second)))
	run2.send(callFrame)
	revokedDenial := decodeReply(t, run2.nextFrame(20*time.Second))
	if revokedDenial.Error != nil {
		t.Logf("live denial for the IDENTICAL frame, session file naming a revoked delegation -> code=%d message=%q",
			revokedDenial.Error.Code, revokedDenial.Error.Message)
	}
	// "revoked" is the live PDP's own word, reached through the one reissue
	// attempt decideAndRelay makes on any DENY: IssueToken refuses a revoked
	// delegation outright (internal/pdpgrpc/token.go), so the denial carries
	// that refusal's text. Asserting on it is what distinguishes "the PDP was
	// really asked, and really said no, for THIS reason" from any other
	// fail-closed path that would also produce an error frame.
	assertDenied(t, revokedDenial, "revoked")
	run2.closeStdin()
	if code := run2.waitForExit(30 * time.Second); code != 0 {
		t.Errorf("run 2 exit = %d, want 0 -- a denied call is not a transport failure; stderr: %s",
			code, run2.stderr.String())
	}

	// Both runs append to ONE record file, so run 2's own contribution is
	// everything past run 1's. Sliced rather than searched: run 1's own
	// initialize would satisfy a whole-file "an initialize is present" check
	// no matter what run 2 did, which is exactly the vacuous pass this
	// control exists to rule out.
	recs := run2.records()
	if len(recs) <= len(afterRun1) {
		t.Fatalf("run 2's upstream added no records at all (%d before, %d after) -- it never started, or never "+
			"received the initialize, so the absence below would prove nothing", len(afterRun1), len(recs))
	}
	run2Records := recs[len(afterRun1):]
	if !recordedMethod(run2Records, "initialize") {
		t.Fatalf("run 2's upstream recorded %+v, want its own initialize among them -- without it the absence "+
			"below would pass vacuously", run2Records)
	}
	if calls := toolCallRecords(run2Records); len(calls) != 0 {
		t.Errorf("run 2 recorded %d tools/call: %+v -- the identical frame run 1 was allowed to make must not "+
			"reach the upstream once the session file's delegation is revoked", len(calls), calls)
	}
	// And across the whole file: still exactly the one tools/call run 1 made.
	assertRecordedTools(t, recs, mcpApprovedTool)
}
