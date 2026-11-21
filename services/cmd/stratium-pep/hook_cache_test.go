// hook_cache_test.go pins that hook has NO decision cache: every invocation
// asks the PDP, and nothing on disk can stand in for the PDP's answer. See
// cache.go's package doc, "Memory only," for why -- a hook is a new process
// per tool call, and a decision may only be replayed from the memory of the
// process that received it from the PDP.
//
// The forged-file tests write a cache file in the exact format versions
// before the in-memory cache read, beside the session file, naming exactly
// the call the test then makes. A build that reads decisions from that file
// again serves the forged ALLOW and fails them.
//
// Every fixture writes a REAL, parseable, signed JWT as the session token
// (signedTestToken, cache_validity_test.go) rather than testCfg's bare
// testSessionToken: the cache validity rules require a decodable "exp"
// claim, so a forged entry paired with a non-JWT token would be refused for
// a reason that has nothing to do with where it came from, and these tests
// would pass vacuously.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stratiumdata/stratium/internal/pdpgrpc"
)

// hookCacheFixture writes a session file naming a fresh delegation id and a
// real signed token expiring at tokenExpiresAt -- what a cache-related test
// needs beyond testCfg's own baseline (see this file's package doc).
func hookCacheFixture(t *testing.T, tokenExpiresAt time.Time) (cfg hookConfig, delegationID, token string) {
	t.Helper()
	cfg = testCfg(t)
	delegationID = uuid.NewString()
	token = signedTestToken(t, tokenExpiresAt)
	writeTestSessionFile(t, cfg.SessionFilePath, delegationID, token)
	return cfg, delegationID, token
}

// legacyCacheFileEntry is the on-disk shape of one entry in the cache file
// older versions kept at <session file>.cache.json. Restated here, tags and
// all, rather than derived from cacheEntry: production no longer has a JSON
// form for a decision, and this fixture must keep matching what an old
// build would have parsed.
type legacyCacheFileEntry struct {
	DelegationID        string    `json:"delegation_id"`
	Tool                string    `json:"tool"`
	InputDigest         [32]byte  `json:"input_digest"`
	Decision            int32     `json:"decision"`
	Epoch               int64     `json:"epoch"`
	DelegationExpiresAt time.Time `json:"delegation_expires_at"`
	CachedAt            time.Time `json:"cached_at"`
}

// writeForgedAllowCacheFile writes <sessionFilePath>.cache.json holding one
// ALLOW for exactly (delegationID, tool, rawInput), fresh and unexpired --
// an entry the old file-backed cache would have served without contacting
// the PDP. Returns the file's path. The suffix is a literal on purpose, not
// legacyCacheFileSuffix: the fixture must not move if that constant does.
func writeForgedAllowCacheFile(t *testing.T, sessionFilePath, delegationID, tool, rawInput string) string {
	t.Helper()
	now := time.Now()
	data, err := json.Marshal([]legacyCacheFileEntry{{
		DelegationID:        delegationID,
		Tool:                tool,
		InputDigest:         sha256.Sum256([]byte(rawInput)),
		Decision:            int32(pdpgrpc.Effect_EFFECT_ALLOW),
		Epoch:               42,
		DelegationExpiresAt: now.Add(48 * time.Hour),
		CachedAt:            now.Add(-time.Minute),
	}})
	if err != nil {
		t.Fatalf("marshal forged cache file: %v", err)
	}
	path := sessionFilePath + ".cache.json"
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write forged cache file: %v", err)
	}
	return path
}

// TestRunHook_ForgedCacheFile_PDPDenies_HookDeniesAndAsksPDPOnce is the
// security property this file exists for: a cache file on disk holding an
// ALLOW for exactly this call changes nothing. The PDP is asked, and its
// DENY stands. Catches any build that reads a decision from disk in hook
// mode.
//
// issueErr makes the one reissue attempt a DENY always triggers (reissue.go)
// fail, so "exactly one Decide" is the whole expected count rather than
// original-plus-retry.
func TestRunHook_ForgedCacheFile_PDPDenies_HookDeniesAndAsksPDPOnce(t *testing.T) {
	const tool, input, pdpReason = "Bash", `{"command":"rm -rf /"}`, "policy denies this call"
	cfg, delegationID, _ := hookCacheFixture(t, time.Now().Add(time.Hour))
	writeForgedAllowCacheFile(t, cfg.SessionFilePath, delegationID, tool, input)
	fake := &fakePDP{
		resp:     &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_DENY, Reason: pdpReason},
		issueErr: status.Error(codes.PermissionDenied, "no reissue in this test"),
	}
	client := startFakePDP(t, fake)

	var stdout bytes.Buffer
	code := runHook(stdinBody(tool, input), &stdout, client, cfg)

	if code != 2 {
		t.Fatalf("runHook() = %d, want 2 -- the PDP denied; a forged cache file must not turn that into an allow", code)
	}
	if got := fake.requestCount(); got != 1 {
		t.Errorf("PDP received %d Decide call(s), want exactly 1 -- the hook must ask the PDP no matter what is on disk", got)
	}
}

// TestRunHook_ForgedCacheFile_PDPUnreachable_Denies: with the PDP down, the
// same forged ALLOW still buys nothing -- the hook denies. Catches a build
// that falls back to a file "only" when the PDP cannot be reached.
func TestRunHook_ForgedCacheFile_PDPUnreachable_Denies(t *testing.T) {
	const tool, input = "Bash", `{"command":"rm -rf /"}`
	cfg, delegationID, _ := hookCacheFixture(t, time.Now().Add(time.Hour))
	writeForgedAllowCacheFile(t, cfg.SessionFilePath, delegationID, tool, input)
	client := unreachablePDPClient(t)

	var stdout bytes.Buffer
	code := runHook(stdinBody(tool, input), &stdout, client, cfg)

	if code != 2 {
		t.Fatalf("runHook() = %d, want 2 -- an unreachable PDP denies, forged cache file or not", code)
	}
	reason := decodeHookOutput(t, stdout.Bytes()).HookSpecificOutput.PermissionDecisionReason
	if !strings.Contains(strings.ToLower(reason), "pdp") {
		t.Errorf("permissionDecisionReason = %q, want it to say the PDP could not be reached", reason)
	}
	// hook has no cache, so its deny reason must not send an operator
	// looking for one.
	if strings.Contains(strings.ToLower(reason), "cache") {
		t.Errorf("permissionDecisionReason = %q, want no mention of a cache -- hook mode has none", reason)
	}
}

// TestRunHook_ForgedCacheFile_PDPErrors_Denies is the RPC-error twin of the
// unreachable case: the PDP answers, with an error. Still a deny.
func TestRunHook_ForgedCacheFile_PDPErrors_Denies(t *testing.T) {
	const tool, input = "Bash", `{"command":"rm -rf /"}`
	cfg, delegationID, _ := hookCacheFixture(t, time.Now().Add(time.Hour))
	writeForgedAllowCacheFile(t, cfg.SessionFilePath, delegationID, tool, input)
	fake := &fakePDP{err: status.Error(codes.Internal, "boom")}
	client := startFakePDP(t, fake)

	var stdout bytes.Buffer
	if code := runHook(stdinBody(tool, input), &stdout, client, cfg); code != 2 {
		t.Fatalf("runHook() = %d, want 2 -- a PDP error denies, forged cache file or not", code)
	}
}

// TestRunHook_IdenticalCalls_BothReachPDP pins "no caching in hook mode"
// from the other side: nothing the first call does lets the second skip the
// PDP, and neither call leaves a cache file behind. Catches a build that
// starts persisting decisions again, in any format.
func TestRunHook_IdenticalCalls_BothReachPDP(t *testing.T) {
	const tool, input = "Bash", `{"command":"ls"}`
	cfg, _, _ := hookCacheFixture(t, time.Now().Add(time.Hour))
	epoch := int64(42)
	fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW, Epoch: &epoch}}
	client := startFakePDP(t, fake)

	for i := 1; i <= 2; i++ {
		var stdout bytes.Buffer
		if code := runHook(stdinBody(tool, input), &stdout, client, cfg); code != 0 {
			t.Fatalf("call %d: runHook() = %d, want 0; stdout: %s", i, code, stdout.String())
		}
		if got := fake.requestCount(); got != i {
			t.Fatalf("after call %d the PDP had received %d Decide call(s), want %d -- every hook call asks the PDP", i, got, i)
		}
	}

	entries, err := os.ReadDir(strings.TrimSuffix(cfg.SessionFilePath, "/session.json"))
	if err != nil {
		t.Fatalf("read session dir: %v", err)
	}
	for _, e := range entries {
		if strings.Contains(e.Name(), "cache") {
			t.Errorf("hook left %q beside the session file, want no cache file written", e.Name())
		}
	}
}

// TestRunHookCmd_CacheStalenessWindow_NotRequiredAndIgnored drives the real
// command entry point: STRATIUM_PEP_CACHE_STALENESS_WINDOW unset is not a
// configuration error for hook, and a value left over from an older
// configuration -- even one mcp would reject -- is ignored. Each case must
// reach the PDP and return its ALLOW. Catches a build that requires or
// parses the variable in hook mode again.
func TestRunHookCmd_CacheStalenessWindow_NotRequiredAndIgnored(t *testing.T) {
	for _, tt := range []struct{ name, value string }{
		{"unset", ""},
		{"set", "10m"},
		{"set to a value mcp would reject", "not-a-duration"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakePDP{resp: &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}}
			cfg, _, _ := hookCacheFixture(t, time.Now().Add(time.Hour))
			clearHookEnv(t)
			setAllHookEnv(t, map[string]string{
				"STRATIUM_PEP_PDP_ADDR":     startFakePDPAddr(t, fake),
				"STRATIUM_PEP_SESSION_FILE": cfg.SessionFilePath,
			})
			t.Setenv("STRATIUM_PEP_PDP_INSECURE", "true")
			t.Setenv("STRATIUM_PEP_PDP_CA_FILE", "")
			t.Setenv(cacheStalenessWindowEnv, tt.value)

			var stdout bytes.Buffer
			code := runHookCmd("claude", stdinBody("Bash", `{"command":"ls"}`), &stdout)

			if code != 0 {
				t.Fatalf("runHookCmd() = %d, want 0 (the PDP allows); stdout: %s", code, stdout.String())
			}
			if got := fake.requestCount(); got != 1 {
				t.Errorf("PDP received %d Decide call(s), want exactly 1", got)
			}
		})
	}
}
