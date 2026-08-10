package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"stratium/internal/pdpgrpc"
	"stratium/pkg/models"
)

// testSessionStartCfg is a valid baseline config: a fresh agent/subject and
// a session file path under a test-scoped temp directory that does not yet
// exist, so a test that never expects a write does not accidentally pass
// because something else created the file first.
func testSessionStartCfg(t *testing.T) sessionStartConfig {
	t.Helper()
	return sessionStartConfig{
		PDPAddr:         "unused: tests dial their own fake client directly",
		AgentID:         uuid.NewString(),
		Subject:         "alice@example.com",
		SessionFilePath: filepath.Join(t.TempDir(), "session.json"),
		RequestedTier:   int32(models.ActionTierReadOnly),
		RequestedTools:  []string{"Read"},
		Purpose:         "test session",
		TTLSeconds:      3600,
	}
}

// writeStaleFile seeds path with content resembling a session file left
// over from a previous run, so a test can assert a failure path actually
// removes it -- "never writes a new file" and "removes an old one" are two
// different bugs, and this is what lets a test tell them apart.
func writeStaleFile(t *testing.T, path string) {
	t.Helper()
	stale := `{"delegation_id":"yesterday","granted_scope":{"max_action_tier":4,"tools":["Bash"]}}`
	if err := os.WriteFile(path, []byte(stale), sessionFileMode); err != nil {
		t.Fatalf("seed stale session file: %v", err)
	}
}

// assertNoSessionFile fails the test unless path is absent -- covers both
// "a new file was never written" and "a stale file was not removed" with
// one assertion, since both bugs leave a different, wrong thing at path.
func assertNoSessionFile(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("session file at %s: Stat error = %v, want a not-exist error (no file, old or new, must remain)", path, err)
	}
}

func readSessionFile(t *testing.T, path string) *pdpgrpc.CreateDelegationResponse {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read session file: %v", err)
	}
	var resp pdpgrpc.CreateDelegationResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		t.Fatalf("session file is not well-formed JSON: %v\ncontent: %s", err, data)
	}
	return &resp
}

func TestRunSessionStart_Success_WritesIDAndGrantedScope(t *testing.T) {
	fake := &fakePDP{createResp: &pdpgrpc.CreateDelegationResponse{
		DelegationId: "deleg-success",
		GrantedScope: &pdpgrpc.GrantedScope{
			MaxActionTier: int32(models.ActionTierReadOnly),
			Tools:         []string{"Read"},
		},
	}}
	client := startFakePDP(t, fake)
	cfg := testSessionStartCfg(t)

	var stderr bytes.Buffer
	code := runSessionStart(client, cfg, &stderr)

	if code != 0 {
		t.Fatalf("runSessionStart() = %d, want 0; stderr: %s", code, stderr.String())
	}
	if fake.createRequestCount() != 1 {
		t.Fatalf("CreateDelegation was called %d times, want exactly 1", fake.createRequestCount())
	}

	got := readSessionFile(t, cfg.SessionFilePath)
	if got.GetDelegationId() != "deleg-success" {
		t.Errorf("delegation_id = %q, want %q", got.GetDelegationId(), "deleg-success")
	}
	if got.GetGrantedScope().GetMaxActionTier() != int32(models.ActionTierReadOnly) {
		t.Errorf("granted_scope.max_action_tier = %d, want %d",
			got.GetGrantedScope().GetMaxActionTier(), models.ActionTierReadOnly)
	}
	if !reflect.DeepEqual(got.GetGrantedScope().GetTools(), []string{"Read"}) {
		t.Errorf("granted_scope.tools = %v, want %v", got.GetGrantedScope().GetTools(), []string{"Read"})
	}

	// The atomic write in writeSessionFile must leave no temp file behind.
	entries, err := os.ReadDir(filepath.Dir(cfg.SessionFilePath))
	if err != nil {
		t.Fatalf("read session dir: %v", err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".stratium-pep-session-") {
			t.Errorf("temp session file %q left behind after a successful write", e.Name())
		}
	}
}

// The session file names a live delegation: a mode looser than 0600 would
// make it group- or world-readable the instant it exists.
func TestRunSessionStart_SessionFileMode0600(t *testing.T) {
	fake := &fakePDP{createResp: &pdpgrpc.CreateDelegationResponse{
		DelegationId: "deleg-mode",
		GrantedScope: &pdpgrpc.GrantedScope{
			MaxActionTier: int32(models.ActionTierReadOnly),
			Tools:         []string{"Read"},
		},
	}}
	client := startFakePDP(t, fake)
	cfg := testSessionStartCfg(t)

	if code := runSessionStart(client, cfg, &bytes.Buffer{}); code != 0 {
		t.Fatalf("runSessionStart() = %d, want 0", code)
	}

	info, err := os.Stat(cfg.SessionFilePath)
	if err != nil {
		t.Fatalf("stat session file: %v", err)
	}
	if perm := info.Mode().Perm(); perm != sessionFileMode {
		t.Errorf("session file mode = %#o, want %#o", perm, sessionFileMode)
	}
}

// The request this test sends asks for DESTRUCTIVE and three tools; the
// fixture PDP response grants only INTERNAL_MODIFY and one, the way the real
// gate clamps an over-broad request. The file must record what came back,
// not what was asked for -- including the removals and their reasons, so a
// later denial is legible against this session's actual authority.
func TestRunSessionStart_Clamped_WritesGrantedNotRequested(t *testing.T) {
	fake := &fakePDP{createResp: &pdpgrpc.CreateDelegationResponse{
		DelegationId: "deleg-clamped",
		GrantedScope: &pdpgrpc.GrantedScope{
			MaxActionTier: int32(models.ActionTierInternalModify),
			Tools:         []string{"Read"},
			Removed: []*pdpgrpc.ScopeRemoval{
				{Dimension: "tier", Value: "DESTRUCTIVE", Reason: "denied"},
				{Dimension: "tool", Value: "Bash", Reason: "denied"},
				{Dimension: "tool", Value: "Write", Reason: "denied"},
			},
		},
	}}
	client := startFakePDP(t, fake)

	cfg := testSessionStartCfg(t)
	cfg.RequestedTier = int32(models.ActionTierDestructive)
	cfg.RequestedTools = []string{"Bash", "Read", "Write"}

	var stderr bytes.Buffer
	if code := runSessionStart(client, cfg, &stderr); code != 0 {
		t.Fatalf("runSessionStart() = %d, want 0; stderr: %s", code, stderr.String())
	}

	got := readSessionFile(t, cfg.SessionFilePath)

	if got.GetGrantedScope().GetMaxActionTier() == cfg.RequestedTier {
		t.Fatalf("file records the requested tier (%d); want the granted, clamped tier instead", cfg.RequestedTier)
	}
	if got.GetGrantedScope().GetMaxActionTier() != int32(models.ActionTierInternalModify) {
		t.Errorf("granted_scope.max_action_tier = %d, want %d (INTERNAL_MODIFY, the clamp)",
			got.GetGrantedScope().GetMaxActionTier(), models.ActionTierInternalModify)
	}
	if !reflect.DeepEqual(got.GetGrantedScope().GetTools(), []string{"Read"}) {
		t.Errorf("granted_scope.tools = %v, want %v (the clamp, not the 3 tools requested)",
			got.GetGrantedScope().GetTools(), []string{"Read"})
	}

	removed := got.GetGrantedScope().GetRemoved()
	if len(removed) != 3 {
		t.Fatalf("granted_scope.removed has %d entries, want 3 -- the removals and their reasons must be cached too",
			len(removed))
	}
	for _, want := range []string{"DESTRUCTIVE", "Bash", "Write"} {
		found := false
		for _, r := range removed {
			if r.GetValue() == want && r.GetReason() == "denied" {
				found = true
			}
		}
		if !found {
			t.Errorf("granted_scope.removed is missing an entry for %q with reason \"denied\"", want)
		}
	}
}

// The request sent to CreateDelegation must carry cfg's configured scope
// through every field the RPC defines -- if it did not, cfg would be dead
// configuration and something else would be deciding what this session
// actually asks for. Mirrors hook_test.go's
// TestRunHook_RequestCarriesRawInputAndNoDeclaredTier, same discipline
// applied to session-start's own request.
func TestRunSessionStart_RequestCarriesConfiguredScope(t *testing.T) {
	fake := &fakePDP{createResp: &pdpgrpc.CreateDelegationResponse{
		DelegationId: "deleg-req-shape",
		GrantedScope: &pdpgrpc.GrantedScope{MaxActionTier: int32(models.ActionTierReadOnly), Tools: []string{"Read"}},
	}}
	client := startFakePDP(t, fake)

	cfg := testSessionStartCfg(t)
	cfg.RequestedTier = int32(models.ActionTierExternalComms)
	cfg.RequestedTools = []string{"WebFetch", "Read"}
	cfg.Purpose = "nightly report generation"
	cfg.TTLSeconds = 7200

	var stderr bytes.Buffer
	if code := runSessionStart(client, cfg, &stderr); code != 0 {
		t.Fatalf("runSessionStart() = %d, want 0; stderr: %s", code, stderr.String())
	}

	req := fake.lastCreateRequest()
	if req == nil {
		t.Fatal("PDP never received a CreateDelegation request")
	}
	if req.GetSubject() != cfg.Subject {
		t.Errorf("subject = %q, want %q", req.GetSubject(), cfg.Subject)
	}
	if req.GetAgentId() != cfg.AgentID {
		t.Errorf("agent_id = %q, want %q", req.GetAgentId(), cfg.AgentID)
	}
	if req.GetRequestedScope().GetMaxActionTier() != cfg.RequestedTier {
		t.Errorf("requested_scope.max_action_tier = %d, want %d",
			req.GetRequestedScope().GetMaxActionTier(), cfg.RequestedTier)
	}
	if !reflect.DeepEqual(req.GetRequestedScope().GetTools(), cfg.RequestedTools) {
		t.Errorf("requested_scope.tools = %v, want %v", req.GetRequestedScope().GetTools(), cfg.RequestedTools)
	}
	if req.GetPurpose() != cfg.Purpose {
		t.Errorf("purpose = %q, want %q", req.GetPurpose(), cfg.Purpose)
	}
	if req.GetTtlSeconds() != cfg.TTLSeconds {
		t.Errorf("ttl_seconds = %d, want %d", req.GetTtlSeconds(), cfg.TTLSeconds)
	}
	if req.GetParentDelegationId() != "" {
		t.Errorf("parent_delegation_id = %q, want empty -- a session delegation is always a root grant",
			req.GetParentDelegationId())
	}
}

// runSessionStart calls removeStaleSessionFile from two independent places:
// after CreateDelegation itself fails, and after it succeeds but the local
// write does not. The tests above only exercise the first. This exercises
// the second -- CreateDelegation succeeds, but the write fails because the
// session file path is already occupied by an empty directory, which
// os.Rename cannot replace with a file -- so a mutation deleting only the
// write-failure branch's removal call cannot hide behind the other tests.
func TestRunSessionStart_WriteFails_RemovesAnyExistingFile(t *testing.T) {
	fake := &fakePDP{createResp: &pdpgrpc.CreateDelegationResponse{
		DelegationId: "deleg-write-fails",
		GrantedScope: &pdpgrpc.GrantedScope{MaxActionTier: int32(models.ActionTierReadOnly), Tools: []string{"Read"}},
	}}
	client := startFakePDP(t, fake)

	cfg := testSessionStartCfg(t)
	if err := os.Mkdir(cfg.SessionFilePath, 0o700); err != nil {
		t.Fatalf("seed a directory at the session file path: %v", err)
	}

	var stderr bytes.Buffer
	code := runSessionStart(client, cfg, &stderr)

	if code != 1 {
		t.Fatalf("runSessionStart() = %d, want 1", code)
	}
	assertNoSessionFile(t, cfg.SessionFilePath)
	if stderr.Len() == 0 {
		t.Error("stderr is empty, want a reason saying the session file could not be written")
	}
}

func TestRunSessionStart_CreationFails_WritesNoFileAndRemovesStale(t *testing.T) {
	fake := &fakePDP{createErr: status.Error(codes.PermissionDenied, "none of the requested tools are held by this principal")}
	client := startFakePDP(t, fake)

	cfg := testSessionStartCfg(t)
	writeStaleFile(t, cfg.SessionFilePath)

	var stderr bytes.Buffer
	code := runSessionStart(client, cfg, &stderr)

	if code != 1 {
		t.Fatalf("runSessionStart() = %d, want 1", code)
	}
	assertNoSessionFile(t, cfg.SessionFilePath)
	if !strings.Contains(stderr.String(), "none of the requested tools") {
		t.Errorf("stderr = %q, want it to carry the PDP's reason", stderr.String())
	}
}

// A creation failure with no prior session file is the more common case in
// practice (first session of the day) -- distinct from the stale-removal
// test above, which proves the opposite direction: an old file being
// cleaned up, not merely a new one never appearing.
func TestRunSessionStart_CreationFails_NoFileWritten(t *testing.T) {
	fake := &fakePDP{createErr: status.Error(codes.Internal, "boom")}
	client := startFakePDP(t, fake)
	cfg := testSessionStartCfg(t)

	if code := runSessionStart(client, cfg, &bytes.Buffer{}); code != 1 {
		t.Fatalf("runSessionStart() = %d, want 1", code)
	}
	assertNoSessionFile(t, cfg.SessionFilePath)
}

func TestRunSessionStart_UnreachablePDP_FailsClosedAndRemovesStale(t *testing.T) {
	client := unreachablePDPClient(t)

	cfg := testSessionStartCfg(t)
	writeStaleFile(t, cfg.SessionFilePath)

	var stderr bytes.Buffer
	code := runSessionStart(client, cfg, &stderr)

	if code != 1 {
		t.Fatalf("runSessionStart() = %d, want 1", code)
	}
	assertNoSessionFile(t, cfg.SessionFilePath)
	if stderr.Len() == 0 {
		t.Error("stderr is empty, want a reason saying the PDP could not be reached")
	}
}

// A response the real PDP would never send (see CreateDelegationResponse's
// own doc comment) but a fake or future implementation might: this proves
// runSessionStart does not trust it just because err == nil.
func TestRunSessionStart_MalformedResponse_FailsClosedAndRemovesStale(t *testing.T) {
	tests := []struct {
		name string
		resp *pdpgrpc.CreateDelegationResponse
	}{
		{
			name: "empty delegation id",
			resp: &pdpgrpc.CreateDelegationResponse{
				GrantedScope: &pdpgrpc.GrantedScope{MaxActionTier: 1, Tools: []string{"Read"}},
			},
		},
		{
			name: "nil granted scope",
			resp: &pdpgrpc.CreateDelegationResponse{DelegationId: uuid.NewString()},
		},
		{
			name: "entirely empty response",
			resp: &pdpgrpc.CreateDelegationResponse{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakePDP{createResp: tt.resp}
			client := startFakePDP(t, fake)

			cfg := testSessionStartCfg(t)
			writeStaleFile(t, cfg.SessionFilePath)

			var stderr bytes.Buffer
			code := runSessionStart(client, cfg, &stderr)

			if code != 1 {
				t.Fatalf("runSessionStart() = %d, want 1", code)
			}
			assertNoSessionFile(t, cfg.SessionFilePath)
			if stderr.Len() == 0 {
				t.Error("stderr is empty, want a reason naming the malformed response")
			}
		})
	}
}

func clearSessionStartEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"STRATIUM_PEP_PDP_ADDR", "STRATIUM_PEP_AGENT_ID", "STRATIUM_PEP_SUBJECT",
		"STRATIUM_PEP_SESSION_FILE", "STRATIUM_PEP_REQUESTED_TIER",
		"STRATIUM_PEP_REQUESTED_TOOLS", "STRATIUM_PEP_TTL_SECONDS", "STRATIUM_PEP_PURPOSE",
	} {
		t.Setenv(k, "")
	}
}

func TestLoadSessionStartConfigFromEnv(t *testing.T) {
	t.Run("all set", func(t *testing.T) {
		clearSessionStartEnv(t)
		t.Setenv("STRATIUM_PEP_PDP_ADDR", "localhost:50051")
		t.Setenv("STRATIUM_PEP_AGENT_ID", "agent-1")
		t.Setenv("STRATIUM_PEP_SUBJECT", "alice@example.com")
		t.Setenv("STRATIUM_PEP_SESSION_FILE", "/tmp/stratium-pep-session.json")
		t.Setenv("STRATIUM_PEP_REQUESTED_TIER", "2")
		t.Setenv("STRATIUM_PEP_REQUESTED_TOOLS", "Read, Grep,Bash")
		t.Setenv("STRATIUM_PEP_TTL_SECONDS", "3600")
		t.Setenv("STRATIUM_PEP_PURPOSE", "an agent session")

		cfg, err := loadSessionStartConfigFromEnv()
		if err != nil {
			t.Fatalf("loadSessionStartConfigFromEnv() error = %v, want nil", err)
		}
		want := sessionStartConfig{
			PDPAddr:         "localhost:50051",
			AgentID:         "agent-1",
			Subject:         "alice@example.com",
			SessionFilePath: "/tmp/stratium-pep-session.json",
			RequestedTier:   2,
			RequestedTools:  []string{"Read", "Grep", "Bash"}, // comma-separated, trimmed
			Purpose:         "an agent session",
			TTLSeconds:      3600,
		}
		if !reflect.DeepEqual(cfg, want) {
			t.Errorf("loadSessionStartConfigFromEnv() = %+v, want %+v", cfg, want)
		}
	})

	t.Run("purpose is optional", func(t *testing.T) {
		clearSessionStartEnv(t)
		t.Setenv("STRATIUM_PEP_PDP_ADDR", "localhost:50051")
		t.Setenv("STRATIUM_PEP_AGENT_ID", "agent-1")
		t.Setenv("STRATIUM_PEP_SUBJECT", "alice@example.com")
		t.Setenv("STRATIUM_PEP_SESSION_FILE", "/tmp/stratium-pep-session.json")
		t.Setenv("STRATIUM_PEP_REQUESTED_TIER", "0")
		t.Setenv("STRATIUM_PEP_REQUESTED_TOOLS", "Read")
		t.Setenv("STRATIUM_PEP_TTL_SECONDS", "60")

		cfg, err := loadSessionStartConfigFromEnv()
		if err != nil {
			t.Fatalf("loadSessionStartConfigFromEnv() error = %v, want nil", err)
		}
		if cfg.Purpose != "" {
			t.Errorf("Purpose = %q, want empty", cfg.Purpose)
		}
	})

	t.Run("missing variable is named in the error", func(t *testing.T) {
		clearSessionStartEnv(t)
		t.Setenv("STRATIUM_PEP_PDP_ADDR", "localhost:50051")
		t.Setenv("STRATIUM_PEP_AGENT_ID", "agent-1")
		t.Setenv("STRATIUM_PEP_SUBJECT", "alice@example.com")
		t.Setenv("STRATIUM_PEP_REQUESTED_TIER", "1")
		t.Setenv("STRATIUM_PEP_REQUESTED_TOOLS", "Read")
		t.Setenv("STRATIUM_PEP_TTL_SECONDS", "60")
		// STRATIUM_PEP_SESSION_FILE left unset.

		_, err := loadSessionStartConfigFromEnv()
		if err == nil {
			t.Fatal("loadSessionStartConfigFromEnv() error = nil, want an error naming STRATIUM_PEP_SESSION_FILE")
		}
		if !strings.Contains(err.Error(), "STRATIUM_PEP_SESSION_FILE") {
			t.Errorf("error = %q, want it to name STRATIUM_PEP_SESSION_FILE", err.Error())
		}
	})

	t.Run("non-numeric tier", func(t *testing.T) {
		clearSessionStartEnv(t)
		t.Setenv("STRATIUM_PEP_PDP_ADDR", "localhost:50051")
		t.Setenv("STRATIUM_PEP_AGENT_ID", "agent-1")
		t.Setenv("STRATIUM_PEP_SUBJECT", "alice@example.com")
		t.Setenv("STRATIUM_PEP_SESSION_FILE", "/tmp/stratium-pep-session.json")
		t.Setenv("STRATIUM_PEP_REQUESTED_TIER", "not-a-number")
		t.Setenv("STRATIUM_PEP_REQUESTED_TOOLS", "Read")
		t.Setenv("STRATIUM_PEP_TTL_SECONDS", "60")

		_, err := loadSessionStartConfigFromEnv()
		if err == nil {
			t.Fatal("loadSessionStartConfigFromEnv() error = nil, want an error naming STRATIUM_PEP_REQUESTED_TIER")
		}
		if !strings.Contains(err.Error(), "STRATIUM_PEP_REQUESTED_TIER") {
			t.Errorf("error = %q, want it to name STRATIUM_PEP_REQUESTED_TIER", err.Error())
		}
	})

	t.Run("ttl not positive", func(t *testing.T) {
		clearSessionStartEnv(t)
		t.Setenv("STRATIUM_PEP_PDP_ADDR", "localhost:50051")
		t.Setenv("STRATIUM_PEP_AGENT_ID", "agent-1")
		t.Setenv("STRATIUM_PEP_SUBJECT", "alice@example.com")
		t.Setenv("STRATIUM_PEP_SESSION_FILE", "/tmp/stratium-pep-session.json")
		t.Setenv("STRATIUM_PEP_REQUESTED_TIER", "1")
		t.Setenv("STRATIUM_PEP_REQUESTED_TOOLS", "Read")
		t.Setenv("STRATIUM_PEP_TTL_SECONDS", "0")

		_, err := loadSessionStartConfigFromEnv()
		if err == nil {
			t.Fatal("loadSessionStartConfigFromEnv() error = nil, want an error about a non-positive TTL")
		}
		if !strings.Contains(err.Error(), "STRATIUM_PEP_TTL_SECONDS") {
			t.Errorf("error = %q, want it to name STRATIUM_PEP_TTL_SECONDS", err.Error())
		}
	})
}

// Missing configuration is a fail-closed path like hook's own
// (TestRunHookCmd_MissingConfig_Denies): a session started with a guessed
// identity or scope is worse than one that refuses to start.
func TestRunSessionStartCmd_MissingConfig_FailsClosed(t *testing.T) {
	clearSessionStartEnv(t)

	var stderr bytes.Buffer
	code := runSessionStartCmd(&stderr)

	if code != 1 {
		t.Fatalf("runSessionStartCmd() = %d, want 1", code)
	}
	if stderr.Len() == 0 {
		t.Error("stderr is empty, want a reason naming the missing configuration")
	}
}
