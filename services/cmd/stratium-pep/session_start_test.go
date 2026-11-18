package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stratiumdata/stratium/internal/pdpgrpc"
	"github.com/stratiumdata/stratium/pkg/models"
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
		ConnectTimeout:  5 * time.Second,
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
		Token: "deleg-success-token",
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

// TestRunSessionStart_WritesToken_DistinctFromDelegationID is the task's own
// required test, named for exactly the property it defends: as of Phase 9
// Task 4, session-start caches the TOKEN CreateDelegation returned, not
// merely a delegation id -- both fields are present in the file (the
// delegation id survives for reissue.go's own IssueToken call), but it is
// the token a caller now depends on. DelegationId and Token below share
// nothing in common, so a bug that wrote one where the other belongs (or
// left Token as a copy of DelegationId) fails this test's second assertion,
// not just its first.
func TestRunSessionStart_WritesToken_DistinctFromDelegationID(t *testing.T) {
	const wantDelegationID = "deleg-token-proof"
	const wantToken = "token-shares-nothing-with-the-delegation-id"
	fake := &fakePDP{createResp: &pdpgrpc.CreateDelegationResponse{
		DelegationId: wantDelegationID,
		GrantedScope: &pdpgrpc.GrantedScope{MaxActionTier: int32(models.ActionTierReadOnly), Tools: []string{"Read"}},
		Token:        wantToken,
	}}
	client := startFakePDP(t, fake)
	cfg := testSessionStartCfg(t)

	if code := runSessionStart(client, cfg, &bytes.Buffer{}); code != 0 {
		t.Fatalf("runSessionStart() = %d, want 0", code)
	}

	got := readSessionFile(t, cfg.SessionFilePath)
	if got.GetToken() != wantToken {
		t.Errorf("token = %q, want %q", got.GetToken(), wantToken)
	}
	if got.GetToken() == got.GetDelegationId() {
		t.Errorf("token = %q, equals delegation_id -- the file must cache the token CreateDelegation "+
			"actually returned, not a copy of the delegation id", got.GetToken())
	}
	if got.GetDelegationId() != wantDelegationID {
		t.Errorf("delegation_id = %q, want %q -- still cached, for reissue.go's own IssueToken call",
			got.GetDelegationId(), wantDelegationID)
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
		Token: "deleg-mode-token",
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
		Token: "deleg-clamped-token",
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
		Token:        "deleg-req-shape-token",
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
		Token:        "deleg-write-fails-token",
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
			// Isolated from the other two: a valid delegation id and granted
			// scope, only the token missing -- the one field Phase 9 Task 4
			// added to this check. Without this subcase, a mutant that
			// deleted only the "|| resp.GetToken() == \"\"" clause would
			// still pass every other subcase here (each already fails for
			// its own, different reason) and would only be caught, if at
			// all, by a much later test exercising the session file it
			// wrongly let through.
			name: "empty token",
			resp: &pdpgrpc.CreateDelegationResponse{
				DelegationId: uuid.NewString(),
				GrantedScope: &pdpgrpc.GrantedScope{MaxActionTier: 1, Tools: []string{"Read"}},
			},
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
		"STRATIUM_PEP_SESSION_FILE", "STRATIUM_PEP_CONNECT_TIMEOUT", "STRATIUM_PEP_REQUESTED_TIER",
		"STRATIUM_PEP_REQUESTED_TOOLS", "STRATIUM_PEP_TTL_SECONDS", "STRATIUM_PEP_PURPOSE",
		"STRATIUM_PEP_ESCALATE_AT", "STRATIUM_PEP_PRINCIPAL_TOKEN_FILE",
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
		t.Setenv("STRATIUM_PEP_CONNECT_TIMEOUT", "5s")
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
			ConnectTimeout:  5 * time.Second,
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
		t.Setenv("STRATIUM_PEP_CONNECT_TIMEOUT", "5s")
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
		t.Setenv("STRATIUM_PEP_CONNECT_TIMEOUT", "5s")
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
		t.Setenv("STRATIUM_PEP_CONNECT_TIMEOUT", "5s")
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
		t.Setenv("STRATIUM_PEP_CONNECT_TIMEOUT", "5s")
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

	t.Run("invalid connect timeout", func(t *testing.T) {
		tests := []struct {
			name  string
			value string
		}{
			{"not a duration", "not-a-duration"},
			{"zero", "0s"},
			{"negative", "-5s"},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				clearSessionStartEnv(t)
				t.Setenv("STRATIUM_PEP_PDP_ADDR", "localhost:50051")
				t.Setenv("STRATIUM_PEP_AGENT_ID", "agent-1")
				t.Setenv("STRATIUM_PEP_SUBJECT", "alice@example.com")
				t.Setenv("STRATIUM_PEP_SESSION_FILE", "/tmp/stratium-pep-session.json")
				t.Setenv("STRATIUM_PEP_CONNECT_TIMEOUT", tt.value)
				t.Setenv("STRATIUM_PEP_REQUESTED_TIER", "1")
				t.Setenv("STRATIUM_PEP_REQUESTED_TOOLS", "Read")
				t.Setenv("STRATIUM_PEP_TTL_SECONDS", "60")

				_, err := loadSessionStartConfigFromEnv()
				if err == nil {
					t.Fatal("loadSessionStartConfigFromEnv() error = nil, want an error naming STRATIUM_PEP_CONNECT_TIMEOUT")
				}
				if !strings.Contains(err.Error(), "STRATIUM_PEP_CONNECT_TIMEOUT") {
					t.Errorf("error = %q, want it to name STRATIUM_PEP_CONNECT_TIMEOUT", err.Error())
				}
			})
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

// STRATIUM_PEP_ESCALATE_AT is optional: unset asks for nothing (the agent's
// own threshold stays in force), set is forwarded as requested_scope.escalate_at,
// and a non-number fails closed at load rather than being dropped silently.
func TestSessionStart_EscalateAt(t *testing.T) {
	setRequired := func(t *testing.T) {
		clearSessionStartEnv(t)
		t.Setenv("STRATIUM_PEP_PDP_ADDR", "localhost:50051")
		t.Setenv("STRATIUM_PEP_AGENT_ID", "agent-1")
		t.Setenv("STRATIUM_PEP_SUBJECT", "alice@example.com")
		t.Setenv("STRATIUM_PEP_SESSION_FILE", "/tmp/stratium-pep-session.json")
		t.Setenv("STRATIUM_PEP_CONNECT_TIMEOUT", "5s")
		t.Setenv("STRATIUM_PEP_REQUESTED_TIER", "4")
		t.Setenv("STRATIUM_PEP_REQUESTED_TOOLS", "Bash")
		t.Setenv("STRATIUM_PEP_TTL_SECONDS", "3600")
	}

	t.Run("unset asks for nothing", func(t *testing.T) {
		setRequired(t)
		cfg, err := loadSessionStartConfigFromEnv()
		if err != nil || cfg.EscalateAt != nil {
			t.Fatalf("cfg.EscalateAt = %v, err = %v; want nil, nil", cfg.EscalateAt, err)
		}
	})
	t.Run("set is parsed", func(t *testing.T) {
		setRequired(t)
		t.Setenv("STRATIUM_PEP_ESCALATE_AT", " 3 ")
		cfg, err := loadSessionStartConfigFromEnv()
		if err != nil || cfg.EscalateAt == nil || *cfg.EscalateAt != 3 {
			t.Fatalf("cfg.EscalateAt = %v, err = %v; want 3", cfg.EscalateAt, err)
		}
	})
	t.Run("not a number fails closed", func(t *testing.T) {
		setRequired(t)
		t.Setenv("STRATIUM_PEP_ESCALATE_AT", "high")
		if _, err := loadSessionStartConfigFromEnv(); err == nil || !strings.Contains(err.Error(), "STRATIUM_PEP_ESCALATE_AT") {
			t.Fatalf("err = %v, want one naming STRATIUM_PEP_ESCALATE_AT", err)
		}
	})
	t.Run("the request carries it", func(t *testing.T) {
		fake := &fakePDP{createResp: &pdpgrpc.CreateDelegationResponse{
			DelegationId: "deleg-esc",
			GrantedScope: &pdpgrpc.GrantedScope{MaxActionTier: 4, Tools: []string{"Bash"}},
			Token:        "deleg-esc-token",
		}}
		client := startFakePDP(t, fake)
		cfg := testSessionStartCfg(t)
		esc := int32(3)
		cfg.EscalateAt = &esc

		var stderr bytes.Buffer
		if code := runSessionStart(client, cfg, &stderr); code != 0 {
			t.Fatalf("runSessionStart() = %d; stderr: %s", code, stderr.String())
		}
		got := fake.lastCreateRequest().GetRequestedScope()
		if got.EscalateAt == nil || got.GetEscalateAt() != 3 {
			t.Errorf("requested_scope.escalate_at = %v, want 3", got.EscalateAt)
		}
	})
}

// STRATIUM_PEP_PRINCIPAL_TOKEN_FILE is optional at load: when set, the file's
// contents (trimmed) are the principal's OIDC token and reach the PDP as
// principal_token. A path that cannot be read, or an empty file, fails the
// load: silently starting a session without the token the operator
// configured would surface later as an unexplained refusal.
func TestSessionStart_PrincipalTokenFile(t *testing.T) {
	setRequired := func(t *testing.T) {
		clearSessionStartEnv(t)
		t.Setenv("STRATIUM_PEP_PDP_ADDR", "localhost:50051")
		t.Setenv("STRATIUM_PEP_AGENT_ID", "agent-1")
		t.Setenv("STRATIUM_PEP_SUBJECT", "alice@example.com")
		t.Setenv("STRATIUM_PEP_SESSION_FILE", filepath.Join(t.TempDir(), "session.json"))
		t.Setenv("STRATIUM_PEP_CONNECT_TIMEOUT", "5s")
		t.Setenv("STRATIUM_PEP_REQUESTED_TIER", "1")
		t.Setenv("STRATIUM_PEP_REQUESTED_TOOLS", "Read")
		t.Setenv("STRATIUM_PEP_TTL_SECONDS", "3600")
	}

	t.Run("unset sends no token", func(t *testing.T) {
		setRequired(t)
		cfg, err := loadSessionStartConfigFromEnv()
		if err != nil || cfg.PrincipalToken != "" {
			t.Fatalf("cfg.PrincipalToken = %q, err = %v; want empty, nil", cfg.PrincipalToken, err)
		}
	})
	t.Run("file contents are trimmed and forwarded", func(t *testing.T) {
		setRequired(t)
		path := filepath.Join(t.TempDir(), "principal.jwt")
		if err := os.WriteFile(path, []byte("  header.payload.sig\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		t.Setenv("STRATIUM_PEP_PRINCIPAL_TOKEN_FILE", path)
		cfg, err := loadSessionStartConfigFromEnv()
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		if cfg.PrincipalToken != "header.payload.sig" {
			t.Fatalf("cfg.PrincipalToken = %q, want the trimmed file contents", cfg.PrincipalToken)
		}
		fake := &fakePDP{createResp: &pdpgrpc.CreateDelegationResponse{
			DelegationId: "deleg-principal",
			GrantedScope: &pdpgrpc.GrantedScope{MaxActionTier: 1, Tools: []string{"Read"}},
			Token:        "deleg-principal-token",
		}}
		var stderr bytes.Buffer
		if code := runSessionStart(startFakePDP(t, fake), cfg, &stderr); code != 0 {
			t.Fatalf("runSessionStart exit = %d, stderr: %s", code, stderr.String())
		}
		if got := fake.lastCreateRequest().GetPrincipalToken(); got != "header.payload.sig" {
			t.Errorf("principal_token sent = %q, want the file's token", got)
		}
		if strings.Contains(stderr.String(), "header.payload.sig") {
			t.Error("stderr contains the principal token")
		}
	})
	for name, write := range map[string]func(t *testing.T) string{
		"missing file": func(t *testing.T) string { return filepath.Join(t.TempDir(), "nope.jwt") },
		"empty file": func(t *testing.T) string {
			p := filepath.Join(t.TempDir(), "empty.jwt")
			if err := os.WriteFile(p, []byte("\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			return p
		},
	} {
		t.Run(name+" fails the load", func(t *testing.T) {
			setRequired(t)
			t.Setenv("STRATIUM_PEP_PRINCIPAL_TOKEN_FILE", write(t))
			if _, err := loadSessionStartConfigFromEnv(); err == nil || !strings.Contains(err.Error(), "STRATIUM_PEP_PRINCIPAL_TOKEN_FILE") {
				t.Fatalf("err = %v, want one naming STRATIUM_PEP_PRINCIPAL_TOKEN_FILE", err)
			}
		})
	}
}
