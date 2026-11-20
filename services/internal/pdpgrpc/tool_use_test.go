package pdpgrpc

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stratiumdata/stratium/internal/store"
)

// reportFixture is a server over wellFormedFixture's chain, a real token for
// its delegation, and one ALLOW on record: Bash with input `{"command":"ls"}`.
func reportFixture(t *testing.T) (*Server, *fakeStore, string) {
	t.Helper()
	fs, _, delegationID := decideTokenFixture(t)
	fs.allowed = map[allowKey]bool{
		{"Bash", sha256.Sum256([]byte(`{"command":"ls"}`))}: true,
	}
	signer := testSigner(t)
	now := time.Now()
	tok := signRealToken(t, signer, delegationID, now, now.Add(time.Hour))
	return NewServer(fs, denyAllPolicy(), testConfig(), signer), fs, tok
}

func TestReportToolUse_MatchedWritesNothing(t *testing.T) {
	srv, fs, tok := reportFixture(t)
	resp, err := srv.ReportToolUse(context.Background(),
		&ReportToolUseRequest{Token: tok, Tool: "Bash", RawInput: `{"command":"ls"}`})
	if err != nil || !resp.GetMatched() {
		t.Fatalf("ReportToolUse() = %v, %v; want matched", resp, err)
	}
	if len(fs.appended) != 0 {
		t.Fatalf("a matched report wrote %d audit entries, want 0", len(fs.appended))
	}
}

func TestReportToolUse_UnmatchedWritesOneAuditEntry(t *testing.T) {
	cases := map[string]*ReportToolUseRequest{
		"different input":             {Tool: "Bash", RawInput: `{"command":"rm -rf /"}`},
		"different tool":              {Tool: "Write", RawInput: `{"command":"ls"}`},
		"same input, different bytes": {Tool: "Bash", RawInput: `{"command": "ls"}`},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			srv, fs, tok := reportFixture(t)
			req.Token = tok
			resp, err := srv.ReportToolUse(context.Background(), req)
			if err != nil || resp.GetMatched() {
				t.Fatalf("ReportToolUse() = %v, %v; want unmatched", resp, err)
			}
			if len(fs.appended) != 1 {
				t.Fatalf("appended %d audit entries, want 1", len(fs.appended))
			}
			e := fs.appended[0]
			if e.EventType != store.EventTypeUnmatchedToolUse || e.Decision != "DENY" ||
				e.ToolName != req.Tool || e.InputDigest != sha256.Sum256([]byte(req.RawInput)) {
				t.Errorf("entry = %+v", e)
			}
			if e.DelegationID == nil || e.RootDelegationID == nil || e.AgentID == nil || e.Actor == "" {
				t.Errorf("entry does not identify the delegation, agent and principal: %+v", e)
			}
		})
	}
}

// A report grants nothing, so a bad token is refused outright and leaves no
// audit entry (Decide audits one because it is a refused attempt to act).
func TestReportToolUse_BadTokenIsRefusedAndNotAudited(t *testing.T) {
	srv, fs, _ := reportFixture(t)
	for _, tok := range []string{"", "not-a-token"} {
		_, err := srv.ReportToolUse(context.Background(),
			&ReportToolUseRequest{Token: tok, Tool: "Bash", RawInput: `{}`})
		if status.Code(err) != codes.Unauthenticated {
			t.Errorf("token %q: code = %v, want Unauthenticated", tok, status.Code(err))
		}
	}
	if len(fs.appended) != 0 {
		t.Fatalf("appended %d audit entries, want 0", len(fs.appended))
	}
}

func TestReportToolUse_Errors(t *testing.T) {
	t.Run("tool is required", func(t *testing.T) {
		srv, _, tok := reportFixture(t)
		_, err := srv.ReportToolUse(context.Background(), &ReportToolUseRequest{Token: tok})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
		}
	})
	t.Run("unknown delegation", func(t *testing.T) {
		srv, fs, tok := reportFixture(t)
		fs.chainErr = store.ErrNotFound
		_, err := srv.ReportToolUse(context.Background(), &ReportToolUseRequest{Token: tok, Tool: "Bash"})
		if status.Code(err) != codes.NotFound {
			t.Fatalf("code = %v, want NotFound", status.Code(err))
		}
	})
	t.Run("lookup failure is not reported as unmatched", func(t *testing.T) {
		srv, fs, tok := reportFixture(t)
		fs.allowLookupErr = errors.New("db down")
		_, err := srv.ReportToolUse(context.Background(), &ReportToolUseRequest{Token: tok, Tool: "Bash"})
		if status.Code(err) != codes.Internal || len(fs.appended) != 0 {
			t.Fatalf("code = %v, appended = %d; want Internal and no entry", status.Code(err), len(fs.appended))
		}
	})
	t.Run("audit failure fails the call", func(t *testing.T) {
		srv, fs, tok := reportFixture(t)
		fs.appendErr = errors.New("disk full")
		_, err := srv.ReportToolUse(context.Background(), &ReportToolUseRequest{Token: tok, Tool: "Write"})
		if status.Code(err) != codes.Internal {
			t.Fatalf("code = %v, want Internal", status.Code(err))
		}
	})
}
