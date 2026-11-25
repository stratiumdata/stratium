package pdpgrpc

import (
	"context"
	"strings"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stratiumdata/stratium/internal/config"
)

// lim is what testConfig carries: the defaults.
var lim = config.DefaultRequestLimits()

func long(n int) string { return strings.Repeat("x", n+1) }

// Decide answers an over-long field from a caller whose token verified with
// an audited DENY, never a bare error: a caller holding a token must not be
// able to choose a refusal that leaves no row.
func TestDecide_OverLongField_IsAnAuditedDenyNamingTheField(t *testing.T) {
	cases := map[string]func(*DecideRequest){
		"tool":            func(r *DecideRequest) { r.Tool = long(lim.ToolBytes) },
		"subject":         func(r *DecideRequest) { r.Subject = long(lim.SubjectBytes) },
		"harness":         func(r *DecideRequest) { r.Harness = long(lim.NameBytes) },
		"cwd":             func(r *DecideRequest) { r.Cwd = long(lim.PathBytes) },
		"dpop_proof":      func(r *DecideRequest) { r.DpopProof = long(lim.CredentialBytes) },
		"observed_method": func(r *DecideRequest) { r.ObservedMethod = long(lim.NameBytes) },
		"observed_uri":    func(r *DecideRequest) { r.ObservedUri = long(lim.URIBytes) },
		"resource key":    func(r *DecideRequest) { r.Resource = map[string]string{long(lim.NameBytes): "v"} },
		"resource value":  func(r *DecideRequest) { r.Resource = map[string]string{"id": long(lim.PathBytes)} },
		"resource has": func(r *DecideRequest) {
			r.Resource = map[string]string{}
			for range lim.ResourceEntries + 1 {
				r.Resource[uuid.NewString()] = "v"
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			fs, req, delegationID := decideTokenFixture(t)
			mutate(req)
			srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

			resp, err := srv.Decide(context.Background(), req)
			if err != nil {
				t.Fatalf("Decide() error = %v, want a DENY decision", err)
			}
			if resp.GetEffect() != Effect_EFFECT_DENY || !strings.Contains(resp.GetReason(), name) {
				t.Fatalf("Effect = %v, Reason = %q; want a DENY naming %q", resp.GetEffect(), resp.GetReason(), name)
			}
			if fs.calls != 1 || len(fs.appended) != 1 {
				t.Fatalf("store calls = %d, audit rows = %d; want one call, the audit append", fs.calls, len(fs.appended))
			}
			row := fs.appended[0]
			if row.DelegationID == nil || *row.DelegationID != delegationID {
				t.Errorf("audit row DelegationID = %v, want %s: the token verified", row.DelegationID, delegationID)
			}
			limit := maxAuditedCallerTextBytes + len(clippedSuffix)
			if len(row.ToolName) > limit || len(row.Actor) > limit {
				t.Errorf("row ToolName is %d bytes and Actor %d, want at most %d", len(row.ToolName), len(row.Actor), limit)
			}
		})
	}
}

// At the limit is allowed: the fixture's call reaches the real decision.
func TestDecide_FieldsAtTheLimitAreDecided(t *testing.T) {
	fs, req, _ := decideTokenFixture(t)
	req.Harness = strings.Repeat("x", lim.NameBytes)
	req.Cwd = strings.Repeat("x", lim.PathBytes)
	srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if resp.GetDeniedLeg() != "principal" {
		t.Errorf("DeniedLeg = %q (reason %q), want principal: the call must reach the policy", resp.GetDeniedLeg(), resp.GetReason())
	}
}

func TestDecide_OverLongToken_DoesNotAuthenticate(t *testing.T) {
	fs, req := wellFormedFixture()
	req.Token = long(lim.CredentialBytes)
	signer := &fakeSigner{}
	srv := NewServer(fs, denyAllPolicy(), testConfig(), signer)

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v, want a DENY decision", err)
	}
	if resp.GetEffect() != Effect_EFFECT_DENY || !strings.Contains(resp.GetReason(), "token") {
		t.Errorf("Effect = %v, Reason = %q; want a DENY naming the token", resp.GetEffect(), resp.GetReason())
	}
	if len(fs.appended) != 1 || fs.appended[0].DelegationID != nil {
		t.Errorf("want one audit row naming no delegation, got %d rows", len(fs.appended))
	}
}

func TestCreateDelegation_OverLongField_IsRefused(t *testing.T) {
	cases := map[string]func(*CreateDelegationRequest){
		"purpose":         func(r *CreateDelegationRequest) { r.Purpose = long(lim.PurposeBytes) },
		"subject":         func(r *CreateDelegationRequest) { r.Subject = long(lim.SubjectBytes) },
		"principal_token": func(r *CreateDelegationRequest) { r.PrincipalToken = long(lim.CredentialBytes) },
		"parent_token":    func(r *CreateDelegationRequest) { r.ParentToken = long(lim.CredentialBytes) },
		"requested_scope.tools[1]": func(r *CreateDelegationRequest) {
			r.RequestedScope.Tools = []string{"Bash", long(lim.ToolBytes)}
		},
		"requested_scope.tools has": func(r *CreateDelegationRequest) {
			r.RequestedScope.Tools = make([]string, lim.RequestedTools+1)
			for i := range r.RequestedScope.Tools {
				r.RequestedScope.Tools[i] = "Bash"
			}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			fs, req, _ := wellFormedDelegationFixture()
			mutate(req)
			srv := newDelegationServer(fs, permissiveGrantSet())

			_, err := srv.CreateDelegation(context.Background(), req)
			if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), name) {
				t.Fatalf("error = %v, want InvalidArgument naming %q", err, name)
			}
			if fs.calls != 0 {
				t.Errorf("store calls = %d, want 0", fs.calls)
			}
		})
	}
}

func TestIssueToken_OverLongField_IsRefused(t *testing.T) {
	jwk := long(lim.CredentialBytes)
	cases := map[string]*IssueTokenRequest{
		"token":    {DelegationId: uuid.NewString(), TtlSeconds: 60, Token: long(lim.CredentialBytes)},
		"dpop_jwk": {DelegationId: uuid.NewString(), TtlSeconds: 60, Token: "t", DpopJwk: &jwk},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			fs := &fakeStore{}
			srv := NewServer(fs, denyAllPolicy(), testConfig(), &fakeSigner{})
			_, err := srv.IssueToken(context.Background(), req)
			if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), name) {
				t.Fatalf("error = %v, want InvalidArgument naming %q", err, name)
			}
			if fs.calls != 0 {
				t.Errorf("store calls = %d, want 0", fs.calls)
			}
		})
	}
}

func TestReportToolUse_OverLongTool_IsRefused(t *testing.T) {
	srv, fs, tok := reportFixture(t)
	_, err := srv.ReportToolUse(context.Background(), &ReportToolUseRequest{Token: tok, Tool: long(lim.ToolBytes)})
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "tool") {
		t.Fatalf("error = %v, want InvalidArgument naming tool", err)
	}
	if fs.calls != 0 {
		t.Errorf("store calls = %d, want 0: nothing may be written for it", fs.calls)
	}
}

// A Config built by hand, as the integration tests build theirs, has no
// limits: nothing is refused for its length.
func TestDecide_ZeroLimitsRefuseNothing(t *testing.T) {
	fs, req, _ := decideTokenFixture(t)
	req.Harness = long(lim.NameBytes)
	cfg := testConfig()
	cfg.Limits = config.RequestLimits{}
	srv := NewServer(fs, denyAllPolicy(), cfg, &fakeSigner{})

	resp, err := srv.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide() error = %v", err)
	}
	if resp.GetDeniedLeg() != "principal" {
		t.Errorf("DeniedLeg = %q (reason %q), want principal: the call must reach the policy", resp.GetDeniedLeg(), resp.GetReason())
	}
}
