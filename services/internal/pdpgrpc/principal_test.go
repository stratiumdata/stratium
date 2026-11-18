package pdpgrpc

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"

	"github.com/stratiumdata/stratium/internal/principal"
)

// fakePrincipals stands in for the OIDC verifier: a token is "valid" when it
// is a key of the map, and identifies the mapped person.
type fakePrincipals map[string]string

func (f fakePrincipals) Identify(_ context.Context, rawToken string) (string, error) {
	if id, ok := f[rawToken]; ok {
		return id, nil
	}
	return "", principal.ErrNotIdentified
}

func verifiedConfig() func(*Server) *Server {
	return func(s *Server) *Server {
		s.cfg.PrincipalAuthInsecure = false
		return s.WithPrincipalVerifier(fakePrincipals{"alice-token": "alice@example.com", "ceo-token": "ceo@example.com"})
	}
}

// With verification on, the principal of a root delegation is whoever the
// token proves, never whoever the request names. This is the property the
// whole feature exists for: a PEP cannot start a session for a principal of
// its choosing.
func TestCreateDelegation_RootPrincipalComesFromTheVerifiedToken(t *testing.T) {
	tests := []struct {
		name, subject, token string
		want                 codes.Code // codes.OK means created for wantUser
		wantUser             string
	}{
		{"token and matching subject", "alice@example.com", "alice-token", codes.OK, "alice@example.com"},
		{"token alone: subject may be omitted", "", "alice-token", codes.OK, "alice@example.com"},
		{"no token: a bare subject is not enough", "alice@example.com", "", codes.Unauthenticated, ""},
		{"a token that does not verify", "alice@example.com", "forged", codes.Unauthenticated, ""},
		{"own token, someone else's name", "ceo@example.com", "alice-token", codes.PermissionDenied, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fs, req, _ := wellFormedDelegationFixture()
			req.Subject, req.PrincipalToken = tt.subject, tt.token
			srv := verifiedConfig()(newDelegationServer(fs, permissiveGrantSet()))

			resp, err := srv.CreateDelegation(context.Background(), req)
			if tt.want != codes.OK {
				if resp != nil {
					t.Fatalf("CreateDelegation() minted a delegation: %+v", resp)
				}
				wantCode(t, err, tt.want)
				if len(fs.created) != 0 || len(fs.appended) != 0 {
					t.Errorf("rows created = %d, audit entries = %d, want 0 and 0", len(fs.created), len(fs.appended))
				}
				return
			}
			if err != nil {
				t.Fatalf("CreateDelegation() error = %v", err)
			}
			if got := fs.created[0].UserID; got != tt.wantUser {
				t.Errorf("stored principal = %q, want the token's %q", got, tt.wantUser)
			}
			if got := fs.appended[0].Actor; got != tt.wantUser {
				t.Errorf("audit actor = %q, want the token's %q", got, tt.wantUser)
			}
		})
	}
}

// A PDP that is neither given a verifier nor told to run without one must
// not quietly believe the request. config.Load prevents this combination;
// this is the server refusing it anyway, so a wiring mistake fails closed.
func TestCreateDelegation_NoVerifierAndNoOptOutRefuses(t *testing.T) {
	fs, req, _ := wellFormedDelegationFixture()
	srv := newDelegationServer(fs, permissiveGrantSet())
	srv.cfg.PrincipalAuthInsecure = false

	resp, err := srv.CreateDelegation(context.Background(), req)
	if resp != nil {
		t.Fatalf("CreateDelegation() minted a delegation with no way to know who for: %+v", resp)
	}
	wantCode(t, err, codes.FailedPrecondition)
}

// A child acts for its chain's root principal and is authorized by the
// parent's token. A principal token has no role there, and silently
// accepting one would suggest it could change who the child is for.
func TestCreateDelegation_ChildWithAPrincipalTokenIsRefused(t *testing.T) {
	fs, req, _ := wellFormedDelegationFixture()
	parentID := uuid.New()
	req.ParentDelegationId = parentID.String()
	req.ParentToken = parentID.String() // fakeSigner: a fixture token is the bare id
	req.PrincipalToken = "alice-token"
	srv := verifiedConfig()(newDelegationServer(fs, permissiveGrantSet()))

	resp, err := srv.CreateDelegation(context.Background(), req)
	if resp != nil {
		t.Fatalf("CreateDelegation() response = %+v, want nil", resp)
	}
	wantCode(t, err, codes.InvalidArgument)
}

// The opt-out keeps the old behaviour and ignores a token it cannot check.
func TestCreateDelegation_InsecureModeBelievesTheSubject(t *testing.T) {
	fs, req, _ := wellFormedDelegationFixture()
	req.PrincipalToken = "anything"
	if _, err := newDelegationServer(fs, permissiveGrantSet()).CreateDelegation(context.Background(), req); err != nil {
		t.Fatalf("CreateDelegation() error = %v", err)
	}
	if got := fs.created[0].UserID; got != req.GetSubject() {
		t.Errorf("stored principal = %q, want the request's subject %q", got, req.GetSubject())
	}
}
