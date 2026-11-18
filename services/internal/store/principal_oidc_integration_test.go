//go:build integration

package store_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stratiumdata/stratium/internal/pdpgrpc"
	"github.com/stratiumdata/stratium/pkg/models"
)

// These proofs run against pdp-oidc, the one PDP in the compose stack that
// authenticates principals the way a production PDP does: against the
// stack's Keycloak, with the same realm, audience, and claim (email) that
// stratium-pap uses to identify approvers. Every other PDP in the stack sets
// STRATIUM_PRINCIPAL_AUTH_INSECURE, so nothing else here could show that the
// verified path works with a real identity provider and real tokens.
//
// The tokens are fetched from Keycloak by papAccessToken, the helper the PAP
// proofs already use, so the PDP and the PAP are shown to accept the same
// credential and derive the same person from it.

const (
	oidcViewerEmail = "pap-viewer@example.com" // deploy/docker/keycloak/stratium-realm.json
	oidcEditorEmail = "pap-editor@example.com"
)

// oidcPDP dials pdp-oidc and returns its client and tenant. Self-contained
// (its own env lookups and dial) rather than another entry in TestMain: it is
// the only consumer.
func oidcPDP(t *testing.T) (pdpgrpc.PDPServiceClient, string) {
	t.Helper()
	addr, tenant := os.Getenv("STRATIUM_IT_PDP_OIDC_ADDR"), os.Getenv("STRATIUM_IT_OIDC_TENANT_ID")
	if addr == "" || tenant == "" {
		t.Fatal("STRATIUM_IT_PDP_OIDC_ADDR and STRATIUM_IT_OIDC_TENANT_ID must be set: run via `make integration`")
	}
	client, closeConn, err := dialAndWaitForServing(t.Context(), addr)
	if err != nil {
		t.Fatalf("dial pdp-oidc at %s: %v", addr, err)
	}
	t.Cleanup(closeConn)
	return client, tenant
}

func oidcRootRequest(agentID uuid.UUID, subject, principalToken string) *pdpgrpc.CreateDelegationRequest {
	return &pdpgrpc.CreateDelegationRequest{
		Subject: subject,
		AgentId: agentID.String(),
		RequestedScope: &pdpgrpc.RequestedScope{
			MaxActionTier: int32(models.ActionTierReadOnly),
			Tools:         []string{"Read"},
		},
		Purpose:        "integration test: principal authentication",
		TtlSeconds:     600,
		PrincipalToken: principalToken,
	}
}

// The principal of a root delegation is the person Keycloak's token proves,
// not anything the request says. The request below names no subject at all;
// the delegation that comes back then decides ALLOW under the token's email
// (the only principal the tenant's policy permits) and DENY under any other
// name, which is only possible if the PDP recorded that email as the root
// principal.
func TestIntegration_PrincipalOIDC_RootPrincipalComesFromTheToken(t *testing.T) {
	client, tenant := oidcPDP(t)
	agentID := uuid.New()
	seedAgent(t, tenant, agentID, "integration-agent-oidc-proof1", models.TrustTierUnverified)
	seedPolicy(t, tenant, "oidc-proof1-permit",
		fmt.Sprintf(`permit(principal == User::"%s", action, resource);`, oidcViewerEmail), "allow")

	created, err := client.CreateDelegation(t.Context(),
		oidcRootRequest(agentID, "", papAccessToken(t, papViewerUser, papViewerPass)))
	if err != nil {
		t.Fatalf("CreateDelegation() with a real Keycloak token and no subject: %v", err)
	}

	decide := func(subject string) *pdpgrpc.DecideResponse {
		t.Helper()
		resp, err := client.Decide(t.Context(), &pdpgrpc.DecideRequest{
			Token: created.GetToken(), AgentId: agentID.String(), Subject: subject, Tool: "Read",
		})
		if err != nil {
			t.Fatalf("Decide(subject=%q): %v", subject, err)
		}
		return resp
	}
	if got := decide(oidcViewerEmail); got.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
		t.Fatalf("Decide under the token's email = %v (%s), want ALLOW: the delegation was not issued for %s",
			got.GetEffect(), got.GetReason(), oidcViewerEmail)
	}
	if got := decide(oidcEditorEmail); got.GetEffect() != pdpgrpc.Effect_EFFECT_DENY || got.GetDeniedLeg() != "delegation" {
		t.Fatalf("Decide under another name = %v at leg %q, want DENY at the delegation leg",
			got.GetEffect(), got.GetDeniedLeg())
	}
	t.Logf("root delegation %s issued for the token's principal %s", created.GetDelegationId(), oidcViewerEmail)
}

// A session cannot be started without proving who it is for, and a valid
// token cannot be used to start one under someone else's name.
func TestIntegration_PrincipalOIDC_RefusesUnprovenOrMismatchedPrincipals(t *testing.T) {
	client, tenant := oidcPDP(t)
	agentID := uuid.New()
	seedAgent(t, tenant, agentID, "integration-agent-oidc-proof2", models.TrustTierUnverified)
	// Permits both people, so the only thing refusing below is authentication.
	seedPolicy(t, tenant, "oidc-proof2-permit", `permit(principal, action, resource);`, "allow")

	viewerToken := papAccessToken(t, papViewerUser, papViewerPass)
	tests := []struct {
		name, subject, token string
		want                 codes.Code
	}{
		{"a bare subject, no token", oidcViewerEmail, "", codes.Unauthenticated},
		{"a token Keycloak did not issue", oidcViewerEmail, "not.a.token", codes.Unauthenticated},
		{"the viewer's own token, the editor's name", oidcEditorEmail, viewerToken, codes.PermissionDenied},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp, err := client.CreateDelegation(t.Context(), oidcRootRequest(agentID, tt.subject, tt.token))
			if resp != nil {
				t.Fatalf("CreateDelegation() minted delegation %s", resp.GetDelegationId())
			}
			if got := status.Code(err); got != tt.want {
				t.Fatalf("code = %v (%v), want %v", got, err, tt.want)
			}
		})
	}

	// Control: the same request with the matching name succeeds, so the
	// refusals above are the check and not a broken fixture.
	if _, err := client.CreateDelegation(t.Context(), oidcRootRequest(agentID, oidcViewerEmail, viewerToken)); err != nil {
		t.Fatalf("control: CreateDelegation() with a matching subject and token: %v", err)
	}
}
