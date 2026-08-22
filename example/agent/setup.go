package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"stratium/internal/pdpgrpc"
)

// kcRealm and kcClient are fixed across every example: Keycloak proves
// identity and role membership only, never a tenant -- tenant scoping lives
// entirely in which PAP instance a token is presented to (see each example's
// own package doc).
const (
	kcRealm  = "stratium"
	kcClient = "stratium-pap"
)

// MintToken gets a fresh operator token from Keycloak. Called anew for every
// PAP request that needs one, never cached: these tokens expire after five
// minutes, and an example's own setup calls plus a live model conversation
// can outlast that window.
func MintToken(kcAddr, user, pass string) (string, error) {
	resp, err := http.PostForm(fmt.Sprintf("http://%s/realms/%s/protocol/openid-connect/token", kcAddr, kcRealm),
		url.Values{
			"grant_type": {"password"},
			"client_id":  {kcClient},
			"username":   {user},
			"password":   {pass},
			"scope":      {"openid email"},
		})
	if err != nil {
		return "", fmt.Errorf("keycloak token for %s: %w", user, err)
	}
	defer func() { _ = resp.Body.Close() }()

	var out struct {
		AccessToken      string `json:"access_token"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("keycloak token for %s: decode: %w", user, err)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("keycloak token for %s: %s: %s", user, out.Error, out.ErrorDescription)
	}
	return out.AccessToken, nil
}

// AddrProbe returns a Precheck probe that fails if addr is unconfigured or
// unreachable -- the same "empty means not configured" check every example's
// own PDP/PAP/service prechecks share.
func AddrProbe(addr string) func() error {
	return func() error {
		if addr == "" {
			return fmt.Errorf("address not configured")
		}
		return DialCheck(addr)()
	}
}

// EnsurePolicy POSTs one cedar policy to a PAP's /v1/policies -- a 201 or a
// 409 (already exists) both count as success, the same idempotent-POST
// convention every example's own resource-label and tool-catalog writes use.
func EnsurePolicy(papAddr, token, name, policyContent string) error {
	body, _ := json.Marshal(map[string]string{"name": name, "language": "cedar", "policy_content": policyContent, "effect": "allow"})
	req, err := http.NewRequest(http.MethodPost, "http://"+papAddr+"/v1/policies", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("policies %q: %w", name, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusCreated || resp.StatusCode == http.StatusConflict {
		return nil
	}
	b, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("policies %q: %s: %s", name, resp.Status, b)
}

// ReadDelegationID reads the delegation id session-start cached to path --
// the same file and wire shape session_file.go's own loadSessionFile reads
// (plain encoding/json over *pdpgrpc.CreateDelegationResponse). Used by any
// surface that refuses an ordinary bearer token and must mint a second,
// DPoP-bound one from the delegation session-start already created.
func ReadDelegationID(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read session file %s: %w", path, err)
	}
	var resp pdpgrpc.CreateDelegationResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return "", fmt.Errorf("decode session file %s: %w", path, err)
	}
	if resp.GetDelegationId() == "" {
		return "", fmt.Errorf("session file %s names no delegation", path)
	}
	return resp.GetDelegationId(), nil
}

// MintBoundToken generates a fresh P-256 keypair and calls the PDP's
// IssueToken RPC directly -- there is no session-start flag for this -- to
// mint a token bound to that key's public half (RFC 9449 spec §4.7.2 K6).
func MintBoundToken(pdpAddr, delegationID string) (*ecdsa.PrivateKey, string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", fmt.Errorf("generate dpop key: %w", err)
	}
	jwkDoc, err := (&jose.JSONWebKey{Key: key.Public()}).MarshalJSON()
	if err != nil {
		return nil, "", fmt.Errorf("marshal dpop public jwk: %w", err)
	}
	jwk := string(jwkDoc)

	conn, err := grpc.NewClient(pdpAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, "", fmt.Errorf("dial pdp: %w", err)
	}
	defer func() { _ = conn.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	resp, err := pdpgrpc.NewPDPServiceClient(conn).IssueToken(ctx, &pdpgrpc.IssueTokenRequest{
		DelegationId: delegationID,
		TtlSeconds:   3600,
		DpopJwk:      &jwk,
	})
	if err != nil {
		return nil, "", fmt.Errorf("issue bound token: %w", err)
	}
	return key, resp.GetToken(), nil
}
