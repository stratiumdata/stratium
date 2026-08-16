//go:build integration

// Task 4's own proof (docs/superpowers/sdd/2026-08-13-phase-10-extauthz/
// task-4-brief.md): everything Tasks 1-3 built in cmd/stratium-pep/
// extauthz.go was proven against hand-constructed envoy.service.auth.v3.
// CheckRequest values, which proves the MAPPING (a CheckRequest becomes the
// right DecideRequest, a DecideResponse becomes the right CheckResponse) but
// not the INTEGRATION -- a real Envoy in front of a real stratium-pep
// extauthz, in front of a real stratium-pdp. Every other enforcement surface
// in this binary was proven against the real thing it was built for (hook
// and mcp against a real claude session); this file is that proof for
// extauthz, against deploy/docker/docker-compose.yml's own envoy,
// pep-extauthz, pdp-extauthz, and echo-upstream services.
//
// Six independent top-level tests, one per proof the brief asks for, rather
// than one test with six t.Run subtests: TestIntegration_Escalation_* in
// escalation_integration_test.go (this package's closest precedent for
// proving a live decision end to end) already establishes that convention,
// and conformance_test.go's own provenElsewhere pointers can only name a
// top-level function (conformance_pointer_test.go's own doc comment: a
// t.Run subtest name is a string argument evaluated at run time, not a
// declaration go/ast can see), which matters directly here -- see this
// file's own note on TestIntegration_Envoy_EscalateDeniesWithFindablePending
// Approval_ApprovedRetrySucceeds.
//
// HEADER RECONSTRUCTION. Proofs 5 and 6 both need to know, precisely, the
// JSON string decideRequestFromCheck (extauthz.go) hashed into the audit
// chain for a real request -- proof 6 to check "authorization" is not in
// it, proof 5 to resend the identical value on a direct retry (see that
// test's own comment for why it cannot go through Envoy a second time).
// Guessing Envoy's exact behavior from memory was rejected in favor of
// checking it directly, and it took two attempts to get right -- both real
// findings about real Envoy behavior a constructed CheckRequest fixture
// would never have surfaced:
//
//   - Envoy's ext_authz CheckRequest headers map is NOT limited to the
//     request's own named headers -- it ALSO carries four pseudo-headers as
//     ordinary map entries, ":authority", ":method", ":path", and ":scheme",
//     duplicating what AttributeContext_HttpRequest's own dedicated Host/
//     Method/Path/Scheme fields already carry. The proto field doc's
//     phrasing ("this field will not be set if... encode_raw_headers") reads
//     as though pseudo-headers live only in those dedicated fields; they do
//     not. reconstructHeaders (below) adds all four explicitly.
//   - Envoy adds x-forwarded-proto to the request before ext_authz ever sees
//     it -- confirmed by instrumenting stratium-pep extauthz itself
//     (temporarily, during development) to print the exact raw_input it
//     built, not by reading Envoy's own trace log: an early attempt to
//     locate the injection point via `POST /logging?filter=trace` looked at
//     the wrong point in the pipeline (the raw wire parse, before the HTTP
//     connection manager's own pre-filter-chain header mutation) and
//     concluded the opposite.
//
// Nothing else this deployment's config adds: no x-request-id
// (generate_request_id: false, envoy.yaml), no x-envoy-expected-rq-timeout-ms
// (the one route's timeout: 0s), no x-forwarded-for (not observed for this
// single-hop, non-TLS, non-proxied listener), no Accept (Go's http.Client
// sends none by default, unlike curl -- confirmed by comparing a curl probe
// against this file's own envoyDo output during development). The one real
// source of an invisible addition from Go's OWN side is http.Transport,
// which sets "Accept-Encoding: gzip" on any request that does not already
// carry that header; envoyDo (below) sets it explicitly instead, so
// sentHeader (read back off the *http.Request before Do() runs) is always
// the complete, exact set of what this file's own client sent. Every proof
// below that depends on this (5 and 6) still verifies the result against a
// real audit row's own digest rather than trusting this comment on its own.
//
// FIXED IDENTITY. extauthzAgentID and extauthzSubject are literal constants,
// not generated per test, because they must equal the compose file's own
// pep-extauthz STRATIUM_PEP_AGENT_ID/STRATIUM_PEP_SUBJECT exactly --
// extauthz.go reads both from its own startup configuration, never from the
// request Envoy is fronting (extauthz.go's own package doc, NO SESSION
// FILE), so no live HTTP request can ever name a different identity. Every
// proof below seeds its own delegation(s) for this one fixed identity.
package store_test

import (
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"stratium/internal/pdpgrpc"
	"stratium/internal/store"
	"stratium/pkg/models"
)

// extauthzAgentID and extauthzSubject: see this file's own package doc,
// FIXED IDENTITY. The agent id has no meaning beyond matching
// docker-compose.yml's pep-extauthz service; no key or secret sits behind
// it.
var extauthzAgentID = uuid.MustParse("72d38ebe-2e5c-4918-9e73-b0de3607fbfa")

const extauthzSubject = "extauthz-integration@example.com"

// extauthzTestUserAgent and extauthzTestAcceptEncoding are set explicitly on
// every request this file sends through Envoy, rather than left for Go's
// own http.Transport to fill in silently: Transport adds "Accept-Encoding:
// gzip" to any request that does not already carry that header, and would
// otherwise do so invisibly to sentHeader (envoyDo reads req.Header back
// before Do() ever runs) -- see this file's own package doc, HEADER
// RECONSTRUCTION.
const (
	extauthzTestUserAgent      = "stratium-extauthz-integration-test"
	extauthzTestAcceptEncoding = "identity"
)

// approvalIDHeaderName mirrors cmd/stratium-pep/extauthz.go's own
// unexported approvalIDHeader constant exactly. Duplicated, not imported:
// package main cannot be imported, and re-deriving the value from a live
// response would defeat the point of an independently stated comparison.
const approvalIDHeaderName = "stratium-approval-id"

// extauthzCredentialHeaderNames mirrors extauthz.go's own credentialHeaderNames
// exactly -- see that file's own doc comment for why the list stops at
// exactly these three (RFC-fixed bearer-authority headers only, not a
// deployment-specific guess, which would be the PEP classifying something).
var extauthzCredentialHeaderNames = map[string]bool{
	"authorization":       true,
	"cookie":              true,
	"proxy-authorization": true,
}

// seedExtauthzAgentOnce idempotently inserts the one agent identity every
// proof in this file shares (extauthzAgentID). ON CONFLICT DO NOTHING
// rather than a sync.Once guard: this file's six tests are independent
// top-level functions precisely so `go test -run` can select any subset of
// them (see the package doc), and a Once keyed to whichever test happens to
// run first would make a lone `-run` invocation of a later one fail to seed
// the agent at all.
func seedExtauthzAgentOnce(t *testing.T) {
	t.Helper()
	withTenantTx(t, envoyTenant, func(tx *sql.Tx) {
		if _, err := tx.ExecContext(t.Context(),
			`INSERT INTO agents (id, tenant_id, name, provider, model_id, trust_tier, enabled, suspended, allowed_tools)
			 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) ON CONFLICT (id) DO NOTHING`,
			extauthzAgentID.String(), envoyTenant, "extauthz-integration-agent", "anthropic", "claude",
			int64(models.TrustTierPlatformTrusted), true, false, []byte(`[]`),
		); err != nil {
			t.Fatalf("seed extauthz agent: %v", err)
		}
	})
}

// envoyDo sends method/path through the real Envoy listener (envoyAddr):
// Authorization set to "Bearer "+token when token is non-empty (proof 3
// needs a genuinely ABSENT header, not an empty Bearer value -- those deny
// for different reasons in extractBearerToken -- so this never sends an
// empty Authorization header), plus every entry of extra set verbatim.
//
// Returns the response status and body (read fully and the response closed
// here, so no caller has to remember to), the response's own headers, and
// sentHeader -- exactly which request headers this call sent, read back off
// the same *http.Request Do() actually issued, before Do() runs (ahead of
// any header Go's own Transport might otherwise add invisibly). That last
// one is what proofs 5 and 6 use to reconstruct the exact raw_input
// stratium-pdp hashed -- see this file's own package doc, HEADER
// RECONSTRUCTION.
func envoyDo(t *testing.T, method, path, token string, extra map[string]string) (status int, body string, respHeader http.Header, sentHeader map[string]string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, "http://"+envoyAddr+path, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("User-Agent", extauthzTestUserAgent)
	req.Header.Set("Accept-Encoding", extauthzTestAcceptEncoding)
	for name, value := range extra {
		req.Header.Set(name, value)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	sentHeader = make(map[string]string, len(req.Header))
	for name := range req.Header {
		sentHeader[name] = req.Header.Get(name)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("envoy request %s %s: %v", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}
	return resp.StatusCode, string(b), resp.Header, sentHeader
}

// echoUpstreamResponse mirrors deploy/docker/echo-upstream/main.go's own
// echoResponse exactly -- the JSON shape Envoy's ALLOW path (routed to the
// echo-upstream compose service) answers with.
type echoUpstreamResponse struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
}

// envoyRequestMetadata mirrors cmd/stratium-pep/extauthz.go's own
// requestMetadata exactly -- same three fields, same json tags, same
// declaration order -- so rawInputJSON (below) produces byte-identical
// output to decideRequestFromCheck's own json.Marshal call for the same
// (method, path, headers) triple. Duplicated, not imported: requestMetadata
// belongs to package main (cmd/stratium-pep), which this external test
// package cannot reach.
type envoyRequestMetadata struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
}

// rawInputJSON reproduces decideRequestFromCheck's own encoding exactly:
// encoding/json marshals a Go struct's fields in declaration order and a
// map[string]string's keys sorted lexicographically (guaranteed,
// deterministic behavior, not an implementation detail this file is
// gambling on) -- so given the SAME (method, path, headers) triple
// decideRequestFromCheck itself built RawInput from, this produces the SAME
// bytes, and SHA-256 of the result matches the SAME audit_chain.input_digest
// stratium-pdp actually stored.
func rawInputJSON(method, path string, headers map[string]string) string {
	raw, err := json.Marshal(envoyRequestMetadata{Method: method, Path: path, Headers: headers})
	if err != nil {
		// method/path are plain strings and headers is a flat
		// map[string]string with no cycles -- Marshal cannot fail for this
		// shape, matching decideRequestFromCheck's own comment on the
		// identical encode.
		panic(err)
	}
	return string(raw)
}

// lowercaseHeaders returns a copy of headers with every key lower-cased --
// matching the casing Envoy's own ext_authz CheckRequest uses (extauthz.go's
// own doc comment on extractBearerToken).
func lowercaseHeaders(headers map[string]string) map[string]string {
	out := make(map[string]string, len(headers))
	for name, value := range headers {
		out[strings.ToLower(name)] = value
	}
	return out
}

// stripCredentialHeaders returns lowercaseHeaders(headers) with every
// extauthzCredentialHeaderNames entry removed -- the reconstruction-side
// mirror of extractBearerToken's own strip-by-omission (extauthz.go),
// applied to what this test sent instead of to a live CheckRequest.
func stripCredentialHeaders(headers map[string]string) map[string]string {
	out := make(map[string]string, len(headers))
	for name, value := range headers {
		lower := strings.ToLower(name)
		if extauthzCredentialHeaderNames[lower] {
			continue
		}
		out[lower] = value
	}
	return out
}

// envoyForwardedProto is the value Envoy's ext_authz CheckRequest carries
// for both ":scheme" and "x-forwarded-proto" on every request this file
// sends: envoy.yaml's one listener is plain HTTP, never TLS, so this is a
// fixed fact about this deployment, not something each proof rediscovers.
const envoyForwardedProto = "http"

// reconstructHeaders builds the exact headers map decideRequestFromCheck
// (extauthz.go) hashes into raw_input for a request this file sends with
// sentHeader (envoyDo's own return value) to path via method, through the
// real Envoy listener at envoyAddr -- see this file's own package doc,
// HEADER RECONSTRUCTION, for how each addition below was confirmed rather
// than assumed. includeCredentials is false for the reconstruction every
// proof actually trusts; proof 6 alone also calls this with true, for a
// negative control that must (and does) produce a different result.
func reconstructHeaders(method, path string, sentHeader map[string]string, includeCredentials bool) map[string]string {
	headers := stripCredentialHeaders(sentHeader)
	if includeCredentials {
		headers = lowercaseHeaders(sentHeader)
	}
	headers[":authority"] = envoyAddr
	headers[":method"] = method
	headers[":path"] = path
	headers[":scheme"] = envoyForwardedProto
	headers["x-forwarded-proto"] = envoyForwardedProto
	return headers
}

// seedExtauthzPermitPolicy seeds a fresh, uniquely-named blanket-permit
// cedar policy for envoyTenant, so the principal leg always allows and
// every proof's own DENY/ESCALATE below is unambiguously attributable to
// the delegation leg, never to policy — the same reasoning
// escalationBlanketPermit's own doc comment gives. A fresh name every call,
// rather than one shared, fixed name: seedPolicy's underlying INSERT has no
// ON CONFLICT clause (policies.name is unique per tenant), and this file's
// six tests are independent top-level functions that must each be safe to
// run alone, in any order, an arbitrary number of times against a
// long-lived database — not just once, immediately after a fresh
// `make integration` volume.
func seedExtauthzPermitPolicy(t *testing.T) {
	t.Helper()
	seedPolicy(t, envoyTenant, "extauthz-permit-"+uuid.New().String(), escalationBlanketPermit, "allow")
}

// newExtauthzDelegation seeds one root delegation for extauthzAgentID/
// extauthzSubject (the one fixed identity every proof in this file shares --
// see the package doc) with a fresh id, purpose, and expiry, so every
// proof's own delegation is otherwise isolated from every other proof's.
func newExtauthzDelegation(t *testing.T, purpose string, maxTier models.ActionTier, escalateAt *models.ActionTier) *models.Delegation {
	t.Helper()
	id := uuid.New()
	return seedDelegation(t, &models.Delegation{
		ID: id, TenantID: envoyTenant, UserID: extauthzSubject, AgentID: extauthzAgentID,
		ApprovedTools: []string{}, MaxActionTier: maxTier, EscalateAt: escalateAt,
		ClassificationCaps: map[string]string{}, ResourceConstraints: map[string]string{},
		Purpose: purpose, ExpiresAt: time.Now().Add(time.Hour),
		RootDelegationID: id, Depth: 0, ChainAgentIDs: []uuid.UUID{extauthzAgentID},
	})
}

// TestIntegration_Envoy_PermittedActionReachesUpstream is proof 1: a valid
// token for a permitted action reaches echo-upstream, and the audit chain
// records the ALLOW.
func TestIntegration_Envoy_PermittedActionReachesUpstream(t *testing.T) {
	seedExtauthzAgentOnce(t)
	seedExtauthzPermitPolicy(t)

	const path = "/proof1-read-item"
	seedToolCatalogEntry(t, envoyTenant, path, tierPtr(models.ActionTierReadOnly), "read", nil, nil)
	delegation := newExtauthzDelegation(t, "extauthz proof 1: a permitted action reaches the upstream",
		models.ActionTierReadOnly, nil)
	token := mintToken(t, envoyPdpClient, delegation.ID)

	status, body, _, _ := envoyDo(t, http.MethodGet, path, token, nil)
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (a permitted action must reach the upstream); body: %s", status, body)
	}
	var echoed echoUpstreamResponse
	if err := json.Unmarshal([]byte(body), &echoed); err != nil {
		t.Fatalf("decode echo-upstream response: %v; body: %s", err, body)
	}
	if echoed.Path != path {
		t.Fatalf("upstream echoed path = %q, want %q -- this must be the request that actually reached "+
			"Envoy, not some other response", echoed.Path, path)
	}
	if echoed.Method != http.MethodGet {
		t.Errorf("upstream echoed method = %q, want %q", echoed.Method, http.MethodGet)
	}

	rows := fetchAuditChain(t, envoyTenant)
	if len(rows) == 0 {
		t.Fatal("no audit rows for envoyTenant")
	}
	if last := rows[len(rows)-1]; last.Decision != "ALLOW" {
		t.Errorf("most recent audit row Decision = %q, want %q", last.Decision, "ALLOW")
	}
}

// TestIntegration_Envoy_DeniedActionBlockedWithPDPReason is proof 2: a
// valid token for a denied action does not reach the upstream, and Envoy
// returns the PDP's own reason.
func TestIntegration_Envoy_DeniedActionBlockedWithPDPReason(t *testing.T) {
	seedExtauthzAgentOnce(t)
	seedExtauthzPermitPolicy(t)

	const path = "/proof2-delete-item"
	seedToolCatalogEntry(t, envoyTenant, path, tierPtr(models.ActionTierDestructive), "delete", nil, nil)
	// A READ_ONLY ceiling under a DESTRUCTIVE-cataloged tool, no
	// EscalateAt: denies outright, never escalates -- proof 2 is
	// deliberately distinct from proof 5's own escalation case.
	delegation := newExtauthzDelegation(t, "extauthz proof 2: a denied action must not reach the upstream",
		models.ActionTierReadOnly, nil)
	token := mintToken(t, envoyPdpClient, delegation.ID)

	status, body, header, _ := envoyDo(t, http.MethodGet, path, token, nil)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 (a denied action must not reach the upstream); body: %s", status, body)
	}
	const wantReason = "exceeds delegation max_action_tier"
	if !strings.Contains(body, wantReason) {
		t.Errorf("body = %q, want it to carry the PDP's own tier-ceiling reason (%q)", body, wantReason)
	}
	if approval := header.Get(approvalIDHeaderName); approval != "" {
		t.Errorf("%s = %q, want empty -- an ordinary DENY must not carry a pending-approval id", approvalIDHeaderName, approval)
	}
}

// TestIntegration_Envoy_NoTokenDeniedNoFallback is proof 3 (K4): a request
// with no token at all is denied, before any delegation or tenant fixture
// exists to deny it -- there is no fallback credential this surface could
// have reached for instead.
func TestIntegration_Envoy_NoTokenDeniedNoFallback(t *testing.T) {
	status, body, _, _ := envoyDo(t, http.MethodGet, "/proof3-no-token", "", nil)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body: %s", status, body)
	}
	const wantReason = "no authorization header"
	if !strings.Contains(body, wantReason) {
		t.Errorf("body = %q, want extractBearerToken's own K4 wording (%q) -- anything else risks masking "+
			"a fallback path this surface must not have", body, wantReason)
	}
}

// TestIntegration_Envoy_RevokedDelegationDeniedAtDelegationLeg is proof 4
// (K3): a token naming a delegation that is revoked AFTER the token was
// minted is denied at the delegation leg, not the token check -- the
// property that makes a token an authenticated reference rather than a
// capability. Mirrors TestIntegration_Live_TokenAuthentication's own
// "token_naming_revoked_delegation_denies_at_delegation_leg" subtest
// (store_integration_test.go), the same proof over a direct gRPC call
// rather than through a real Envoy.
func TestIntegration_Envoy_RevokedDelegationDeniedAtDelegationLeg(t *testing.T) {
	seedExtauthzAgentOnce(t)
	seedExtauthzPermitPolicy(t)

	const path = "/proof4-revoked-item"
	seedToolCatalogEntry(t, envoyTenant, path, tierPtr(models.ActionTierReadOnly), "read", nil, nil)
	delegation := newExtauthzDelegation(t, "extauthz proof 4 (K3): a revoked delegation denies at the delegation leg",
		models.ActionTierDestructive, nil)
	token := mintToken(t, envoyPdpClient, delegation.ID) // minted while still active

	withTenantTx(t, envoyTenant, func(tx *sql.Tx) {
		res, err := tx.ExecContext(t.Context(), `UPDATE delegations SET revoked = true WHERE id = $1`, delegation.ID.String())
		if err != nil {
			t.Fatalf("revoke delegation: %v", err)
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			t.Fatalf("revoke delegation: RowsAffected = %d, err = %v, want 1, nil", n, err)
		}
	})

	status, body, _, _ := envoyDo(t, http.MethodGet, path, token, nil)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body: %s", status, body)
	}
	if !strings.Contains(body, "is revoked") {
		t.Errorf("body = %q, want DelegationLeg's own revocation wording (\"... is revoked\") -- anything "+
			"else means this was denied somewhere other than the real delegation-leg re-evaluation, which "+
			"is exactly what K3 requires", body)
	}
	if strings.Contains(body, "token") {
		t.Errorf("body = %q, mentions \"token\" -- a revoked-delegation denial must come from "+
			"DelegationLeg, which knows nothing about tokens, not from token authentication", body)
	}
}

// TestIntegration_Envoy_AuthorizationHeaderExcludedFromAuditDigest is proof
// 6: the authorization header does not reach the audit row's input-digest
// source, checked against a real request through real Envoy rather than a
// constructed CheckRequest (Task 2's own unit-level proof; see this file's
// package doc for what real Envoy traffic can do differently). A custom
// header (x-proof6-marker) is the positive control: it must survive into
// the reconstruction, or a digest match below would be vacuous -- proof the
// reconstruction preserves content in general, not merely proof that
// everything gets dropped.
func TestIntegration_Envoy_AuthorizationHeaderExcludedFromAuditDigest(t *testing.T) {
	seedExtauthzAgentOnce(t)
	seedExtauthzPermitPolicy(t)

	const path = "/proof6-digest-item"
	const marker = "proof6-marker-value"
	seedToolCatalogEntry(t, envoyTenant, path, tierPtr(models.ActionTierReadOnly), "read", nil, nil)
	delegation := newExtauthzDelegation(t, "extauthz proof 6: authorization must not reach the audit digest source",
		models.ActionTierReadOnly, nil)
	token := mintToken(t, envoyPdpClient, delegation.ID)

	status, body, _, sentHeader := envoyDo(t, http.MethodGet, path, token, map[string]string{"X-Proof6-Marker": marker})
	if status != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", status, body)
	}
	var echoed echoUpstreamResponse
	if err := json.Unmarshal([]byte(body), &echoed); err != nil {
		t.Fatalf("decode echo-upstream response: %v; body: %s", err, body)
	}
	// A secondary, end-to-end sanity check distinct from the digest match
	// below: the marker really did reach the upstream, unaltered, so a
	// reconstruction preserving it is checking something real.
	if got := echoed.Headers["x-proof6-marker"]; got != marker {
		t.Fatalf("echo-upstream received x-proof6-marker = %q, want %q", got, marker)
	}

	headers := reconstructHeaders(http.MethodGet, path, sentHeader, false)
	if _, ok := headers["authorization"]; ok {
		t.Fatalf("reconstruction still carries an authorization key -- reconstructHeaders itself is "+
			"broken, this proof cannot proceed: %+v", headers)
	}
	if v, ok := headers["x-proof6-marker"]; !ok || v != marker {
		t.Fatalf("reconstruction dropped the non-credential positive-control header -- a digest match "+
			"below would be vacuous (a digest computed over nothing meaningful); got %+v", headers)
	}
	reconstructed := rawInputJSON(http.MethodGet, path, headers)
	if strings.Contains(reconstructed, "authorization") || strings.Contains(reconstructed, token) {
		t.Fatalf("reconstructed raw_input carries \"authorization\" or the bearer token itself: %s", reconstructed)
	}

	rows := fetchAuditChain(t, envoyTenant)
	if len(rows) == 0 {
		t.Fatal("no audit rows for envoyTenant")
	}
	got := rows[len(rows)-1].InputDigest
	want := sha256.Sum256([]byte(reconstructed))
	if got != want {
		t.Fatalf("audit row's input_digest does not match the without-authorization reconstruction -- "+
			"either Envoy sent a header this test did not account for, or the credential-stripping "+
			"property does not hold for real Envoy traffic. reconstructed=%s got=%x want=%x",
			reconstructed, got, want)
	}

	// Belt and suspenders: confirm the digest is SPECIFICALLY the
	// without-authorization version, not merely a value that happens not to
	// differ -- the with-authorization reconstruction must hash to
	// something else.
	withAuth := rawInputJSON(http.MethodGet, path, reconstructHeaders(http.MethodGet, path, sentHeader, true))
	if withAuthDigest := sha256.Sum256([]byte(withAuth)); withAuthDigest == want {
		t.Fatal("the with- and without-authorization reconstructions hash identically -- this positive " +
			"control is broken (they differ in content, so their digests must differ too), which would " +
			"make the match above meaningless")
	}
}

// TestIntegration_Envoy_EscalateDeniesWithFindablePendingApproval_ApprovedRetrySucceeds
// is proof 5, and separately the pointer C23's provenElsewhere reassessment
// names (internal/authz/conformance_test.go) -- kept as one self-contained
// top-level function, not a t.Run subtest of some larger test, specifically
// so that pointer can name it directly (conformance_pointer_test.go can
// only verify a top-level Go test declaration; see this file's own package
// doc).
//
// The retry is a DIRECT Decide call to pdp-extauthz, never through Envoy a
// second time: decideRequestFromCheck (extauthz.go) never attaches
// approval_id to an outgoing DecideRequest, deliberately (Task 3's own
// report: "the consuming side of a retry is a direct-PDP-call concern the
// proto already supports without extauthz needing new plumbing") -- there
// is no way to make Envoy carry one. E5 only requires the non-blocking
// surface to degrade to deny plus a FINDABLE pending record; this proves
// the record it finds is real and actionable by resolving it the way the
// system actually supports, not by inventing a retry path extauthz itself
// does not have.
//
// calibDelegation exists because the real escalating call below can never
// itself reach a real audit row this test could compare a fresh
// reconstruction against ahead of time (an escalated decision is still
// audited, but this test wants to verify its reconstruction technique
// BEFORE betting the whole proof on it). It shares the escalating
// delegation's own tool, method, and headers exactly, differing only in
// EscalateAt (unset, so it allows outright) and in the token's own value,
// which never reaches raw_input at all (proof 6 proves this directly) -- so
// its own RawInput is provably identical to the escalating call's, which is
// what licenses reusing calibRawInput, unchanged, as the retry's own
// RawInput.
func TestIntegration_Envoy_EscalateDeniesWithFindablePendingApproval_ApprovedRetrySucceeds(t *testing.T) {
	seedExtauthzAgentOnce(t)
	seedExtauthzPermitPolicy(t)

	const path = "/proof5-escalate-item"
	seedToolCatalogEntry(t, envoyTenant, path, tierPtr(models.ActionTierDestructive), "delete", nil, nil)

	calibDelegation := newExtauthzDelegation(t,
		"extauthz proof 5 calibration: same path and headers, no escalation -- self-checks the "+
			"reconstruction technique before the escalating call below relies on it",
		models.ActionTierDestructive, nil)
	calibToken := mintToken(t, envoyPdpClient, calibDelegation.ID)

	escalateAt := models.ActionTierExternalComms
	escDelegation := newExtauthzDelegation(t,
		"extauthz proof 5: escalation degrades to deny plus a findable pending approval (E5)",
		models.ActionTierDestructive, &escalateAt)

	// Calibration call: allows outright.
	calibStatus, calibBody, _, calibSent := envoyDo(t, http.MethodGet, path, calibToken, nil)
	if calibStatus != http.StatusOK {
		t.Fatalf("calibration call status = %d, want 200 (no EscalateAt, sufficient ceiling -- must allow "+
			"outright); body: %s", calibStatus, calibBody)
	}
	calibRawInput := rawInputJSON(http.MethodGet, path, reconstructHeaders(http.MethodGet, path, calibSent, false))

	// Self-consistency check: the reconstruction must hash to the SAME
	// digest audit_chain actually stored for THIS calibration decision,
	// before this test trusts it for the escalating call below.
	calibRows := fetchAuditChain(t, envoyTenant)
	if len(calibRows) == 0 {
		t.Fatal("no audit rows for envoyTenant after the calibration call")
	}
	calibWant := sha256.Sum256([]byte(calibRawInput))
	if calibGot := calibRows[len(calibRows)-1].InputDigest; calibGot != calibWant {
		t.Fatalf("calibration self-consistency check failed: the reconstructed raw_input does not hash to "+
			"the calibration decision's own audit digest -- the header-reconstruction technique this proof "+
			"depends on does not hold for real Envoy traffic here, so the retry below cannot be trusted "+
			"either. reconstructed=%s got=%x want=%x", calibRawInput, calibGot, calibWant)
	}

	// The real escalating call: identical path and headers, a different
	// token -- which cannot itself change RawInput (proof 6), so this
	// call's own RawInput is provably calibRawInput, unchanged.
	escStatus, escBody, escHeader, _ := envoyDo(t, http.MethodGet, path, mintToken(t, envoyPdpClient, escDelegation.ID), nil)
	if escStatus != http.StatusForbidden {
		t.Fatalf("escalating call status = %d, want 403 (E5: a non-blocking surface degrades ESCALATE to "+
			"deny); body: %s", escStatus, escBody)
	}
	approvalID := escHeader.Get(approvalIDHeaderName)
	if approvalID == "" {
		t.Fatalf("%s header is empty -- E5 requires the denial to carry enough to find the pending "+
			"approval; body: %s", approvalIDHeaderName, escBody)
	}
	if !strings.Contains(escBody, approvalID) {
		t.Errorf("denial body = %q, want it to also carry approval id %q, for a human reading a captured "+
			"403 without knowing to look for a header by name", escBody, approvalID)
	}

	approvalUUID, err := uuid.Parse(approvalID)
	if err != nil {
		t.Fatalf("%s = %q is not a valid UUID: %v", approvalIDHeaderName, approvalID, err)
	}
	pending, err := store.New(testDB, envoyTenant).LoadApproval(t.Context(), approvalUUID)
	if err != nil {
		t.Fatalf("LoadApproval() error = %v, want the pending row the denial pointed at", err)
	}
	if pending.Status != "pending" {
		t.Fatalf("approval status = %q, want %q", pending.Status, "pending")
	}
	if pending.RootPrincipal != extauthzSubject {
		t.Errorf("approval RootPrincipal = %q, want %q", pending.RootPrincipal, extauthzSubject)
	}

	// Approve out of band, THROUGH THE ADMIN PLANE. Until Phase 14 Task 8
	// this step was a direct UPDATE issued by the test itself, standing in
	// for a control plane that did not exist yet; the claim it supported was
	// only ever "some privileged writer could resolve this." Now there is a
	// real one: a live stratium-pap process (pap-extauthz, compose), a real
	// operator, and a real OIDC token from a real IdP. Nothing in
	// stratium-pdp or stratium-pep could perform this step either way -- the
	// PDP's serving role holds no UPDATE grant on approvals at all (E7;
	// TestIntegration_Approvals_ServingRoleCannotUpdate, above, proves that
	// absence directly), and the PAP connects as a different role entirely.
	// That absence is what makes routing the approval through the admin
	// plane the ONLY way this retry can succeed.
	//
	// pap-extauthz, not the stratium-pap serving the Task 8 proofs: N1 fixes
	// a PAP process's tenant at startup and forbids a request from carrying
	// one, so approving a row in envoyTenant requires a process configured
	// for envoyTenant. See that compose service's own comment.
	//
	// The operator is the realm user whose email is extauthzSubject, and
	// that is not a coincidence to be tidied away: N7 (spec §4.10.1)
	// requires an approver's own identity to equal the approval's
	// root_principal, which the PDP populated from pep-extauthz's
	// STRATIUM_PEP_SUBJECT. The negative below is what proves that gate is
	// live rather than merely satisfied by luck -- a DIFFERENT admin, with
	// every role privilege this route requires, is still refused.
	wrongAdmin := papAccessToken(t, papAdminUser, papAdminPass)
	wrongStatus, wrongBody := papDo(t, papExtauthzAddr, http.MethodPost,
		"/v1/approvals/"+approvalID+"/approve", wrongAdmin, nil)
	if wrongStatus != http.StatusForbidden {
		t.Fatalf("approving as an admin who is NOT the root principal = %d, want 403 (N7: a role is "+
			"necessary and never sufficient); body: %s", wrongStatus, wrongBody)
	}
	// The status alone does not attribute the refusal, and that matters
	// here more than usual: this route is ALSO gated at RoleAdmin, so a 403
	// is equally consistent with N7 having fired and with pap-admin simply
	// not clearing the role floor -- which is what a renamed realm group
	// would quietly turn this proof into, still green and proving nothing.
	// The body separates them: authorize (cmd/stratium-pap/server.go) writes
	// a bare "forbidden" for a role refusal, while writeStoreError surfaces
	// ErrApproverNotRootPrincipal's own message for N7's. Reaching that
	// message means this operator cleared RoleAdmin, reached decideApproval,
	// reached internal/store, and was refused on identity.
	if !strings.Contains(wrongBody, "root principal") {
		t.Fatalf("approving as the wrong admin was refused with %q, want a body naming N7's own refusal "+
			"(store.ErrApproverNotRootPrincipal) -- a bare \"forbidden\" is the ROLE floor talking, which "+
			"would mean this operator never reached the identity check at all and this negative proves "+
			"nothing about N7", wrongBody)
	}

	approver := papAccessToken(t, papExtauthzApproverUser, papExtauthzApproverPass)
	var approved models.Approval
	papJSON(t, papExtauthzAddr, http.MethodPost, "/v1/approvals/"+approvalID+"/approve", approver, nil, &approved)
	if approved.Status != "approved" {
		t.Fatalf("PAP approve returned status %q, want %q", approved.Status, "approved")
	}
	if approved.ID != approvalUUID {
		t.Fatalf("PAP approve returned approval %s, want the pending %s", approved.ID, approvalUUID)
	}

	// The retry -- see this function's own doc comment for why it is a
	// direct Decide call, not a second trip through Envoy. Tool and
	// RawInput reuse the escalating call's own values exactly:
	// models.Approval.Verify checks both for equality against what the
	// original escalation recorded.
	retryToken := mintToken(t, envoyPdpClient, escDelegation.ID)
	retryResp, err := envoyPdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
		Token: retryToken, AgentId: extauthzAgentID.String(), Subject: extauthzSubject,
		Tool: path, RawInput: calibRawInput, ApprovalId: &approvalID,
	})
	if err != nil {
		t.Fatalf("retry Decide() error = %v, want a decision", err)
	}
	if retryResp.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
		t.Fatalf("retry Effect = %v, want EFFECT_ALLOW (reason: %s) -- E5 end to end requires an approved "+
			"retry to succeed", retryResp.GetEffect(), retryResp.GetReason())
	}
	if retryResp.GetApprovalId() != "" {
		t.Errorf("retry ApprovalId = %q, want empty: no second approval is created on an approved retry",
			retryResp.GetApprovalId())
	}
}
