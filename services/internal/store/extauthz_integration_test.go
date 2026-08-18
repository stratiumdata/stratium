//go:build integration

// Task 4's own proof (docs/superpowers/sdd/2026-08-13-phase-10-extauthz/
// task-4-brief.md): everything Tasks 1-3 built in cmd/stratium-pep/
// extauthz.go was proven against hand-constructed envoy.service.auth.v3.
// CheckRequest values, which proves the MAPPING (a CheckRequest becomes the
// right DecideRequest, a DecideResponse becomes the right CheckResponse) but
// not the INTEGRATION -- a real Envoy in front of a real stratium-pep
// extauthz, in front of a real stratium-pdp. Every other enforcement surface
// in this binary was proven against the real thing it was built for (hook
// via cache_e2e_integration_test.go, mcp via mcp_e2e_integration_test.go --
// this line said "hook and mcp against a real claude session" until the mcp
// live proof landed, and no such proof ever existed for either; see
// internal/authz/conformance_test.go's C19 for the full correction and for
// the two places, both generated from proto/target/v1/target.proto, that
// still carry the original phrasing); this file is that proof for
// extauthz, against deploy/docker/docker-compose.yml's own envoy,
// pep-extauthz, pdp-extauthz, and echo-upstream services.
//
// Nine independent top-level tests -- six from Phase 10 Task 4, one per proof
// that brief asks for, plus two added by Phase 15 Task 5 (K5's refusal of an
// unbound token and K7's refusal of an authority this surface does not serve)
// and one by Phase 15 Task 7 (C25 itself: a bound token presented with no
// proof) -- rather than one test with nine t.Run subtests:
// TestIntegration_Escalation_* in
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
// chain for a real request -- proof 6 to check neither "authorization" nor
// the Phase 15 "dpop" proof is in it (K10), proof 5 to resend the identical
// value on a direct retry (see that test's own comment for why it cannot go
// through Envoy a second time).
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
	"crypto/ecdsa"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
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

// extauthzPublicAuthority is the authority every request in this file
// ADDRESSES, as distinct from envoyAddr, which is the host:port it DIALS. It
// must equal docker-compose.yml's own pep-extauthz
// STRATIUM_PEP_EXTAUTHZ_ALLOWED_HOSTS exactly (Phase 15, K7): extauthz refuses
// an authority it is not configured to serve, and builds htu from the
// configured spelling rather than the observed one.
//
// The two differ on purpose, and not only because compose publishes envoy's
// 10000 on an ephemeral host port no static allowlist could name. It is the
// ordinary deployment shape: an agent behind a load balancer connects to
// whatever address resolves and addresses a stable public hostname, and it is
// that hostname -- not the socket -- that lands in Host, that the surface
// validates, and that the agent signs into its proof's htu. envoyDo sets it
// via http.Request.Host (which overrides the URL's own authority on the
// wire), and extauthzProof signs the same string.
const extauthzPublicAuthority = "envoy.stratium.test"

// approvalIDHeaderName mirrors cmd/stratium-pep/extauthz.go's own
// unexported approvalIDHeader constant exactly. Duplicated, not imported:
// package main cannot be imported, and re-deriving the value from a live
// response would defeat the point of an independently stated comparison.
const approvalIDHeaderName = "stratium-approval-id"

// extauthzCredentialHeaderNames mirrors extauthz.go's own credentialHeaderNames
// exactly -- see that file's own doc comment for why the list stops at
// exactly these four (RFC-fixed bearer-authority headers only, not a
// deployment-specific guess, which would be the PEP classifying something).
// dpop is the fourth as of Phase 15 (RFC 9449 §4.1): spec §4.7.2 K10 keeps a
// proof out of raw_input for the same reason the other three stay out, and
// proof 6 below is what checks it against a real request rather than a
// constructed one.
var extauthzCredentialHeaderNames = map[string]bool{
	"authorization":       true,
	"cookie":              true,
	"proxy-authorization": true,
	"dpop":                true,
}

// mintExtauthzBoundToken mints a token bound to key's public half (spec
// §4.7.2 K6) through the real IssueToken RPC, so the containerized PDP's own
// verifier is what decides the token is genuine -- the same reasoning
// mintToken's doc comment gives, extended by the one field that makes the
// token usable on this surface at all as of Phase 15.
//
// Every proof below that expects to REACH the upstream has to use this rather
// than mintToken: extauthz refuses an unbound token outright (K5), so a bearer
// token now produces a 403 no matter how permissive the policy behind it is.
// TestIntegration_Envoy_UnboundTokenRefusedEvenWhenPermitted is the proof of
// exactly that.
//
// The proofs that expect a DENIAL deliberately keep calling mintToken, and
// that is not laziness: a denial they attribute to a revoked delegation or a
// tier ceiling must be attributable to THAT and not to a binding requirement
// that would have refused the request anyway. Each one asserts the PDP's own
// reason text, so a K5 refusal arriving instead fails them loudly rather than
// passing on the right status code for the wrong reason.
func mintExtauthzBoundToken(t *testing.T, delegationID uuid.UUID, key *ecdsa.PrivateKey) string {
	t.Helper()
	doc, err := (&jose.JSONWebKey{Key: key.Public()}).MarshalJSON()
	if err != nil {
		t.Fatalf("marshal public jwk: %v", err)
	}
	jwk := string(doc)
	const ttlSeconds = 10 * 365 * 24 * 60 * 60 // always clamped to the delegation's own expiry; see mintToken
	resp, err := envoyPdpClient.IssueToken(t.Context(), &pdpgrpc.IssueTokenRequest{
		DelegationId: delegationID.String(),
		TtlSeconds:   ttlSeconds,
		DpopJwk:      &jwk,
	})
	if err != nil {
		t.Fatalf("mint bound token for delegation %s: %v", delegationID, err)
	}
	return resp.GetToken()
}

// extauthzProof builds an RFC 9449 proof for the request this file is about
// to send through Envoy, signed by key. jti is fresh per call because K8
// makes it single-use in the database: two proofs sharing one would collide,
// and the second request would deny for replay rather than for whatever the
// calling proof is actually about.
//
// htu is stated INDEPENDENTLY here rather than read back from anything the
// PEP computed: "http://" + extauthzPublicAuthority + path is the URI this
// test's own client addressed (see that constant's doc comment for why the
// addressed authority is not the dialed one), which is what a real agent
// minting a proof would use. So
// a request that reaches the upstream is the end-to-end evidence that
// cmd/stratium-pep/extauthz.go's observedURI reconstructs the SAME string
// from what real Envoy reports -- scheme, authority, and path, from three
// separate accessors -- and a reconstruction that differed in any of the
// three would deny instead. That is the only way this property can be
// checked: the PDP compares the two, and neither side is visible to the other.
func mustDPoPSigner(t *testing.T, key *ecdsa.PrivateKey) jose.Signer {
	t.Helper()
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: key},
		(&jose.SignerOptions{EmbedJWK: true}).WithType("dpop+jwt"),
	)
	if err != nil {
		t.Fatalf("new jose signer: %v", err)
	}
	return signer
}

func extauthzProof(t *testing.T, key *ecdsa.PrivateKey, method, path string) string {
	t.Helper()
	proof, err := josejwt.Signed(mustDPoPSigner(t, key)).Claims(map[string]any{
		"htm": method,
		"htu": "http://" + extauthzPublicAuthority + path,
		"jti": uuid.NewString(),
		"iat": time.Now().Unix(),
	}).Serialize()
	if err != nil {
		t.Fatalf("serialize proof: %v", err)
	}
	return proof
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
	return envoyDoAs(t, extauthzPublicAuthority, method, path, token, extra)
}

// envoyDoAs is envoyDo with the ADDRESSED authority as a parameter, for the
// one proof that needs to address an authority this surface does not serve.
func envoyDoAs(t *testing.T, authority, method, path, token string, extra map[string]string) (status int, body string, respHeader http.Header, sentHeader map[string]string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, "http://"+envoyAddr+path, nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	// The authority this request ADDRESSES, overriding the dialed host:port
	// the URL carries. Go puts req.Host on the wire as the Host header when
	// it is non-empty, so this is what Envoy reports and what extauthz
	// validates -- see extauthzPublicAuthority's own doc comment. Not in
	// req.Header, and therefore not in sentHeader below: reconstructHeaders
	// adds ":authority" explicitly instead.
	req.Host = authority
	req.Header.Set("User-Agent", extauthzTestUserAgent)
	req.Header.Set("Accept-Encoding", extauthzTestAcceptEncoding)
	for name, value := range extra {
		req.Header.Set(name, value)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	// A proof, when a caller has one, rides in extra under the RFC 9449
	// header name -- deliberately NOT a dedicated parameter here, because
	// http.Header.Set canonicalizes "DPoP" to "Dpop" on the wire and that
	// third casing is itself worth sending: extauthz folds header names to
	// lower case before matching (extractCredentials), and a proof that only
	// ever arrived under one spelling would leave that fold unproven against
	// a real Envoy.
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
		// approvalIDHeaderName alongside the credentials: as of Phase 15 Task
		// 6 both network surfaces CONSUME that header rather than reporting it
		// (cmd/stratium-pep/extauthz.go's consumedRequestKey), for a reason
		// that is not K10's -- raw_input has to stay byte-identical between an
		// escalating request and its approved retry, because the approval is
		// bound to sha256(raw_input). Mirrored here so this reconstruction
		// cannot drift from what the surface actually does; no proof in this
		// file sends the header today, so it changes no current digest.
		if extauthzCredentialHeaderNames[lower] || lower == approvalIDHeaderName {
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
	// The ADDRESSED authority, not the dialed one -- envoyDo overrides Host.
	headers[":authority"] = extauthzPublicAuthority
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
	key := dpopKey(t)
	token := mintExtauthzBoundToken(t, delegation.ID, key)

	// A 200 here is now two properties at once, and the second is the one
	// only a live stack can establish: the action is permitted, AND the htu
	// this test signed independently ("http://" + extauthzPublicAuthority +
	// path) equals the observed_uri extauthz reconstructed from what real
	// Envoy reported. Any disagreement -- a scheme read from the wrong place,
	// an authority taken from the upstream rather than the downstream, a query
	// string left on -- denies at the PDP's htu comparison instead.
	//
	// The signed authority is deliberately NOT envoyAddr. Compose publishes
	// Envoy on an ephemeral port, so no static allowlist could name the dialed
	// address; envoyDo sets http.Request.Host to extauthzPublicAuthority and
	// this proof signs the same value. That is what a real client does -- it
	// dials whatever DNS resolves and addresses a stable hostname, and RFC
	// 9449 §4.3 binds htu to the URI the client USED, never to the socket.
	// It also makes the two strings genuinely different, which is what lets
	// this proof show that Envoy reports the caller's Host rather than the
	// address it was reached on -- the hazard the allowlist exists to close.
	status, body, _, _ := envoyDo(t, http.MethodGet, path, token,
		map[string]string{"DPoP": extauthzProof(t, key, http.MethodGet, path)})
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
// 6: neither credential header -- authorization, nor the DPoP proof this
// phase adds (K10) -- reaches the audit row's input-digest source, checked
// against a real request through real Envoy rather than a constructed
// CheckRequest (Task 2's own unit-level proof; see this file's package doc
// for what real Envoy traffic can do differently). A custom header
// (x-proof6-marker) is the positive control: it must survive into the
// reconstruction, or a digest match below would be vacuous -- proof the
// reconstruction preserves content in general, not merely proof that
// everything gets dropped.
//
// The digest match is what makes this structural rather than an inspection
// of one value. It compares SHA-256 of an INDEPENDENTLY reconstructed
// raw_input against the digest the PDP actually stored, so it fails if
// raw_input differs from the reconstruction by so much as one byte in any
// direction -- a leaked proof under any spelling, a header dropped that
// should not have been, an addition nobody accounted for.
//
// The proof header is sent as "DPoP", which Go's http.Header.Set
// canonicalizes to "Dpop" -- a third casing, matching neither the RFC's own
// spelling nor the lower-case form Envoy delivers to ext_authz, and one no
// unit fixture would have thought to construct.
func TestIntegration_Envoy_AuthorizationHeaderExcludedFromAuditDigest(t *testing.T) {
	seedExtauthzAgentOnce(t)
	seedExtauthzPermitPolicy(t)

	const path = "/proof6-digest-item"
	const marker = "proof6-marker-value"
	seedToolCatalogEntry(t, envoyTenant, path, tierPtr(models.ActionTierReadOnly), "read", nil, nil)
	delegation := newExtauthzDelegation(t, "extauthz proof 6: no credential reaches the audit digest source",
		models.ActionTierReadOnly, nil)
	key := dpopKey(t)
	token := mintExtauthzBoundToken(t, delegation.ID, key)
	proof := extauthzProof(t, key, http.MethodGet, path)

	status, body, _, sentHeader := envoyDo(t, http.MethodGet, path, token, map[string]string{
		"X-Proof6-Marker": marker,
		"DPoP":            proof,
	})
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
	for _, credential := range []string{"authorization", "dpop"} {
		if _, ok := headers[credential]; ok {
			t.Fatalf("reconstruction still carries a %q key -- reconstructHeaders itself is "+
				"broken, this proof cannot proceed: %+v", credential, headers)
		}
	}
	if v, ok := headers["x-proof6-marker"]; !ok || v != marker {
		t.Fatalf("reconstruction dropped the non-credential positive-control header -- a digest match "+
			"below would be vacuous (a digest computed over nothing meaningful); got %+v", headers)
	}
	reconstructed := rawInputJSON(http.MethodGet, path, headers)
	if strings.Contains(reconstructed, "dpop") || strings.Contains(reconstructed, proof) {
		t.Fatalf("reconstructed raw_input carries \"dpop\" or the proof JWT itself (K10): %s", reconstructed)
	}
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
// THE RETRY GOES THROUGH ENVOY, and through Phase 14 it could not. The reason
// recorded here then was that decideRequestFromCheck "never attaches
// approval_id to an outgoing DecideRequest, deliberately... there is no way to
// make Envoy carry one." Phase 15 Task 6 made both clauses false: extauthz now
// reads stratium-approval-id off a request header and forwards it, AND strips
// it, so the retry's raw_input still hashes to the digest the approval is
// bound to.
//
// I declined this rewrite once, on the grounds that a through-Envoy retry
// needs the escalating call to be minted BOUND -- which is true -- and that
// rebinding it was too large a change to a proof conformance_test.go points at
// for C23 and that also carries N7's wrong-admin negative. Fix round 3 removed
// that objection rather than overruling it: extauthz now refuses an UNBOUND
// escalation outright, so the escalating call HAD to become bound for this
// proof to reach a degrade at all. Once it was, the retry cost two header
// values. The lesson is worth the sentence -- a cost estimate is a claim to
// re-check after the code around it moves.
//
// E5 only requires the non-blocking surface to degrade to deny plus a FINDABLE
// pending record. This now proves the record is not merely findable but
// SPENDABLE, over the exact request docs/pep.md tells an operator to make.
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
	// Bound, with a proof: the calibration call is the only one here that
	// must actually be FORWARDED, and extauthz refuses an unbound token on
	// the ALLOW branch (K5). The escalating call below stays unbound
	// deliberately -- an ESCALATE degrades to a denial before that branch is
	// ever reached, so its binding is irrelevant to what it proves, and
	// leaving it unbound keeps the retry a plain direct Decide call with no
	// proof to re-mint.
	//
	// This makes the DPoP header a third difference between the two calls,
	// on top of EscalateAt and the token value, and the doc comment's claim
	// that their raw_input is identical still holds for the same reason it
	// held for the token: a credential header never reaches raw_input (K10,
	// proof 6). It is not assumed here either -- the calibration
	// self-consistency check below hashes this call's reconstruction against
	// its own real audit row, and models.Approval.Verify re-checks the
	// escalating call's against the same value on the retry.
	calibKey := dpopKey(t)
	calibToken := mintExtauthzBoundToken(t, calibDelegation.ID, calibKey)

	escalateAt := models.ActionTierExternalComms
	escDelegation := newExtauthzDelegation(t,
		"extauthz proof 5: escalation degrades to deny plus a findable pending approval (E5)",
		models.ActionTierDestructive, &escalateAt)

	// Calibration call: allows outright.
	calibStatus, calibBody, _, calibSent := envoyDo(t, http.MethodGet, path, calibToken,
		map[string]string{"DPoP": extauthzProof(t, calibKey, http.MethodGet, path)})
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

	// The real escalating call: identical path, a different token and a
	// different proof -- neither of which can change RawInput (proof 6), so
	// this call's own RawInput is provably calibRawInput, unchanged.
	//
	// BOUND, and it has to be as of Phase 15 Task 6's fix round 3: extauthz
	// refuses an UNBOUND escalation outright rather than degrading it (K5
	// before E5), because an approval cannot rescue a token that carries no
	// cnf.jkt -- matchProof returns nil for one whatever proof accompanies it,
	// so the retry always resolves to an ALLOW the surface refuses anyway.
	// This test caught that live: with mintToken here it now gets K5's
	// refusal and no approval id at all, which is the correct new behaviour
	// and is asserted directly by
	// TestCheck_EscalateOnUnboundToken_RefusedNotDegraded.
	escKey := dpopKey(t)
	escToken := mintExtauthzBoundToken(t, escDelegation.ID, escKey)
	escStatus, escBody, escHeader, _ := envoyDo(t, http.MethodGet, path, escToken,
		map[string]string{"DPoP": extauthzProof(t, escKey, http.MethodGet, path)})
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

	// THE RETRY, THROUGH ENVOY -- see this function's own doc comment for why
	// it used to be a direct Decide call and why it no longer has to be.
	//
	// Same token, same path, a FRESH proof, and the approval id in the header
	// the denial handed back. Every one of those is load-bearing: the original
	// proof's jti is spent (K8) so it cannot be replayed; without the id the
	// PDP would create a SECOND pending approval instead of resolving this
	// one; and the id must not disturb raw_input, because
	// models.Approval.Verify checks sha256(raw_input) for equality against
	// what the escalation recorded -- which is why extauthz strips the header
	// rather than reporting it.
	//
	// A 200 through Envoy is therefore the end-to-end evidence for all three
	// at once, and for the operator recipe docs/pep.md publishes. A direct
	// Decide call could never have shown any of it: it bypasses the surface
	// that reads and strips the header.
	retryStatus, retryBody, _, _ := envoyDo(t, http.MethodGet, path, escToken, map[string]string{
		"DPoP":               extauthzProof(t, escKey, http.MethodGet, path),
		approvalIDHeaderName: approvalID,
	})
	if retryStatus != http.StatusOK {
		t.Fatalf("retry through Envoy status = %d, want 200 -- E5 end to end requires an approved retry to "+
			"succeed, and this is the exact request docs/pep.md tells an operator to make; body: %s",
			retryStatus, retryBody)
	}

	// No SECOND approval was created: the retry resolved the existing one
	// rather than escalating afresh. Without the header this is exactly what
	// would have happened, and a human would be asked twice.
	after := pendingApprovalCount(t, escDelegation.ID)
	if after != 0 {
		t.Errorf("pending approvals for this delegation after the retry = %d, want 0 -- a retry that failed "+
			"to carry the approval id escalates again and leaves a fresh pending row", after)
	}
}

// pendingApprovalCount reports how many approvals for delegationID are still
// pending. Used by proof 5 to prove the approved retry RESOLVED the existing
// approval rather than creating a second one -- the failure mode a retry that
// silently dropped the approval id would produce, which no status code shows.
func pendingApprovalCount(t *testing.T, delegationID uuid.UUID) int {
	t.Helper()
	var n int
	withTenantTx(t, envoyTenant, func(tx *sql.Tx) {
		if err := tx.QueryRowContext(t.Context(),
			`SELECT count(*) FROM approvals WHERE delegation_id = $1 AND status = 'pending'`,
			delegationID.String()).Scan(&n); err != nil {
			t.Fatalf("count pending approvals: %v", err)
		}
	})
	return n
}

// TestIntegration_Envoy_UnboundTokenRefusedEvenWhenPermitted is K5's live
// proof and the converse half of C25 -- the migration hole C25's own wording
// does not cover. C25 says a bound token presented without a proof is denied;
// it says nothing about a token that was never bound, and an attacker who
// simply asks IssueToken for an ordinary bearer token walks through that gap
// on a surface where the request arrives from the party being policed.
//
// It is deliberately the SAME fixture as proof 1 -- same delegation shape,
// same READ_ONLY catalog entry under a READ_ONLY ceiling, same blanket-permit
// policy, same method and path shape -- differing in exactly one property:
// the token is minted with no dpop_jwk, so the PDP allows the action and
// reports sender_constrained=false, and extauthz refuses it anyway. Without
// that pairing a 403 here would prove nothing; with it, the 403 is
// attributable to the binding and to nothing else.
//
// The reason is asserted, and specifically asserted NOT to be C25's own: the
// two name opposite defects, and an operator told "you sent no proof" when
// the real problem is "your token cannot carry one" has been sent to fix the
// wrong thing.
func TestIntegration_Envoy_UnboundTokenRefusedEvenWhenPermitted(t *testing.T) {
	seedExtauthzAgentOnce(t)
	seedExtauthzPermitPolicy(t)

	const path = "/proof-k5-unbound-item"
	seedToolCatalogEntry(t, envoyTenant, path, tierPtr(models.ActionTierReadOnly), "read", nil, nil)
	delegation := newExtauthzDelegation(t, "extauthz K5: an unbound token is refused on a network surface",
		models.ActionTierReadOnly, nil)
	// mintToken, not mintExtauthzBoundToken: no dpop_jwk, so the PDP mints a
	// plain bearer token exactly as it did before this phase existed. That is
	// the one difference from proof 1.
	token := mintToken(t, envoyPdpClient, delegation.ID)

	status, body, _, _ := envoyDo(t, http.MethodGet, path, token, nil)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 -- an unbound token must be refused on this surface even though the "+
			"PDP allows the action (K5); body: %s", status, body)
	}
	if !strings.Contains(body, "not bound to a key") {
		t.Errorf("body = %q, want extauthz's own K5 refusal wording (\"... not bound to a key\") -- any other "+
			"denial means this 403 came from somewhere else and the binding requirement is unproven", body)
	}
	if !strings.Contains(body, "dpop_jwk") {
		t.Errorf("body = %q, want it to name dpop_jwk -- the only action available to a caller holding an "+
			"unbound token is to request a bound one", body)
	}
	if strings.Contains(body, "carried no dpop proof") {
		t.Errorf("body = %q carries C25's own reason, which names the opposite defect: this caller's token "+
			"is not bound at all, so producing a proof for it is impossible", body)
	}
}

// TestIntegration_Envoy_UnservedAuthorityRefused is the live half of the
// hazard review round 1 found, and the property that makes htu's authority
// mean anything at all.
//
// Envoy reports the caller's own Host/:authority header as
// AttributeContext_HttpRequest.Host. Before this check existed, an attacker
// who captured a bound token and its proof in flight to one gateway -- and
// dropped the request, leaving the jti unspent -- could replay both at any
// other gateway reachable to them, sending the original Host. Every check
// downstream passed, because the second gateway reported the authority it was
// told. This is that replay, executed for real against the live stack: the
// same request, differing from the passing one in exactly one property, the
// addressed authority.
//
// It is a genuinely different request from proof 1's, not a mangled one: the
// bound token is real and unexpired, the proof is freshly signed and its jti
// unspent, the delegation permits the action, and the policy allows it.
// Everything an attacker would hold, they hold here.
func TestIntegration_Envoy_UnservedAuthorityRefused(t *testing.T) {
	seedExtauthzAgentOnce(t)
	seedExtauthzPermitPolicy(t)

	const path = "/proof-k7-unserved-authority"
	seedToolCatalogEntry(t, envoyTenant, path, tierPtr(models.ActionTierReadOnly), "read", nil, nil)
	delegation := newExtauthzDelegation(t, "extauthz K7: an authority this surface does not serve is refused",
		models.ActionTierReadOnly, nil)
	key := dpopKey(t)
	token := mintExtauthzBoundToken(t, delegation.ID, key)

	// The proof binds to the OTHER gateway, exactly as a captured one would.
	const otherGateway = "gw-elsewhere.stratium.test"
	proof, err := josejwt.Signed(mustDPoPSigner(t, key)).Claims(map[string]any{
		"htm": http.MethodGet, "htu": "http://" + otherGateway + path,
		"jti": uuid.NewString(), "iat": time.Now().Unix(),
	}).Serialize()
	if err != nil {
		t.Fatalf("serialize proof: %v", err)
	}

	status, body, _, _ := envoyDoAs(t, otherGateway, http.MethodGet, path, token,
		map[string]string{"DPoP": proof})
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 -- a request addressing an authority this surface is not "+
			"configured to serve must be refused, however good its token and proof are; body: %s", status, body)
	}
	if !strings.Contains(body, "not one this surface is configured to serve") {
		t.Errorf("body = %q, want extauthz's own unserved-authority wording -- any other denial means the "+
			"403 came from somewhere else and this replay is unproven", body)
	}
	if strings.Contains(body, otherGateway) || strings.Contains(body, extauthzPublicAuthority) {
		t.Errorf("body = %q echoes an authority -- neither the caller's claim (request metadata in a "+
			"denial body) nor this deployment's own configured set (reconnaissance) belongs there", body)
	}

	// The positive control: the SAME token and key, differing only in the
	// authority addressed and signed, is forwarded. Without it a 403 above
	// would be consistent with the fixture being broken in some way that has
	// nothing to do with authorities.
	okStatus, okBody, _, _ := envoyDo(t, http.MethodGet, path, token,
		map[string]string{"DPoP": extauthzProof(t, key, http.MethodGet, path)})
	if okStatus != http.StatusOK {
		t.Fatalf("control request status = %d, want 200 -- the same token and key addressed at the served "+
			"authority must be forwarded, or the 403 above is not attributable to the authority; body: %s",
			okStatus, okBody)
	}
}

// TestIntegration_Envoy_BoundTokenWithNoProofRefused is C25 itself, live on
// this surface: spec §7's own sentence, "a delegation token without a valid
// DPoP proof is denied when the token is sender-constrained."
//
// Everything before Task 7 proved this at a layer below a real request.
// internal/pdpgrpc's TestDecide_BoundTokenWithNoProof_Denies proves the PDP
// produces the denial, against a fake store; cmd/stratium-pep's
// TestCheck_BoundTokenWithNoProof_DeniesWithThePDPsOwnReason proves this
// surface relays it, against a fake PDP and a constructed CheckRequest.
// Neither shows a real Envoy carrying a real bound token to a real PDP and
// the caller being refused, which is the only form of the claim an operator
// would recognise -- and the form C25's proven-elsewhere pointer now names.
//
// Deliberately the SAME fixture as proof 1, differing in exactly one
// property: the DPoP header is absent. The token is genuine, bound, and
// unexpired; the delegation permits the action; the policy allows it; the
// authority is one this surface serves. Proof 1 sends the identical request
// WITH a proof and gets 200, so the 403 here is attributable to the missing
// proof and to nothing else -- and the control below re-establishes that with
// this test's own token rather than leaning on a sibling test to do it.
//
// The reason is asserted, and asserted NOT to be K5's, for the same reason
// TestIntegration_Envoy_UnboundTokenRefusedEvenWhenPermitted asserts the
// mirror image: the two name opposite defects. "Your token is bound and you
// sent no proof" is fixed by sending a proof; "your token was never bound" can
// only be fixed by obtaining a different token. An operator handed the wrong
// one of those goes and does the wrong thing.
func TestIntegration_Envoy_BoundTokenWithNoProofRefused(t *testing.T) {
	seedExtauthzAgentOnce(t)
	seedExtauthzPermitPolicy(t)

	const path = "/proof-c25-no-proof-item"
	seedToolCatalogEntry(t, envoyTenant, path, tierPtr(models.ActionTierReadOnly), "read", nil, nil)
	delegation := newExtauthzDelegation(t, "extauthz C25: a bound token presented with no proof is denied",
		models.ActionTierReadOnly, nil)
	key := dpopKey(t)
	token := mintExtauthzBoundToken(t, delegation.ID, key)

	// No DPoP header at all -- not an empty one. An empty header value and an
	// absent header are different requests, and C25 is about the second: a
	// caller that simply did not send a proof.
	status, body, _, _ := envoyDo(t, http.MethodGet, path, token, nil)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d, want 403 -- a sender-constrained token presented with no proof must be "+
			"denied (C25), however permitted the action behind it is; body: %s", status, body)
	}
	if !strings.Contains(body, "carried no dpop proof") {
		t.Errorf("body = %q, want the PDP's own errNoProof wording (\"... carried no dpop proof\") -- any "+
			"other denial means this 403 came from somewhere else and C25 is unproven here", body)
	}
	if strings.Contains(body, "not bound to a key") || strings.Contains(body, "dpop_jwk") {
		t.Errorf("body = %q carries K5's unbound-token refusal, which names the opposite defect: this "+
			"caller's token IS bound, so telling them to request a bound one is unactionable", body)
	}

	// The control: the same token, the same key, the same everything, with a
	// proof. Without it a 403 above would be consistent with the fixture being
	// broken in some way that has nothing to do with the proof -- a mis-seeded
	// catalog, an expired delegation, a token the PDP will not accept at all.
	okStatus, okBody, _, _ := envoyDo(t, http.MethodGet, path, token,
		map[string]string{"DPoP": extauthzProof(t, key, http.MethodGet, path)})
	if okStatus != http.StatusOK {
		t.Fatalf("control request status = %d, want 200 -- the SAME token with a proof must be forwarded, "+
			"or the 403 above is not attributable to the proof's absence; body: %s", okStatus, okBody)
	}
}
