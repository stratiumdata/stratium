//go:build integration

// Package store_test is Task 7's end-to-end proof: against a real Postgres
// and a real, containerized stratium-pdp, it confirms the whole slice
// documented in docs/superpowers/plans/2026-08-09-phase-1c-running-pdp.md —
// migrations from the binary's own startup, RLS tenant isolation with no
// WHERE clause in Go, the hash-linked audit chain, and a Decide call that
// denies honestly at the principal leg (the only outcome this slice can
// produce; see that plan's "What it deliberately does not prove").
//
// Extended for Phase 2b Task 4
// (docs/superpowers/plans/2026-08-09-phase-2b-policy-verdicts.md): the same
// live stack now also proves policy-verdict provenance survives the whole
// path into the response and the audit row — not just that the column
// exists (Task 2's tests already proved that and still missed the seam
// Task 3 found, where nothing ever set the field on a real decision) — that
// the hash chain still verifies across the migration that added the
// provenance columns, and that the ten-way concurrency measurement is
// unchanged by the wider audit row.
//
// Extended again for Phase 2c Task 5
// (docs/superpowers/sdd/2026-08-10-phase-2c-cedar-engine/task-5-brief.md):
// cmd/stratium-pdp/main.go wired policy.Configured(store, cedar.New())
// instead of policy.Unconfigured(), so this became the first live stack
// with a real policy engine in the path. proof2 (below) exercised
// Configured's own "no cedar policies for this tenant" case rather than
// Unconfigured's "no engine at all" case — both still deny with a single,
// named verdict, just attributed differently (see noPoliciesReason).
// proof7-proof9 seed real Cedar policies and prove: a permit produces this
// system's first-ever ALLOW on the principal leg, with the audit row's
// provenance compared against the response rather than merely non-empty; a
// forbid denies with that policy attributed; and an allowing policy still
// cannot exceed the delegation's max_action_tier (C14, end to end, with a
// real engine rather than a synthetic verdict). They run after proof5 and
// before the latency/concurrency measurements, deliberately: seeding them
// there means single_decide_latency_baseline and
// measured_concurrent_decide_split_on_the_same_tail measure Decide with
// several real Cedar policies actually being loaded, prepared, and
// evaluated on every call — not a zero-policy fast path — which is what
// "Cedar in the path" is supposed to mean for those two measurements.
//
// Extended again for Phase 4 Task 2
// (docs/superpowers/sdd/2026-08-11-phase-4-policy-engines/task-2-brief.md):
// main.go now wires policy.NewMulti(store, policy.Registry{"cedar":
// cedar.New()}) instead of policy.Configured — a registry of one engine
// today, but the seam that lets Rego/JSON/XACML (Tasks 3-5) join it without
// main.go changing again. proof2's zero-policies case now goes through
// Multi's own "no policies configured for this tenant" verdict rather than
// Configured's "no cedar policies" one — attributed to Source "none", not
// "cedar": with N possible registered languages instead of one, there is no
// single language left to name once a tenant has authored nothing in any
// of them, and literally no engine's Prepare is even invoked in that case
// (see policy.Multi's own doc comment in internal/policy/multi.go). Once
// this tenant's first cedar policy is seeded (proof7 onward), Source goes
// back to "cedar" — a real engine ran and decided something — exactly as
// before.
//
// Extended again for Phase 9 Task 3
// (docs/superpowers/sdd/2026-08-13-phase-9-tokens/task-3-brief.md):
// DecideRequest no longer carries a bare delegation_id at all — Decide now
// authenticates a signed token and reads the delegation id it names from
// the token's own claims (spec §4.7.1 K4). Every DecideRequest literal in
// this file set a field named Token to a plain delegation id string,
// unchanged from before that task, because minting a REAL token here was
// left for Task 4 (it is what moves the PEPs, and this file's own PEP-shaped
// proofs, onto tokens) — Task 3 only needed this file to keep compiling
// under `go vet -tags integration ./...`, one of its own required-green
// gates, and every proof that reached a live PDP through one of these
// requests observed a DENY for an unparseable token where it used to
// observe whatever the delegation itself would have produced —
// `make integration` failing was exactly this, named in the phase brief, not
// a regression Task 3 introduced quietly.
//
// Extended again for Phase 9 Task 4
// (docs/superpowers/sdd/2026-08-13-phase-9-tokens/task-4-brief.md): every
// Token field in this file now carries a genuinely signed token, minted
// through the real IssueToken RPC (mintToken, below) — the only way this
// process can produce one the containerized PDP's own Verify will accept,
// since its signing key is generated fresh at image build time and never
// reaches this test process (see deploy/docker/docker-compose.yml's own
// comment on STRATIUM_TOKEN_SIGNING_KEY_PATH). A delegation this file
// already had in hand from a real CreateDelegation response reuses that
// response's own Token field directly, at no extra cost; a delegation built
// directly against Postgres (seedDelegation/twoHopChain/singleHopDelegation
// — most of this file's fixtures, which have never gone through
// CreateDelegation and so have no token of their own) calls mintToken, this
// file's own test-side use of Phase 9 Task 4's production re-issuance path
// (cmd/stratium-pep/reissue.go).
//
// Build-tagged so `go test ./...` and `golangci-lint run ./...` skip it by
// default. `make integration` (repo root) is what runs it, against
// deploy/docker/docker-compose.yml: bring the stack up on a fresh volume,
// run this file with -tags=integration against the published ports, tear
// the stack down.
//
// It is an external test package (store_test, not store) deliberately: it
// dials the real gRPC server through package pdpgrpc, and pdpgrpc imports
// store — an internal store_test.go could not import pdpgrpc without an
// import cycle.
package store_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/google/uuid"
	"github.com/lib/pq" // also registers the "postgres" database/sql driver (used directly for pq.Array below)
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"stratium/internal/authz"
	"stratium/internal/config"
	"stratium/internal/grpctarget"
	"stratium/internal/pdpgrpc"
	"stratium/internal/policy"
	"stratium/internal/policy/cedar"
	"stratium/internal/policy/jsonpolicy"
	"stratium/internal/policy/rego"
	"stratium/internal/policy/xacml"
	"stratium/internal/store"
	"stratium/internal/token"
	"stratium/migrations"
	"stratium/pkg/audit"
	"stratium/pkg/classification"
	"stratium/pkg/models"
)

// secondTenantID is a tenant the running PDP is never configured for. It
// only ever needs to be internally consistent within this test, unlike the
// configured tenant (below), which must match whatever
// deploy/docker/docker-compose.yml set STRATIUM_TENANT_ID to — so it is a
// plain constant rather than another environment variable.
const secondTenantID = "tenant-two-integration"

// Package-level: set once in TestMain, read by every subtest. TestMain also
// owns the wait-for-readiness retries described in the task report, and
// closes both connections after m.Run().
//
// testDB deliberately connects as stratium_migrate (STRATIUM_IT_DATABASE_URL
// — see the Makefile's integration target), not as the stratium role the pdp
// container actually serves from. This test needs to seed fixtures directly
// (agents, delegations — there is no gRPC write path for either yet) and, in
// proof6, REVOKE a grant on audit_chain; both need privileges the serving
// identity must not have (see cmd/stratium-pdp's startup check). The system
// under test is only ever exercised through pdpClient, whose backing
// connection is whatever STRATIUM_DATABASE_URL the pdp container was given.
var (
	testDB           *sql.DB
	pdpClient        pdpgrpc.PDPServiceClient
	configuredTenant string

	// servingDB connects as the real serving identity (STRATIUM_IT_SERVING_
	// DATABASE_URL — the same "stratium" login role, member of stratium_app
	// only, that STRATIUM_DATABASE_URL gives the pdp container itself in
	// docker-compose.yml). testDB, above, is deliberately the wrong
	// connection for proving what the serving role can and cannot do: it
	// authenticates as stratium_migrate, which OWNS every table these
	// migrations create (CREATE DATABASE stratium OWNER stratium_migrate —
	// deploy/docker/init-db.sql) and so holds every privilege on it
	// regardless of what any GRANT statement says. Only a connection that is
	// genuinely the stratium_app role can make
	// TestIntegration_Approvals_ServingRoleCannotUpdate a real proof instead
	// of a tautology.
	servingDB *sql.DB

	// papDB connects as the admin plane's own serving identity
	// (STRATIUM_IT_PAP_DATABASE_URL — the "stratium_pap_login" role, member
	// of stratium_pap only, deploy/docker/init-db.sql), the same reasoning
	// servingDB's own doc comment gives for the PDP's identity, applied to
	// the write role migrations/000016_stratium_pap_role creates. Task 2's
	// own pap_role_integration_test.go is the only file that uses this
	// connection: every proof there needs a connection that is genuinely the
	// stratium_pap role, not testDB (which would make a write "succeed"
	// whether or not the GRANT it is supposed to prove even exists).
	papDB *sql.DB

	// narrowPdpClient and narrowTenant back
	// TestIntegration_Live_OrphanLanguageDeniesNamingIt: a second,
	// independently configured PDP (deploy/docker/docker-compose.yml's
	// pdp-narrow service) with its own fixed tenant and a registry one
	// language short of pdpClient's own four — see that test's own doc
	// comment for why the orphan-language case needs a second service to
	// reach live at all, rather than a second tenant on pdpClient's PDP.
	narrowPdpClient pdpgrpc.PDPServiceClient
	narrowTenant    string

	// resourcePdpClient and resourceTenant back
	// TestIntegration_Live_ResourceIdentityEnforcement (Phase 7 Task 4): a
	// third, independently configured PDP (deploy/docker/docker-compose.yml's
	// pdp-resource service) with its own fixed tenant, touched by nothing
	// else in this file. Neither pdpClient's tenant (TestEndToEnd's proof2
	// needs zero cedar policies at one specific point) nor
	// narrowPdpClient's (already carries a permanent
	// unconditional cedar forbid from its one existing live test) can serve
	// a live proof that needs a principal policy which legitimately
	// allows — see the compose file's own comment on pdp-resource for the
	// full reasoning.
	resourcePdpClient pdpgrpc.PDPServiceClient
	resourceTenant    string

	// envoyPdpClient and envoyTenant back extauthz_integration_test.go
	// (Phase 10 Task 4): a fourth, independently configured PDP
	// (deploy/docker/docker-compose.yml's pdp-extauthz service), its own
	// tenant, touched by nothing else in this file — the same reasoning
	// narrowPdpClient and resourcePdpClient's own comments already give,
	// restated a third time in that file's own package doc rather than
	// here. Dialed directly like the other three: extauthz_integration_
	// test.go needs a host-reachable gRPC client both to seed fixtures via
	// mintToken (IssueToken, the same real re-issuance path every other live
	// proof in this file uses) and to send the direct, out-of-band retry
	// Decide call proof 5 needs, which cannot go through Envoy at all (see
	// that test file's own comment on why).
	envoyPdpClient pdpgrpc.PDPServiceClient
	envoyTenant    string

	// envoyAddr is the real Envoy listener extauthz_integration_test.go
	// drives every one of its six proofs against — an http.Client target,
	// not a gRPC one, unlike every other package-level address here.
	envoyAddr string

	// proxyPdpClient and proxyTenant back proxy_integration_test.go (Phase
	// 11 Task 4): a sixth, independently configured PDP
	// (deploy/docker/docker-compose.yml's pdp-proxy service), its own
	// tenant, touched by nothing else in this file -- the same reasoning
	// narrowPdpClient, resourcePdpClient, and envoyPdpClient's own comments
	// already give, restated a fourth time in that file's own package doc
	// rather than here. Dialed directly like the other three: proxy_
	// integration_test.go needs a host-reachable gRPC client to seed
	// fixtures via mintToken (IssueToken), the same real re-issuance path
	// every other live proof in this file uses.
	proxyPdpClient pdpgrpc.PDPServiceClient
	proxyTenant    string

	// proxyTargetClient and directTargetClient both speak
	// grpctarget.TargetServiceClient -- the real generated client for
	// services/internal/grpctarget (proto/target/v1/target.proto) -- but
	// dial two different addresses. proxyTargetClient is dialed at
	// pep-proxy's own published port: every call through it is exactly what
	// a real caller's "point an existing gRPC client at this process
	// instead of the real target" (proxy.go's own package doc) looks like,
	// authorized or not depending on what each proof seeds. directTargetClient
	// is dialed straight at grpc-target's own published port, bypassing
	// stratium-pep proxy entirely -- used only to read grpc-target's own
	// call counter (CallCount), a side channel independent of anything the
	// proxy or the PDP reports (proxy_integration_test.go's own package doc).
	proxyTargetClient  grpctarget.TargetServiceClient
	directTargetClient grpctarget.TargetServiceClient

	// epochPdpClient and epochTenant back Phase 12 Task 3's live-stack
	// revocation-epoch proofs (revocation_epoch_e2e_integration_test.go): a
	// seventh, independently configured PDP (deploy/docker/docker-compose.yml's
	// pdp-epoch service), its own tenant, touched by nothing else in this
	// package — the same reasoning narrowPdpClient, resourcePdpClient,
	// envoyPdpClient, and proxyPdpClient's own comments already give,
	// restated a fifth time in that compose service's own comment rather
	// than here. Dialed directly like the other four: those proofs need a
	// host-reachable gRPC client to mint tokens (IssueToken) and to drive
	// real Decide()/CreateDelegation() calls whose responses carry the
	// epoch a future cache would validate against.
	epochPdpClient pdpgrpc.PDPServiceClient
	epochTenant    string

	// cacheConn, cacheTenant, and cacheAddr back Task 4's live-stack
	// decision-cache proofs (cache_e2e_integration_test.go): an eighth,
	// independently configured PDP (deploy/docker/docker-compose.yml's
	// pdp-cache service), its own tenant, touched by nothing else in this
	// package — the same reasoning narrowPdpClient, resourcePdpClient,
	// envoyPdpClient, proxyPdpClient, and epochPdpClient's own comments
	// already give, restated again in that compose service's own comment
	// rather than here.
	//
	// The raw *grpc.ClientConn is kept, not only a wrapped PDPServiceClient
	// (every other dedicated PDP above keeps only the latter): those proofs
	// deliberately stop and restart pdp-cache mid-test — the first PDP
	// instance in this whole stack any test is allowed to do that to — and
	// need to re-poll its health service (waitForServing, below) after each
	// restart, which needs the connection itself, not a client wrapping it.
	// gRPC's own client connection reconnects automatically once the
	// container is back, so this one connection, dialed once here, is reused
	// across every restart rather than leaking a fresh one each time.
	cacheConn   *grpc.ClientConn
	cacheTenant string
	cacheAddr   string

	// mcpAddr and mcpTenant back the `mcp` enforcement surface's live proofs
	// (mcp_e2e_integration_test.go): the EIGHTH PDP dedicated to a single
	// test file (pdp-narrow, pdp-resource, pdp-extauthz, pdp-proxy,
	// pdp-epoch, pdp-cache, pdp-pap, and this one —
	// deploy/docker/docker-compose.yml's pdp-mcp service) and its own
	// tenant, for the same reason every dedicated PDP above has one — those
	// proofs seed policies, create delegations through the real
	// "session-start" subcommand, and revoke one of them, which bumps
	// tenant_epoch for anything sharing the tenant.
	//
	// An ADDRESS, not a client, and that is the whole difference from every
	// entry above: nothing in this package ever calls pdp-mcp directly. The
	// `mcp` proxy is a subprocess that dials it for itself, from
	// STRATIUM_PEP_PDP_ADDR, so what those proofs need from here is the
	// string to hand it — the same thing cacheAddr is for, minus the
	// connection (nothing there ever stops or restarts pdp-mcp). runTestMain
	// still dials it once, to wait for SERVING, and drops the client.
	//
	// COUNTED AS DEDICATED SERVICES, which is deliberately not the ordinal
	// scheme the comments above use: those count the general-purpose `pdp`
	// as the first, so pdp-pap below calls itself "a ninth" while being the
	// seventh dedicated one. Both numbers are right about different things,
	// and enumerating the services by name here is what keeps this from
	// reading as a second, contradictory "ninth" eighteen lines away.
	mcpAddr   string
	mcpTenant string

	// papPdpClient and papTenant back Phase 14 Task 8's live admin-plane
	// proofs (pap_e2e_integration_test.go): a ninth, independently
	// configured PDP (deploy/docker/docker-compose.yml's pdp-pap service)
	// and its own tenant, for the same reason every dedicated PDP above has
	// one — stated most sharply in that compose service's own comment, since
	// these proofs do not merely read shared state, they CREATE policies,
	// revoke delegations, and write tier overrides, every one of which bumps
	// tenant_epoch under any test unlucky enough to share the tenant.
	papPdpClient pdpgrpc.PDPServiceClient
	papTenant    string

	// papAddr is the live stratium-pap process serving papTenant, and
	// papExtauthzAddr a SECOND stratium-pap process serving envoyTenant.
	// Two processes rather than one because N1 makes the tenant startup
	// configuration and forbids a request from carrying one — see that
	// compose service's own comment. Proof 4 (extauthz_integration_test.go)
	// is the only user of the second.
	papAddr         string
	papExtauthzAddr string

	// keycloakAddr is the real OIDC provider both PAP processes verify
	// against (deploy/docker/keycloak/stratium-realm.json). Reachable from
	// the host only so this suite can obtain real operator tokens the same
	// way the admin UI's browser does; the PAPs themselves reach it over the
	// compose network, at the issuer URL the realm pins.
	keycloakAddr string
)

func TestMain(m *testing.M) {
	os.Exit(runTestMain(m))
}

// runTestMain exists so deferred cleanup actually runs — os.Exit from
// TestMain itself would skip any defer in that function.
func runTestMain(m *testing.M) int {
	dbURL := os.Getenv("STRATIUM_IT_DATABASE_URL")
	servingDBURL := os.Getenv("STRATIUM_IT_SERVING_DATABASE_URL")
	papDBURL := os.Getenv("STRATIUM_IT_PAP_DATABASE_URL")
	pdpAddr := os.Getenv("STRATIUM_IT_PDP_ADDR")
	configuredTenant = os.Getenv("STRATIUM_IT_TENANT_ID")
	narrowPdpAddr := os.Getenv("STRATIUM_IT_PDP_NARROW_ADDR")
	narrowTenant = os.Getenv("STRATIUM_IT_NARROW_TENANT_ID")
	resourcePdpAddr := os.Getenv("STRATIUM_IT_PDP_RESOURCE_ADDR")
	resourceTenant = os.Getenv("STRATIUM_IT_RESOURCE_TENANT_ID")
	envoyPdpAddr := os.Getenv("STRATIUM_IT_PDP_EXTAUTHZ_ADDR")
	envoyTenant = os.Getenv("STRATIUM_IT_EXTAUTHZ_TENANT_ID")
	envoyAddr = os.Getenv("STRATIUM_IT_ENVOY_ADDR")
	pdpProxyAddr := os.Getenv("STRATIUM_IT_PDP_PROXY_ADDR")
	proxyTenant = os.Getenv("STRATIUM_IT_PROXY_TENANT_ID")
	grpcTargetAddr := os.Getenv("STRATIUM_IT_GRPC_TARGET_ADDR")
	pepProxyAddr := os.Getenv("STRATIUM_IT_PEP_PROXY_ADDR")
	epochPdpAddr := os.Getenv("STRATIUM_IT_PDP_EPOCH_ADDR")
	epochTenant = os.Getenv("STRATIUM_IT_EPOCH_TENANT_ID")
	pdpCacheAddr := os.Getenv("STRATIUM_IT_PDP_CACHE_ADDR")
	cacheTenant = os.Getenv("STRATIUM_IT_CACHE_TENANT_ID")
	mcpAddr = os.Getenv("STRATIUM_IT_PDP_MCP_ADDR")
	mcpTenant = os.Getenv("STRATIUM_IT_MCP_TENANT_ID")
	if dbURL == "" || servingDBURL == "" || papDBURL == "" || pdpAddr == "" || configuredTenant == "" || narrowPdpAddr == "" || narrowTenant == "" ||
		resourcePdpAddr == "" || resourceTenant == "" || envoyPdpAddr == "" || envoyTenant == "" || envoyAddr == "" ||
		pdpProxyAddr == "" || proxyTenant == "" || grpcTargetAddr == "" || pepProxyAddr == "" ||
		epochPdpAddr == "" || epochTenant == "" || pdpCacheAddr == "" || cacheTenant == "" ||
		mcpAddr == "" || mcpTenant == "" {
		fmt.Fprintln(os.Stderr,
			"STRATIUM_IT_DATABASE_URL, STRATIUM_IT_SERVING_DATABASE_URL, STRATIUM_IT_PAP_DATABASE_URL, "+
				"STRATIUM_IT_PDP_ADDR, STRATIUM_IT_TENANT_ID, "+
				"STRATIUM_IT_PDP_NARROW_ADDR, STRATIUM_IT_NARROW_TENANT_ID, STRATIUM_IT_PDP_RESOURCE_ADDR, "+
				"STRATIUM_IT_RESOURCE_TENANT_ID, STRATIUM_IT_PDP_EXTAUTHZ_ADDR, STRATIUM_IT_EXTAUTHZ_TENANT_ID, "+
				"STRATIUM_IT_ENVOY_ADDR, STRATIUM_IT_PDP_PROXY_ADDR, STRATIUM_IT_PROXY_TENANT_ID, STRATIUM_IT_GRPC_TARGET_ADDR, "+
				"STRATIUM_IT_PEP_PROXY_ADDR, STRATIUM_IT_PDP_EPOCH_ADDR, STRATIUM_IT_EPOCH_TENANT_ID, STRATIUM_IT_PDP_CACHE_ADDR, "+
				"STRATIUM_IT_CACHE_TENANT_ID, STRATIUM_IT_PDP_MCP_ADDR, "+
				"and STRATIUM_IT_MCP_TENANT_ID must all be set — run via `make integration`, not `go test` directly")
		return 1
	}
	// Phase 14 Task 8's own five, checked here rather than by lengthening the
	// condition above, which already spans four lines. Same all-at-once
	// contract, but name -> destination in one map rather than this being a
	// value list zipped by position against a name list declared in another
	// file (formerly papE2ERequiredEnv, pap_e2e_integration_test.go): that
	// coupling could silently drift -- the wrong name in the error, or an
	// index panic if the two lengths ever diverged -- without either file's
	// compiler catching it. One list, keyed by name, cannot name the wrong
	// variable.
	var papPdpAddr string
	papEnv := map[string]*string{
		"STRATIUM_IT_PDP_PAP_ADDR":      &papPdpAddr,
		"STRATIUM_IT_PAP_TENANT_ID":     &papTenant,
		"STRATIUM_IT_PAP_ADDR":          &papAddr,
		"STRATIUM_IT_PAP_EXTAUTHZ_ADDR": &papExtauthzAddr,
		"STRATIUM_IT_KEYCLOAK_ADDR":     &keycloakAddr,
	}
	var missingPAPEnv []string
	for name, dst := range papEnv {
		*dst = os.Getenv(name)
		if *dst == "" {
			missingPAPEnv = append(missingPAPEnv, name)
		}
	}
	if len(missingPAPEnv) > 0 {
		slices.Sort(missingPAPEnv) // map iteration order isn't; keep the message deterministic
		fmt.Fprintln(os.Stderr, papE2EEnvError(missingPAPEnv))
		return 1
	}

	tenants := map[string]bool{
		configuredTenant: true, narrowTenant: true, resourceTenant: true, secondTenantID: true, envoyTenant: true, proxyTenant: true,
		epochTenant: true, cacheTenant: true, papTenant: true, mcpTenant: true,
	}
	if len(tenants) != 10 {
		fmt.Fprintln(os.Stderr, "STRATIUM_IT_TENANT_ID, STRATIUM_IT_NARROW_TENANT_ID, STRATIUM_IT_RESOURCE_TENANT_ID, "+
			"STRATIUM_IT_EXTAUTHZ_TENANT_ID, STRATIUM_IT_PROXY_TENANT_ID, STRATIUM_IT_EPOCH_TENANT_ID, "+
			"STRATIUM_IT_CACHE_TENANT_ID, STRATIUM_IT_PAP_TENANT_ID, STRATIUM_IT_MCP_TENANT_ID, and the test's "+
			"hardcoded second tenant must all be distinct from one another")
		return 1
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open database: %v\n", err)
		return 1
	}
	defer func() { _ = db.Close() }()
	if err := waitForDB(ctx, db); err != nil {
		fmt.Fprintf(os.Stderr, "database never became reachable: %v\n", err)
		return 1
	}
	testDB = db

	sdb, err := sql.Open("postgres", servingDBURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open serving-role database: %v\n", err)
		return 1
	}
	defer func() { _ = sdb.Close() }()
	if err := waitForDB(ctx, sdb); err != nil {
		fmt.Fprintf(os.Stderr, "serving-role database connection never became reachable: %v\n", err)
		return 1
	}
	servingDB = sdb

	pdb, err := sql.Open("postgres", papDBURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open pap-role database: %v\n", err)
		return 1
	}
	defer func() { _ = pdb.Close() }()
	if err := waitForDB(ctx, pdb); err != nil {
		fmt.Fprintf(os.Stderr, "pap-role database connection never became reachable: %v\n", err)
		return 1
	}
	papDB = pdb

	client, closeConn, err := dialAndWaitForServing(ctx, pdpAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pdp: %v\n", err)
		return 1
	}
	defer closeConn()
	pdpClient = client

	narrowClient, closeNarrowConn, err := dialAndWaitForServing(ctx, narrowPdpAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pdp-narrow: %v\n", err)
		return 1
	}
	defer closeNarrowConn()
	narrowPdpClient = narrowClient

	resourceClient, closeResourceConn, err := dialAndWaitForServing(ctx, resourcePdpAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pdp-resource: %v\n", err)
		return 1
	}
	defer closeResourceConn()
	resourcePdpClient = resourceClient

	envoyClient, closeEnvoyPdpConn, err := dialAndWaitForServing(ctx, envoyPdpAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pdp-extauthz: %v\n", err)
		return 1
	}
	defer closeEnvoyPdpConn()
	envoyPdpClient = envoyClient

	// Envoy itself has no gRPC health service to poll (dialAndWaitForServing
	// is specific to the PDP's own grpc_health_v1 registration, which
	// stratium-pep extauthz deliberately does not have — Task 1's own
	// report, "no health-check service registered"; extauthz.go's package
	// doc explains why adding one was left alone for this task too). An
	// ordinary HTTP request Envoy can only answer once its own listener,
	// its ext_authz cluster to pep-extauthz, and pep-extauthz's own gRPC
	// listener are all up is the readiness signal instead.
	if err := waitForEnvoy(ctx, envoyAddr); err != nil {
		fmt.Fprintf(os.Stderr, "envoy: %v\n", err)
		return 1
	}

	proxyPdpConn, closeProxyPdpConn, err := dialAndWaitForServing(ctx, pdpProxyAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pdp-proxy: %v\n", err)
		return 1
	}
	defer closeProxyPdpConn()
	proxyPdpClient = proxyPdpConn

	// grpc-target has no gRPC health service of its own (a deliberate
	// omission matching pep-proxy's own, below, and pep-extauthz's before
	// either -- Task 1's own report on that surface, "no health-check
	// service registered") -- a real, answered RPC (CallCount) is the
	// readiness signal instead, the same choice waitForEnvoy already makes
	// for the analogous HTTP case.
	grpcTargetConn, err := dialPlain(grpcTargetAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "grpc-target: %v\n", err)
		return 1
	}
	defer func() { _ = grpcTargetConn.Close() }()
	directTargetClient = grpctarget.NewTargetServiceClient(grpcTargetConn)
	if err := waitForGRPCTarget(ctx, directTargetClient); err != nil {
		fmt.Fprintf(os.Stderr, "grpc-target: %v\n", err)
		return 1
	}

	// pep-proxy has no gRPC health service either (proxy.go's own design --
	// a transparent proxy registers no services of its own, "PASSTHROUGH
	// CODEC" section) -- an unauthenticated call always denies by
	// construction (K4, no fallback) once pep-proxy and pdp-proxy are both
	// up, which doubles as a first, cheap witness that the no-token deny
	// path proof 3 later asserts in detail is already wired end to end --
	// the identical reasoning waitForEnvoy already establishes for the
	// analogous HTTP case.
	pepProxyConn, err := dialPlain(pepProxyAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pep-proxy: %v\n", err)
		return 1
	}
	defer func() { _ = pepProxyConn.Close() }()
	proxyTargetClient = grpctarget.NewTargetServiceClient(pepProxyConn)
	if err := waitForProxyReady(ctx, proxyTargetClient); err != nil {
		fmt.Fprintf(os.Stderr, "pep-proxy: %v\n", err)
		return 1
	}

	epochClient, closeEpochConn, err := dialAndWaitForServing(ctx, epochPdpAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pdp-epoch: %v\n", err)
		return 1
	}
	defer closeEpochConn()
	epochPdpClient = epochClient

	// Dialed by hand rather than dialAndWaitForServing (used by every other
	// PDP instance above): this is the one instance whose raw connection a
	// later test needs directly (see the package var's own doc comment), and
	// dialAndWaitForServing only ever hands back a wrapped PDPServiceClient.
	cacheGRPCConn, err := grpc.NewClient(pdpCacheAddr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "pdp-cache: create gRPC client: %v\n", err)
		return 1
	}
	defer func() { _ = cacheGRPCConn.Close() }()
	waited, err := waitForServing(ctx, cacheGRPCConn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pdp-cache never reported SERVING: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stdout, "%s reported SERVING after %s (this is the measured wait, not an assumption)\n", pdpCacheAddr, waited)
	cacheConn = cacheGRPCConn
	cacheAddr = pdpCacheAddr

	// Dialed only to WAIT, and the client is dropped on the floor: nothing in
	// this package ever calls pdp-mcp directly (see mcpAddr's own doc comment
	// -- the `mcp` proxy subprocess dials it for itself). Waiting still has to
	// happen here, before any test runs: `compose up --wait` returns when the
	// container is RUNNING, which is before migrations.Up() and net.Listen
	// have finished, and a proof whose FIRST act is exec'ing a subprocess
	// against an address nothing is listening on yet would fail as an
	// unreachable-PDP denial -- indistinguishable, from the test's side, from
	// the surface genuinely failing closed.
	_, closeMCPConn, err := dialAndWaitForServing(ctx, mcpAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pdp-mcp: %v\n", err)
		return 1
	}
	defer closeMCPConn()

	papClient, closePAPConn, err := dialAndWaitForServing(ctx, papPdpAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "pdp-pap: %v\n", err)
		return 1
	}
	defer closePAPConn()
	papPdpClient = papClient

	// Both PAPs are waited for explicitly, and they are the only services in
	// this stack that need it in Go rather than in compose. Every PDP is
	// gated by waitForServing above; postgres and keycloak have compose
	// healthchecks. The PAP containers have neither -- distroless images
	// carry no shell, so a compose healthcheck cannot be expressed for them
	// -- so `compose up --wait` returns as soon as the container is RUNNING,
	// which is before cmd/stratium-pap's run() has finished OIDC discovery
	// against keycloak and reached ListenAndServe. The PDP polls above give
	// incidental slack, which is why this never bit; that is luck, not a
	// gate, and this is the phase's capstone proof to have it flake in.
	for _, addr := range []string{papAddr, papExtauthzAddr} {
		waited, err := waitForPAP(ctx, addr)
		if err != nil {
			fmt.Fprintf(os.Stderr, "stratium-pap at %s never became ready: %v\n", addr, err)
			return 1
		}
		fmt.Fprintf(os.Stdout, "stratium-pap at %s answered after %s (this is the measured wait, not an assumption)\n",
			addr, waited)
	}

	return m.Run()
}

// dialAndWaitForServing dials addr and blocks until its health service
// reports SERVING (waitForServing), returning a ready-to-use client and a
// closer for the underlying connection — the closer is returned rather than
// deferred here so runTestMain can keep closing both connections only after
// m.Run() completes, exactly as it did before this was factored out.
// Factored out so dialing the second, pdp-narrow service (Phase 4a Task 5)
// is one call instead of a second copy of the same dial-wait-log sequence.
func dialAndWaitForServing(ctx context.Context, addr string) (pdpgrpc.PDPServiceClient, func(), error) {
	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, nil, fmt.Errorf("create gRPC client for %s: %w", addr, err)
	}
	waited, err := waitForServing(ctx, conn)
	if err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("%s never reported SERVING: %w", addr, err)
	}
	fmt.Fprintf(os.Stdout, "%s reported SERVING after %s (this is the measured wait, not an assumption)\n", addr, waited)
	return pdpgrpc.NewPDPServiceClient(conn), func() { _ = conn.Close() }, nil
}

// waitForPAP polls a stratium-pap process until it answers HTTP at all, and
// reports how long that took — the http.Server analogue of waitForServing
// below, for the two services in this stack that can have no readiness gate
// anywhere else (see runTestMain's own comment on why: a distroless image
// has no shell for a compose healthcheck to run in).
//
// An UNAUTHENTICATED request, and any status at all counts as ready. The
// question here is exactly "is ListenAndServe accepting connections yet",
// not "does this process work" — every proof in this package answers the
// second question for itself, loudly, and a readiness probe that also
// asserted behavior would just be a worse copy of them. Sending no
// credential also keeps this from needing a token before keycloak is
// necessarily reachable, which would make the probe depend on a second
// service being up to answer a question about the first.
func waitForPAP(ctx context.Context, addr string) (time.Duration, error) {
	start := time.Now()
	var lastErr error
	for {
		select {
		case <-ctx.Done():
			return 0, fmt.Errorf("last error: %w: %w", lastErr, ctx.Err())
		default:
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+addr+"/v1/policies", nil)
		if err != nil {
			return 0, fmt.Errorf("build readiness request for %s: %w", addr, err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			return time.Since(start), nil
		}
		lastErr = err
		time.Sleep(250 * time.Millisecond)
	}
}

// waitForDB retries PingContext instead of assuming the first attempt
// succeeds: compose's own healthcheck already gates postgres, so this
// exists for robustness against slow CI runners rather than to paper over
// a real race between compose and this test binary starting.
func waitForDB(ctx context.Context, db *sql.DB) error {
	var lastErr error
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("last error: %w: %w", lastErr, ctx.Err())
		default:
		}
		if lastErr = db.PingContext(ctx); lastErr == nil {
			return nil
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// waitForServing polls the PDP's health service (registered in main.go
// alongside PDPService) until it reports SERVING, and reports how long that
// took — this is the Go-side half of "does the PDP wait correctly for the
// database or race it": migrations.Up() and net.Listen both happen before
// main.go ever marks health SERVING, so a fast, single-digit-second wait
// here is a real signal, not a guess.
func waitForServing(ctx context.Context, conn *grpc.ClientConn) (time.Duration, error) {
	start := time.Now()
	health := grpc_health_v1.NewHealthClient(conn)
	var lastErr error
	for {
		select {
		case <-ctx.Done():
			return 0, fmt.Errorf("last error: %w: %w", lastErr, ctx.Err())
		default:
		}
		resp, err := health.Check(ctx, &grpc_health_v1.HealthCheckRequest{})
		if err == nil && resp.GetStatus() == grpc_health_v1.HealthCheckResponse_SERVING {
			return time.Since(start), nil
		}
		lastErr = err
		time.Sleep(250 * time.Millisecond)
	}
}

// waitForEnvoy polls addr with a deliberately credential-free GET until it
// gets back an ordinary HTTP response (any status code) rather than a
// connection error — proof that a real TCP round trip through Envoy, its
// ext_authz call to pep-extauthz, and pep-extauthz's own answer all
// completed, not just that Envoy's listener accepted a connection. A
// request with no authorization header always denies (extractBearerToken,
// extauthz.go — K4, no fallback), so this doubles as a first, cheap witness
// that the deny path this test suite's own proof 3 later asserts in detail
// is already wired end to end before any fixture is seeded.
func waitForEnvoy(ctx context.Context, addr string) error {
	url := "http://" + addr + "/waiting-for-envoy"
	client := &http.Client{Timeout: 2 * time.Second}
	var lastErr error
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("last error: %w: %w", lastErr, ctx.Err())
		default:
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return fmt.Errorf("build readiness request: %w", err)
		}
		resp, err := client.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			return nil
		}
		lastErr = err
		time.Sleep(250 * time.Millisecond)
	}
}

// dialPlain dials addr the same insecure, lazy way dialAndWaitForServing
// (above) does, but returns the bare connection instead of a
// pdpgrpc-typed client: grpc-target and pep-proxy both speak
// grpctarget.TargetServiceClient, not pdpgrpc.PDPServiceClient, so the
// caller builds its own typed client from the connection this returns.
func dialPlain(addr string) (*grpc.ClientConn, error) {
	return grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
}

// waitForGRPCTarget polls grpc-target's own CallCount RPC directly (no
// authorization concept exists at that layer, and this call bypasses
// stratium-pep proxy entirely) until it succeeds -- see this function's
// own call site in runTestMain for why a real RPC, not a health service,
// is the readiness signal here.
func waitForGRPCTarget(ctx context.Context, client grpctarget.TargetServiceClient) error {
	var lastErr error
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("last error: %w: %w", lastErr, ctx.Err())
		default:
		}
		callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		_, err := client.CallCount(callCtx, &grpctarget.CallCountRequest{})
		cancel()
		if err == nil {
			return nil
		}
		lastErr = err
		time.Sleep(250 * time.Millisecond)
	}
}

// waitForProxyReady polls pep-proxy's own listener with an
// unauthenticated Fetch call until it returns ANY real gRPC response
// (in practice codes.PermissionDenied, per K4 -- no token, no fallback)
// rather than a transport-level connection failure -- see this
// function's own call site in runTestMain for why that, and not a health
// service, is the readiness signal here.
func waitForProxyReady(ctx context.Context, client grpctarget.TargetServiceClient) error {
	var lastErr error
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("last error: %w: %w", lastErr, ctx.Err())
		default:
		}
		callCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		_, err := client.Fetch(callCtx, &grpctarget.EchoRequest{Message: "readiness-probe"})
		cancel()
		if err != nil && status.Code(err) != codes.Unavailable {
			return nil
		}
		lastErr = err
		time.Sleep(250 * time.Millisecond)
	}
}

// withTenantTx runs fn inside a transaction with app.tenant_id set for that
// transaction only — the same pattern internal/store.beginTenantTx uses,
// reproduced here because that helper is unexported and this is a
// deliberately external test package (see the package doc). Seeding through
// this, rather than a superuser bypass, means every fixture this test
// writes is itself proof that RLS's WITH CHECK accepts a correctly tenant-
// scoped writer — not just that it rejects a mismatched one.
func withTenantTx(t *testing.T, tenant string, fn func(tx *sql.Tx)) {
	t.Helper()
	tx, err := testDB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(t.Context(), `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
		t.Fatalf("set_config app.tenant_id: %v", err)
	}
	fn(tx)
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
}

const insertAgentQuery = `INSERT INTO agents (id, tenant_id, name, provider, model_id, trust_tier, enabled, suspended, allowed_tools, classification_caps)
	VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`

// seedAgent inserts one enabled, unsuspended agent row. trustTier is an
// explicit parameter, not a hardcoded default, because Phase 2c Task 5's
// ceiling proof (proof9) needs an agent trusted enough for a DESTRUCTIVE
// action (PLATFORM_TRUSTED — see authz.DefaultTrustTable) so its agent leg
// legitimately allows; every earlier caller passes TrustTierUnverified,
// preserving exactly the value this function used to hardcode.
//
// classification_caps is hardcoded to '{}' (no caps, matching CreateAgent's
// own "every created agent starts capless" default) rather than a parameter:
// migrations/000020_agent_classification_caps added the column NOT NULL with
// no default, so this INSERT stopped compiling against a live schema the
// moment that migration landed -- every existing caller here already assumed
// a capless agent (the column did not exist yet), so this is the value that
// preserves their behaviour exactly, not a new decision.
func seedAgent(t *testing.T, tenant string, id uuid.UUID, name string, trustTier models.AgentTrustTier) {
	t.Helper()
	withTenantTx(t, tenant, func(tx *sql.Tx) {
		if _, err := tx.ExecContext(t.Context(), insertAgentQuery,
			id.String(), tenant, name, "anthropic", "claude", int64(trustTier), true, false, []byte(`[]`), []byte(`{}`),
		); err != nil {
			t.Fatalf("seed agent %s: %v", name, err)
		}
	})
}

const insertDelegationQuery = `INSERT INTO delegations (
		id, tenant_id, user_id, agent_id, approved_tools, max_action_tier,
		classification_caps, resource_constraints, purpose, expires_at,
		revoked, parent_delegation_id, root_delegation_id, depth, chain_agent_ids, escalate_at
	) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`

// seedDelegation inserts d as one delegations row and returns d unchanged,
// so callers can seed and keep the same *models.Delegation for later
// in-process use (proof 5 below reuses it directly against
// authz.ValidateChain — no read-back required, since a successful INSERT
// under RLS's WITH CHECK already proves the row persisted exactly as this
// struct describes it).
//
// escalate_at is appended at the end, mirroring internal/store/delegation.go's
// own insertDelegationQuery (production's CreateDelegation) both in
// position and in passing d.EscalateAt — a *models.ActionTier — directly:
// database/sql's default parameter converter maps a nil pointer to SQL
// NULL and a non-nil one to its pointee's value, so every pre-Phase-5-Task-5
// caller of this function (which never sets EscalateAt) round-trips exactly
// the NULL it always got before this column existed in this INSERT list —
// this is a behavior-preserving addition, not a new requirement on any
// existing fixture. Phase 5 Task 5's own escalation proofs
// (escalation_integration_test.go) are the first callers that need this
// column to actually persist: found live, the column was silently absent
// from this test-only raw INSERT (unlike production's own, which has always
// included it since Task 1) because nothing before Task 5 needed a seeded
// delegation to carry a real threshold.
func seedDelegation(t *testing.T, d *models.Delegation) *models.Delegation {
	t.Helper()
	approvedTools, err := json.Marshal(d.ApprovedTools)
	if err != nil {
		t.Fatalf("marshal approved_tools: %v", err)
	}
	caps, err := json.Marshal(d.ClassificationCaps)
	if err != nil {
		t.Fatalf("marshal classification_caps: %v", err)
	}
	constraints, err := json.Marshal(d.ResourceConstraints)
	if err != nil {
		t.Fatalf("marshal resource_constraints: %v", err)
	}
	chainAgentIDs, err := json.Marshal(d.ChainAgentIDs)
	if err != nil {
		t.Fatalf("marshal chain_agent_ids: %v", err)
	}

	var parent interface{}
	if d.ParentDelegationID != nil {
		parent = d.ParentDelegationID.String()
	}

	withTenantTx(t, d.TenantID, func(tx *sql.Tx) {
		if _, err := tx.ExecContext(t.Context(), insertDelegationQuery,
			d.ID.String(), d.TenantID, d.UserID, d.AgentID.String(), approvedTools, int64(d.MaxActionTier),
			caps, constraints, d.Purpose, d.ExpiresAt,
			d.Revoked, parent, d.RootDelegationID.String(), int64(d.Depth), chainAgentIDs, d.EscalateAt,
		); err != nil {
			t.Fatalf("seed delegation %s: %v", d.ID, err)
		}
	})
	return d
}

// mintToken calls the real IssueToken RPC through client to obtain a
// genuinely signed token naming delegationID — the only legitimate way any
// proof in this file can produce a token the containerized PDP's own Verify
// will accept. Its signing key is generated fresh at image build time
// (deploy/docker/docker-compose.yml's own comment on
// STRATIUM_TOKEN_SIGNING_KEY_PATH) and never reaches this test process, so
// there is no way to sign one locally — this is Phase 9 Task 4's own
// production re-issuance path (cmd/stratium-pep/reissue.go), exercised here
// for the same delegations seedDelegation/twoHopChain/singleHopDelegation
// already build directly against Postgres, which — unlike a delegation
// CreateDelegation itself minted — have no token of their own to reuse.
// ttlSeconds mirrors reissue.go's own reissueTTLSeconds: deliberately larger
// than any fixture delegation's remaining lifetime, so IssueToken's own
// clamp (internal/pdpgrpc/token.go's clampTokenExpiry) is always what
// actually decides the token's expiry, not a duration this helper guessed.
func mintToken(t *testing.T, client pdpgrpc.PDPServiceClient, delegationID uuid.UUID) string {
	t.Helper()
	const ttlSeconds = 10 * 365 * 24 * 60 * 60 // 10 years; always clamped down to the delegation's own remaining life
	resp, err := client.IssueToken(t.Context(), &pdpgrpc.IssueTokenRequest{
		DelegationId: delegationID.String(),
		TtlSeconds:   ttlSeconds,
	})
	if err != nil {
		t.Fatalf("mint token for delegation %s: %v", delegationID, err)
	}
	return resp.GetToken()
}

// twoHopChain builds a root delegation and one child narrowing it one level
// deeper — the "two-hop delegation chain" the brief asks for — both issued
// to the same agent, and seeds both. Every leg but the principal leg is
// deliberately well-formed (matches internal/pdpgrpc's wellFormedFixture):
// enabled agent, active and sufficiently-tiered delegations, so the DENY
// this test asserts is unambiguously attributable to the principal leg
// alone, not to some other leg that happened to deny first.
func twoHopChain(t *testing.T, tenant string, agentID uuid.UUID) (root, child *models.Delegation) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	rootID, childID := uuid.New(), uuid.New()

	root = seedDelegation(t, &models.Delegation{
		ID: rootID, TenantID: tenant, UserID: "integration-test-user", AgentID: agentID,
		ApprovedTools: []string{}, MaxActionTier: models.ActionTierInternalModify,
		ClassificationCaps: map[string]string{}, ResourceConstraints: map[string]string{},
		Purpose: "integration test: root grant", ExpiresAt: now.Add(time.Hour),
		RootDelegationID: rootID, Depth: 0, ChainAgentIDs: []uuid.UUID{agentID},
	})
	child = seedDelegation(t, &models.Delegation{
		ID: childID, TenantID: tenant, UserID: "integration-test-user", AgentID: agentID,
		ApprovedTools: []string{}, MaxActionTier: models.ActionTierInternalModify,
		ClassificationCaps: map[string]string{}, ResourceConstraints: map[string]string{},
		Purpose: "integration test: re-delegated one hop deeper", ExpiresAt: now.Add(time.Hour),
		ParentDelegationID: &rootID, RootDelegationID: rootID, Depth: 1, ChainAgentIDs: []uuid.UUID{agentID, agentID},
	})
	return root, child
}

// singleHopDelegation seeds one root delegation (depth 0), well-formed on
// every dimension except MaxActionTier — the caller's choice — so it can
// stand in either as an unrestricted grant or, for
// proof9_cedar_permit_cannot_exceed_delegation_ceiling, deliberately as a
// low one. A single root is the simplest chain authz.ValidateChain accepts
// (the same shape wellFormedFixture uses at the unit level, in
// pdpgrpc/server_test.go); none of the Phase 2c Task 5 proofs below are
// testing chain depth, so twoHopChain's second hop would only add fixture
// noise.
func singleHopDelegation(t *testing.T, tenant string, agentID uuid.UUID, maxTier models.ActionTier, purpose string) *models.Delegation {
	t.Helper()
	id := uuid.New()
	now := time.Now().UTC().Truncate(time.Second)
	return seedDelegation(t, &models.Delegation{
		ID: id, TenantID: tenant, UserID: "integration-test-user", AgentID: agentID,
		ApprovedTools: []string{}, MaxActionTier: maxTier,
		ClassificationCaps: map[string]string{}, ResourceConstraints: map[string]string{},
		Purpose: purpose, ExpiresAt: now.Add(time.Hour),
		RootDelegationID: id, Depth: 0, ChainAgentIDs: []uuid.UUID{agentID},
	})
}

const insertPolicyQuery = `INSERT INTO policies (id, tenant_id, name, language, policy_content, effect, enabled, priority)
	VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`

// seedPolicyPriority is the non-zero priority every seeded policy carries.
// It exists so LoadAllPolicies' priority round-trip is proven against a real
// column rather than against sqlmock — the field sat declared-but-unpopulated
// for two phases precisely because no test touched real Postgres for it.
const seedPolicyPriority = 42

// seedPolicy inserts one enabled Cedar policy row for tenant and returns its
// id — client-generated, like seedAgent/seedDelegation's ids above, so a
// caller can assert a response's decided_policy_id against a known value
// without a read-back. effect is 'allow'|'deny' metadata satisfying the
// policies table's CHECK constraint only: Cedar's own engine derives the
// actual verdict effect by parsing text's permit/forbid keyword, not by
// reading this column back (see cedar.Engine.Prepare's doc comment) — it is
// set consistent with text here purely so a future reader isn't misled by a
// mismatched pair.
//
// A thin wrapper around seedPolicyLang (below), fixed to "cedar" — every
// call site that predates Task 6 is Cedar-only, and stays that way
// unchanged; seedPolicyLang exists for the multi-language proofs Task 6
// adds, without touching this signature or any of its ~20 existing callers.
func seedPolicy(t *testing.T, tenant, name, text, effect string) string {
	t.Helper()
	return seedPolicyLang(t, tenant, name, "cedar", text, effect)
}

// seedPolicyLang is seedPolicy's general form: same contract, with the
// language column an explicit parameter instead of a hardcoded "cedar", for
// Task 6's multi-language end-to-end proofs (TestIntegration_Decide_*,
// TestIntegration_Multi_*, TestIntegration_CreateDelegation_*, below).
func seedPolicyLang(t *testing.T, tenant, name, lang, text, effect string) string {
	t.Helper()
	id := uuid.New().String()
	withTenantTx(t, tenant, func(tx *sql.Tx) {
		if _, err := tx.ExecContext(t.Context(), insertPolicyQuery,
			id, tenant, name, lang, text, effect, true, seedPolicyPriority,
		); err != nil {
			t.Fatalf("seed policy %s (%s): %v", name, lang, err)
		}
	})
	return id
}

// LoadAllPolicies against real Postgres. Every other LoadAllPolicies test
// uses sqlmock, which returns whatever columns the test names — so it can
// prove the scan order matches the query string, and nothing at all about
// whether those columns exist, whether the serving role may read them, or
// what the database stores. StoredPolicy.Priority spent two phases declared,
// carried into PolicyVerdict, and hashed into audit provenance while no
// column existed to load it from, and no sqlmock test could have noticed.
// This one would have: it fails on a missing column, a missing grant, and a
// wrong scan order alike.
//
// Renamed from TestIntegration_LoadPolicies_RoundTripsPriority (Phase 4a
// Task 4): it exercised store.LoadPolicies, deleted alongside policy.
// Configured once policy.Multi's LoadAllPolicies-based path subsumed both —
// see policy.go's own package doc. The property this test proves —
// real-Postgres round-trip of Priority, and that Text does not land in the
// wrong scan target — is unchanged by which loader it runs through, so it
// was re-pointed at LoadAllPolicies rather than deleted with LoadPolicies.
func TestIntegration_LoadAllPolicies_RoundTripsPriority(t *testing.T) {
	// Its own tenant, like boundaryTenant below. The suite shares one database,
	// and TestEndToEnd/proof2 asserts configuredTenant has *no* cedar policies
	// in order to prove the unconfigured-principal denial — seeding a permit
	// policy there turned that denial into an allow and broke four later
	// proofs. RLS makes an isolated tenant a complete fix rather than a
	// cleanup-ordering bet.
	const priorityTenant = "tenant-policy-priority-integration"
	const text = "permit(principal, action, resource);"
	id := seedPolicy(t, priorityTenant, "priority-round-trip", text, "allow")

	got, err := store.New(testDB, priorityTenant).LoadAllPolicies(t.Context())
	if err != nil {
		t.Fatalf("LoadAllPolicies() error = %v", err)
	}

	var found *policy.StoredPolicy
	for i := range got {
		if got[i].ID == id {
			found = &got[i]
			break
		}
	}
	if found == nil {
		t.Fatalf("LoadAllPolicies() did not return seeded policy %s (got %d policies)", id, len(got))
	}
	if found.Priority != seedPolicyPriority {
		t.Errorf("Priority = %d, want %d — the column exists but the value did not survive the load",
			found.Priority, seedPolicyPriority)
	}
	if found.Text != text {
		t.Errorf("Text = %q, want %q — adjacent scan targets are transposed", found.Text, text)
	}
}

// sqlStatePermissionDenied and sqlStateCheckViolation are the two Postgres
// SQLSTATEs Task 2's approvals proofs below distinguish from "any error at
// all" — the same discipline store.sqlStateUniqueViolation applies in
// audit.go, reproduced here rather than imported (both are unexported, and
// this is a deliberately external test package — see this file's own doc
// comment on why).
const (
	sqlStatePermissionDenied = "42501" // insufficient_privilege
	sqlStateCheckViolation   = "23514" // check_violation
)

// insertApprovalRawQuery is store's own (unexported) insertApprovalQuery
// reproduced here with one difference: status is an explicit, caller-chosen
// column rather than left to the schema's DEFAULT 'pending'.
// internal/store.CreateApproval deliberately never accepts a caller-supplied
// status at all (see that function's own doc comment) — precisely because
// E7 gives it no legitimate reason to write anything but 'pending' — so
// there is no Go-side call this test could make to reach an invalid status
// value. Only a raw INSERT naming one directly, bypassing CreateApproval
// entirely, can put the CHECK constraint (migrations/000012_approvals) to
// the test.
const insertApprovalRawQuery = `INSERT INTO approvals (
	id, tenant_id, agent_id, delegation_id, root_delegation_id,
	subject, root_principal, tool_name, action, derived_tier,
	input_digest, status, expires_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`

// TestIntegration_Approvals_StatusCheckConstraintRejectsInvalidValue proves
// approvals.status is a closed vocabulary enforced by the database, not by
// Go — the property migrations/000012_approvals' own comment states and
// this project's house style requires backing with a real assertion rather
// than a claim. Its own tenant, for the reason
// TestIntegration_LoadAllPolicies_RoundTripsPriority's own comment gives.
//
// Uses testDB (not servingDB): a CHECK constraint applies to every role
// alike, ownership included, unlike a GRANT — this test is not about who is
// permitted to write, only about what value is accepted once they do. The
// transaction is deliberately never committed, only ever rolled back
// (unconditionally, via defer): the INSERT is expected to fail, and
// Postgres aborts the whole transaction on a constraint violation, so
// attempting a COMMIT afterward would only add an unrelated, undefined
// second failure mode to reason about.
func TestIntegration_Approvals_StatusCheckConstraintRejectsInvalidValue(t *testing.T) {
	const tenant = "tenant-approvals-status-check-integration"

	agentID := uuid.New()
	seedAgent(t, tenant, agentID, "status-check-agent", models.TrustTierUnverified)
	delegation := singleHopDelegation(t, tenant, agentID, models.ActionTierExternalComms, "status check proof")
	digest := sha256.Sum256([]byte("status check proof"))

	tx, err := testDB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(t.Context(), `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
		t.Fatalf("set_config app.tenant_id: %v", err)
	}

	_, insertErr := tx.ExecContext(t.Context(), insertApprovalRawQuery,
		uuid.New().String(), tenant, agentID.String(), delegation.ID.String(), delegation.ID.String(),
		"subject", "root-principal", "Bash", "execute", int64(models.ActionTierExternalComms),
		digest[:], "not-a-real-status", time.Now().Add(time.Hour),
	)
	if insertErr == nil {
		t.Fatal("INSERT with status = 'not-a-real-status' succeeded, want a check_violation — " +
			"the CHECK constraint in migrations/000012_approvals must reject it")
	}
	var pqErr *pq.Error
	if !errors.As(insertErr, &pqErr) || pqErr.Code != sqlStateCheckViolation {
		t.Fatalf("INSERT error = %v, want SQLSTATE %s (check_violation)", insertErr, sqlStateCheckViolation)
	}
	t.Logf("INSERT with an invalid status correctly rejected: %v", insertErr)
}

// TestIntegration_Approvals_ServingRoleCannotUpdate is Task 2's E7 proof:
// the serving role can create and read approvals rows (SELECT, INSERT —
// migrations/000012_approvals) but genuinely cannot UPDATE one. sqlmock has
// no grants to violate (internal/store/approval_test.go proves the Go
// call shape, nothing about privilege), so only a real Postgres, connected
// as the real serving identity, can prove this — see servingDB's own doc
// comment for why testDB specifically cannot stand in for it here.
//
// Its own tenant, for the reason TestIntegration_LoadAllPolicies_
// RoundTripsPriority's own comment gives.
func TestIntegration_Approvals_ServingRoleCannotUpdate(t *testing.T) {
	const tenant = "tenant-approvals-grant-integration"

	agentID := uuid.New()
	seedAgent(t, tenant, agentID, "approvals-grant-agent", models.TrustTierUnverified)
	delegation := singleHopDelegation(t, tenant, agentID, models.ActionTierExternalComms, "approvals grant proof")

	approval := &models.Approval{
		ID: uuid.New(), AgentID: agentID, DelegationID: delegation.ID, RootDelegationID: delegation.ID,
		Subject: "integration-test-subject", RootPrincipal: "integration-test-root-principal",
		ToolName: "Bash", Action: "execute", DerivedTier: models.ActionTierExternalComms,
		InputDigest: sha256.Sum256([]byte("approvals grant proof")),
		ExpiresAt:   time.Now().Add(time.Hour),
	}
	// Created through servingDB, not testDB: this doubles as proof the
	// serving role's own SELECT/INSERT grants are sufficient for
	// CreateApproval to work at all. Without this, a role that could not
	// even create the row would make the UPDATE probe below meaningless —
	// its failure indistinguishable from "nothing works for this role."
	if err := store.New(servingDB, tenant).CreateApproval(t.Context(), approval); err != nil {
		t.Fatalf("CreateApproval() via the serving role error = %v, want nil — "+
			"SELECT/INSERT must work before UPDATE's absence means anything", err)
	}

	// The UPDATE probe itself: same serving connection, same tenant, raw SQL
	// rather than a Go store method — there is no CreateApproval-style
	// wrapper for UPDATE because E7 says none should ever exist. Scoped by
	// RLS via app.tenant_id, not a WHERE tenant_id clause, matching every
	// other query in this file. Never committed, only ever rolled back: the
	// UPDATE is expected to fail outright (a permission error, not merely a
	// zero-row match), so there is nothing this transaction should persist.
	tx, err := servingDB.BeginTx(t.Context(), nil)
	if err != nil {
		t.Fatalf("begin tx on serving connection: %v", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(t.Context(), `SELECT set_config('app.tenant_id', $1, true)`, tenant); err != nil {
		t.Fatalf("set_config app.tenant_id on serving connection: %v", err)
	}

	_, updateErr := tx.ExecContext(t.Context(),
		`UPDATE approvals SET status = 'approved', approved_by = $1, approved_at = NOW() WHERE id = $2`,
		"integration-test-root-principal", approval.ID.String())
	if updateErr == nil {
		t.Fatal("UPDATE approvals as the serving role succeeded, want a permission error — " +
			"E7 requires this grant to be absent (migrations/000012_approvals)")
	}
	var pqErr *pq.Error
	if !errors.As(updateErr, &pqErr) || pqErr.Code != sqlStatePermissionDenied {
		t.Fatalf("UPDATE error = %v, want SQLSTATE %s (insufficient_privilege)", updateErr, sqlStatePermissionDenied)
	}
	t.Logf("UPDATE approvals as the serving role correctly failed: %v", updateErr)

	// Belt-and-suspenders on top of the permission error itself: confirm via
	// testDB (unaffected by the grant) that the row genuinely never changed.
	got, err := store.New(testDB, tenant).LoadApproval(t.Context(), approval.ID)
	if err != nil {
		t.Fatalf("LoadApproval() after the failed UPDATE error = %v", err)
	}
	if got.Status != "pending" || got.ApprovedBy != nil {
		t.Errorf("approval after a rejected UPDATE = %+v, want unchanged (status=pending, approved_by=nil)", got)
	}
}

const auditChainQuery = `SELECT prev_hash, tenant_id, occurred_at, event_type, actor,
	agent_id, delegation_id, root_delegation_id, chain_depth,
	tool_name, action, declared_tier, derived_tier,
	decision, denied_leg, denied_at_depth, reason, policy_source, policy_id, unevaluated_policy_ids, input_digest
	FROM audit_chain ORDER BY seq ASC`

// fetchAuditChain reads a tenant's entire chain from the first entry,
// ordered oldest first — audit.Verify's own precondition (see its doc
// comment) — scoped by RLS via app.tenant_id, not a WHERE clause, matching
// every other read in this slice.
//
// policy_source/policy_id decode through sql.NullString into Entry's plain
// string fields, mirroring store.scanAuditTail exactly: NULL and ""
// resolve to the same Go zero value. unevaluated_policy_ids scans straight
// into pq.Array(&e.UnevaluatedPolicyIDs), also mirroring scanAuditTail: NULL
// decodes to a nil []string (pq.StringArray's own Scan), which pkg/audit.
// Entry.Hash's list encoding treats identically to an explicit empty array.
// That is what makes audit.Verify's hash recomputation reproduce the same
// digest for a row written before migrations/000006 or 000010 as for one
// written after with explicitly empty provenance (see
// "chain_verifies_across_the_migration_boundary" below) — but it also means
// this function alone cannot tell "never populated" apart from "correctly
// empty." auditRowProvenance and auditRowUnevaluatedPolicyIDs, below, are
// the queries that keep NULL-ness visible for exactly that reason.
func fetchAuditChain(t *testing.T, tenant string) []audit.Entry {
	t.Helper()
	var entries []audit.Entry
	withTenantTx(t, tenant, func(tx *sql.Tx) {
		rows, err := tx.QueryContext(t.Context(), auditChainQuery)
		if err != nil {
			t.Fatalf("query audit_chain: %v", err)
		}
		defer func() { _ = rows.Close() }()

		for rows.Next() {
			var e audit.Entry
			var prevHash, inputDigest []byte
			var policySource, policyID sql.NullString
			if err := rows.Scan(
				&prevHash, &e.TenantID, &e.OccurredAt, &e.EventType, &e.Actor,
				&e.AgentID, &e.DelegationID, &e.RootDelegationID, &e.ChainDepth,
				&e.ToolName, &e.Action, &e.DeclaredTier, &e.DerivedTier,
				&e.Decision, &e.DeniedLeg, &e.DeniedAtDepth, &e.Reason,
				&policySource, &policyID, pq.Array(&e.UnevaluatedPolicyIDs), &inputDigest,
			); err != nil {
				t.Fatalf("scan audit_chain row: %v", err)
			}
			copy(e.PrevHash[:], prevHash)
			if policySource.Valid {
				e.PolicySource = policySource.String
			}
			if policyID.Valid {
				e.PolicyID = policyID.String
			}
			if inputDigest != nil {
				copy(e.InputDigest[:], inputDigest)
			}
			entries = append(entries, e)
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("iterate audit_chain rows: %v", err)
		}
	})
	return entries
}

// auditRowProvenance reads policy_source/policy_id for a tenant's single
// most recent audit_chain row straight into sql.NullString, deliberately
// bypassing audit.Entry — Entry models both as plain strings, so (as
// fetchAuditChain's doc comment above explains) a NULL column and a
// legitimately empty one are indistinguishable once decoded there. That
// collapse is correct for Hash(), but it would also hide the exact defect
// Task 3 found: a column that is silently always NULL looks, at the
// Entry layer, identical to one that is correctly empty. Only a read that
// keeps NULL-ness visible, like this one, can tell those two apart.
func auditRowProvenance(t *testing.T, tenant string) (source, policyID sql.NullString) {
	t.Helper()
	withTenantTx(t, tenant, func(tx *sql.Tx) {
		row := tx.QueryRowContext(t.Context(),
			`SELECT policy_source, policy_id FROM audit_chain ORDER BY seq DESC LIMIT 1`)
		if err := row.Scan(&source, &policyID); err != nil {
			t.Fatalf("query latest audit_chain row's provenance columns: %v", err)
		}
	})
	return source, policyID
}

// auditRowUnevaluatedPolicyIDs reads unevaluated_policy_ids for a tenant's
// single most recent audit_chain row — the purpose-built column
// migrations/000010_audit_unevaluated_policy_ids adds so an operator can ask
// WHERE 'some-id' = ANY(unevaluated_policy_ids) directly, without needing
// the affected policy's language to have won authz.FoldVerdicts' own
// tie-break first. See TestIntegration_Live_OrphanLanguageDeniesNamingIt,
// the reason this helper exists: it is the one live proof that this column
// is populated even when a DIFFERENT verdict (a Cedar deny) decides the
// outcome.
func auditRowUnevaluatedPolicyIDs(t *testing.T, tenant string) []string {
	t.Helper()
	var ids []string
	withTenantTx(t, tenant, func(tx *sql.Tx) {
		row := tx.QueryRowContext(t.Context(),
			`SELECT unevaluated_policy_ids FROM audit_chain ORDER BY seq DESC LIMIT 1`)
		if err := row.Scan(pq.Array(&ids)); err != nil {
			t.Fatalf("query latest audit_chain row's unevaluated_policy_ids column: %v", err)
		}
	})
	return ids
}

const loadDelegationForAssertionQuery = `SELECT max_action_tier, approved_tools, depth, root_delegation_id ` +
	`FROM delegations WHERE id = $1`

// fetchDelegationRow reads back exactly the four columns Task 5's brief
// singles out for the persisted-matches-response comparison: max_action_tier,
// approved_tools, depth, root_delegation_id. Scoped by RLS via app.tenant_id
// (withTenantTx), not a WHERE tenant_id clause, matching every other read in
// this file — proof11 below is what turns a successful read here into
// evidence RLS's WITH CHECK accepted CreateDelegation's own write as
// correctly tenant-scoped, the same reasoning seedDelegation's doc comment
// gives for not re-reading its own inserts.
func fetchDelegationRow(t *testing.T, tenant string, id uuid.UUID) (maxActionTier int64, approvedTools []string, depth int64, rootDelegationID uuid.UUID) {
	t.Helper()
	withTenantTx(t, tenant, func(tx *sql.Tx) {
		var toolsRaw []byte
		if err := tx.QueryRowContext(t.Context(), loadDelegationForAssertionQuery, id.String()).
			Scan(&maxActionTier, &toolsRaw, &depth, &rootDelegationID); err != nil {
			t.Fatalf("query delegation %s: %v", id, err)
		}
		if err := json.Unmarshal(toolsRaw, &approvedTools); err != nil {
			t.Fatalf("decode delegation %s approved_tools: %v", id, err)
		}
	})
	return
}

// findRemoval returns the ScopeRemoval in removed matching dimension/value,
// or nil. Reproduced here rather than imported: internal/pdpgrpc's own
// findRemoval (delegation_test.go) is unexported and operates on the same
// package's unqualified *ScopeRemoval — this file is an external test
// package (store_test) and sees the qualified *pdpgrpc.ScopeRemoval instead.
func findRemoval(removed []*pdpgrpc.ScopeRemoval, dimension, value string) *pdpgrpc.ScopeRemoval {
	for _, r := range removed {
		if r.GetDimension() == dimension && r.GetValue() == value {
			return r
		}
	}
	return nil
}

func wantCode(t *testing.T, err error, want codes.Code) *status.Status {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want status code %v", want)
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("error is not a gRPC status error: %v", err)
	}
	if st.Code() != want {
		t.Fatalf("code = %v, want %v (message: %s)", st.Code(), want, st.Message())
	}
	return st
}

// noPoliciesReason mirrors internal/policy.Multi's literal reason string for
// a tenant with zero stored policies in any language. Not imported from that
// package — this test only reaches it through the wire response, the same
// way any real gRPC client would — so the exact string is reproduced here
// deliberately.
//
// Renamed from noCedarPoliciesReason (it named cedar specifically, matching
// policy.Configured's own single-language message) when Phase 4 Task 2
// rewired main.go from policy.Configured to policy.NewMulti: proof2 below
// (run before this file seeds any cedar policy) now exercises Multi's
// tenant-wide "no policies configured for this tenant" path, which no
// longer names any one language, rather than Configured's "no cedar
// policies for this tenant" path. Both still deny with a single, present,
// non-generic verdict — that property (see policy.Unconfigured's own doc
// comment) is what changed implementation but not principle.
const noPoliciesReason = "principal: no policies configured for this tenant"

// migrationBeforeProvenance and migrationWithProvenance pin the version
// boundary "chain_verifies_across_the_migration_boundary" (below) needs to
// cross. Package migrations exposes only Up, which always targets the
// latest version (see its doc comment on why) — there is no exported
// constant for either version, so both are pinned here rather than left as
// bare magic numbers.
//
// migrationWithProvenance points at 000010_audit_unevaluated_policy_ids, not
// 000006_audit_policy_provenance as its name might suggest at first glance:
// it originally did point at 000006 (the only audit_chain-provenance
// migration that existed then), and was repointed here rather than
// duplicated when 000010 became the next migration to touch audit_chain's
// schema, for the same reason a caller of store.AppendAudit must reach — the
// real function's own INSERT names every provenance column unconditionally,
// unevaluated_policy_ids included, so exercising it against a database
// deliberately migrated only up to 000006 would fail on a column that does
// not exist yet at that version. Migrating straight from
// migrationBeforeProvenance to migrationWithProvenance still exercises the
// 000006 boundary along the way — golang-migrate applies every intervening
// up script in sequence — so nothing about the original 000006 boundary
// this test existed for stops being covered; 000010's own boundary is
// additive coverage from the same live migrate-then-append.
const (
	migrationBeforeProvenance = 5
	migrationWithProvenance   = 10
)

// preProvenanceAuditInsertQuery is store's own (unexported) insertAuditQuery
// reproduced here — it cannot be imported — with policy_source and
// policy_id removed: the exact column set audit_chain had before
// migrations/000006. "chain_verifies_across_the_migration_boundary" uses
// this to write a row under that earlier schema directly, bypassing
// store.AppendAudit (whose INSERT already names both columns and would
// fail against a database migrated back to migrationBeforeProvenance).
const preProvenanceAuditInsertQuery = `INSERT INTO audit_chain (` +
	`tenant_id, prev_hash, entry_hash, occurred_at, event_type, actor, ` +
	`agent_id, delegation_id, root_delegation_id, chain_depth, ` +
	`tool_name, action, declared_tier, derived_tier, ` +
	`decision, denied_leg, denied_at_depth, reason, input_digest` +
	`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)`

// newMigrator builds a *migrate.Migrate against db from the same embedded
// migrations migrations.Up uses, reproducing that function's own
// construction (see its doc comment on why closing it matters) but
// stopping short of calling Up: "chain_verifies_across_the_migration_boundary"
// needs to stop at an exact version, which migrations.Up deliberately does
// not support.
func newMigrator(t *testing.T, db *sql.DB) *migrate.Migrate {
	t.Helper()
	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		t.Fatalf("load embedded migrations: %v", err)
	}
	driver, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		t.Fatalf("create postgres migration driver: %v", err)
	}
	m, err := migrate.NewWithInstance("iofs", src, "postgres", driver)
	if err != nil {
		t.Fatalf("create migrator: %v", err)
	}
	return m
}

// ---------------------------------------------------------------------------
// Phase 4 Task 6 (docs/superpowers/sdd/2026-08-11-phase-4-policy-engines/
// task-6-brief.md): the six multi-language end-to-end proofs.
//
// Four of the six (four-languages, orphan-language, one-engine-prepare-
// failure, cross-tenant-isolation) live here, each its own dedicated tenant
// — never configuredTenant, for the reason
// TestIntegration_LoadAllPolicies_RoundTripsPriority's own doc comment
// already gives — and each builds policy.Multi directly against
// store.New(testDB, tenant) rather than going through pdpClient. That is not
// a style choice; the shared docker-compose PDP this whole file's pdpClient
// talks to is itself single-tenant, permanently: main.go builds
// repo := store.New(db, cfg.TenantID) once at startup, cfg.TenantID never
// varies per request, and store.beginTenantTx always sets app.tenant_id to
// that one fixed value — so pdpClient can only ever resolve agents,
// delegations, and policies belonging to configuredTenant ("tenant-one" in
// deploy/docker/docker-compose.yml). A dedicated tenant is exactly what
// TestEndToEnd's own proof4/proof5/proof14 already rely on to prove
// cross-tenant rows are invisible to it — the same fact that rules pdpClient
// out for any proof below that genuinely needs a SECOND tenant, or a
// language the schema permits but nothing forces the shared PDP's own
// registry to be missing. Three more reasons converge on building
// policy.Multi directly instead:
//
//   - DecideResponse carries only ONE decided_source/decided_policy_id pair
//     (proto/pdp/v1/pdp.proto's own doc comment: "the policy verdict the
//     decision was attributed to"), the single verdict authz.FoldVerdicts
//     picked. "Four verdicts, each with the right Source and PolicyID" and
//     "confirm both appear" cannot be observed through that response, or
//     through the audit row (audit_chain.policy_source/policy_id are the
//     same singular pair) — only through the full []authz.PolicyVerdict
//     slice policy.Multi.Evaluate itself returns.
//   - policies.language carries a CHECK constraint
//     (migrations/000001_baseline.up.sql) restricting it to exactly
//     'json','cedar','rego','xacml' — the four languages this system
//     implements. There is no language string the real schema would accept
//     that pdpClient's own registry (all four, by cfg's default) does not
//     also have an engine for, so "a language absent from the registry"
//     cannot be produced against pdpClient specifically without narrowing
//     `pdp`'s own configuration — which would also remove that language
//     from every other proof here that needs it registered. Building
//     policy.Multi locally, with a registry one language short of the
//     schema's own set, reproduces exactly the shape a smaller
//     STRATIUM_POLICY_LANGUAGES deployment would have, against a real
//     Postgres-loaded StoredPolicy, without touching `pdp` at all.
//   - Cross-tenant isolation (proof 6) needs two tenants observed
//     independently. pdpClient is one client wired to one PDP wired to one
//     tenant; there is no second tenant it could ever be asked about.
//
// This is still genuinely "against a live stack": real Postgres, real
// migrated schema, real RLS-scoped store, the actual production policy.Multi
// — only the transport (in-process call vs. a network round trip to a
// separately-configured PDP process) differs.
//
// A prior version of the first bullet above concluded from it that the
// orphan-language case "cannot be produced against the shared PDP at all" —
// true only of `pdp` specifically (correct: it is wired for all four
// languages, permanently, for every other proof's sake), and false as read
// more broadly, the way Phase 4's Task 6 report stated it and a later task
// took at face value. Nothing about pdpClient being unable to reach this
// case implies no live PDP can: deploy/docker/docker-compose.yml's
// pdp-narrow service (added by Phase 4a Task 5, its own STRATIUM_TENANT_ID
// and a STRATIUM_POLICY_LANGUAGES one language short of all four) is a
// second, independently configured PDP built for exactly this gap, and
// TestIntegration_Live_OrphanLanguageDeniesNamingIt (below,
// near TestIntegration_Multi_OrphanLanguageDeniesNamingIt) is the live proof
// it enables — over real gRPC, through pdpgrpc.Server.Decide and toResponse,
// not just policy.Multi.Evaluate in-process. The two tests are complementary,
// not redundant: this file's own in-process TestIntegration_Multi_
// OrphanLanguageDeniesNamingIt still earns its keep for the reasons the rest
// of this banner gives (no live PDP is wired one language short of only the
// four this repo ships without dedicating a whole second service to it, and
// the full four-verdict slice these other proofs need is not observable
// through any wire response) — it was just never true that it was the only
// proof available, and it no longer is the only one that exists.
//
// The other two (cedar+rego deny-overrides, and the rego-only delegation-
// creation clamp) genuinely need pdpClient — one for a real audit row
// written through the server's own appendAudit, the other for the
// CreateDelegation RPC itself — which means they genuinely need
// configuredTenant. They are added as new subtests INSIDE TestEndToEnd
// instead, at the positions marked "Phase 4 Task 6" below, the same pattern
// Phase 2c Task 5 (proof7-9) and Phase 2d Task 5 (proof10-14) already
// established for extending that one sequential run rather than fighting
// its ordering constraints from outside it.
// ---------------------------------------------------------------------------

// fourLanguagePurpose is the delegation purpose every one of
// TestIntegration_Multi_FourLanguagesProduceFourVerdicts' four policies
// conditions on. Delegation.Purpose, not Principal.Subject: jsonpolicy's
// schema can only match a principal via Principal.Attributes (subject.attr —
// see that package's own doc comment), which a real EvaluationInput never
// populates from a wire request (pdpgrpc/server.go builds
// authz.Principal{Subject: ...} alone), so subject is not a dimension all
// four languages can be proven against uniformly. purpose is: every engine's
// own package doc lists it among the shared-name dimensions (trust_tier,
// max_action_tier, purpose, derived_tier) cedar/request.go, rego/input.go,
// jsonpolicy/engine.go, and xacml/engine.go all expose identically.
const fourLanguagePurpose = "multi-language four-verdict proof"

// cedarPurposeCondition, regoPurposeCondition, jsonPurposeCondition, and
// xacmlPurposeCondition each match a StoredPolicy in their own language
// against Delegation.Purpose == fourLanguagePurpose — the one dimension
// every engine maps identically (see fourLanguagePurpose's own doc comment).
// Shared by TestIntegration_Multi_FourLanguagesProduceFourVerdicts and
// TestIntegration_Multi_OrphanLanguageDeniesNamingIt, so the four fixtures
// exist in exactly one place each.
func cedarPurposeCondition(purpose string) string {
	return fmt.Sprintf(`permit(principal, action, resource) when { context.delegation.purpose == "%s" };`, purpose)
}

func regoPurposeCondition(purpose string) string {
	return fmt.Sprintf(`package stratium.policy

allow if {
	input.delegation.purpose == %q
}`, purpose)
}

func jsonPurposeCondition(purpose string) string {
	return fmt.Sprintf(`{"effect": "allow", "match": {"delegation": {"attr": "purpose", "equals": %q}}}`, purpose)
}

func xacmlPurposeCondition(policyID, purpose string) string {
	return fmt.Sprintf(`<Policy PolicyId=%q RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Target>
    <AnyOf>
      <AllOf>
        <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
          <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">%s</AttributeValue>
          <AttributeDesignator AttributeId="delegation-purpose" DataType="http://www.w3.org/2001/XMLSchema#string" Category="urn:oasis:names:tc:xacml:3.0:attribute-category:environment"/>
        </Match>
      </AllOf>
    </AnyOf>
  </Target>
  <Rule RuleId=%q Effect="Permit"/>
</Policy>`, policyID, purpose, policyID+"-rule")
}

// fullRegistry is every engine main.go's own default STRATIUM_POLICY_LANGUAGES
// wires — built fresh per call (each policy.PolicyEngine implementation here
// is a stateless zero-value struct, so there is no cost or shared-state risk
// to doing so) rather than shared as a package var, so nothing here could
// accidentally alias engine state across proofs even if a future engine
// stopped being stateless.
func fullRegistry() policy.Registry {
	return policy.Registry{
		"cedar": cedar.New(),
		"rego":  rego.New(),
		"json":  jsonpolicy.New(),
		"xacml": xacml.New(),
	}
}

// TestIntegration_Multi_FourLanguagesProduceFourVerdicts is proof 2: a
// tenant with one matching policy in each of the four languages gets four
// verdicts back from policy.Multi.Evaluate, each correctly attributed.
func TestIntegration_Multi_FourLanguagesProduceFourVerdicts(t *testing.T) {
	const tenant = "tenant-multilang-four-verdicts-integration"

	cedarID := seedPolicyLang(t, tenant, "four-lang-cedar", "cedar", cedarPurposeCondition(fourLanguagePurpose), "allow")
	regoID := seedPolicyLang(t, tenant, "four-lang-rego", "rego", regoPurposeCondition(fourLanguagePurpose), "allow")
	jsonID := seedPolicyLang(t, tenant, "four-lang-json", "json", jsonPurposeCondition(fourLanguagePurpose), "allow")
	xacmlID := seedPolicyLang(t, tenant, "four-lang-xacml", "xacml", xacmlPurposeCondition("four-lang-xacml", fourLanguagePurpose), "allow")

	multi := policy.NewMulti(store.New(testDB, tenant), fullRegistry())
	verdicts := multi.Evaluate(t.Context(), policy.EvaluationInput{
		Delegation: policy.DelegationContext{Purpose: fourLanguagePurpose},
	})
	t.Logf("Evaluate() with one matching policy per language -> %d verdicts: %+v", len(verdicts), verdicts)

	if len(verdicts) != 4 {
		t.Fatalf("got %d verdicts, want 4 (one per language)", len(verdicts))
	}
	want := map[string]string{"cedar": cedarID, "rego": regoID, "json": jsonID, "xacml": xacmlID}
	byLang := make(map[string]authz.PolicyVerdict, len(verdicts))
	for _, v := range verdicts {
		byLang[v.Source] = v
	}
	for lang, wantID := range want {
		v, ok := byLang[lang]
		if !ok {
			t.Errorf("no verdict from source %q", lang)
			continue
		}
		if v.PolicyID != wantID {
			t.Errorf("source %q: PolicyID = %q, want %q", lang, v.PolicyID, wantID)
		}
		if v.Effect != authz.EffectAllow {
			t.Errorf("source %q: Effect = %v, want EffectAllow", lang, v.Effect)
		}
	}
}

// TestIntegration_Multi_OrphanLanguageDeniesNamingIt is proof 3 — D10's own
// proof, and the reason the whole multi-engine seam exists: a policy in a
// language absent from the registry must deny, naming that language, not be
// silently skipped. Asserts the exact Reason string (orphanVerdicts, multi.go),
// not merely Effect==Deny: an effect-only check would also pass a denial for
// a completely different reason, which is precisely the failure mode D10
// names — a policy an operator believes is protecting them, silently never
// evaluated. See this file's own "Phase 4 Task 6" banner above for why this
// builds policy.Multi directly instead of going through pdpClient, and
// TestIntegration_Live_OrphanLanguageDeniesNamingIt (below) for the live,
// over-the-wire counterpart Phase 4a Task 5 added — this test alone does not
// exercise pdpgrpc.Server.Decide or its copy of FoldVerdicts' chosen reason
// into DecideResponse.PrincipalReason at all, only policy.Multi.Evaluate.
//
// PolicyID stays empty here — it names one policy, and this verdict is
// about the whole (one-policy) language, not a policy-level answer. The
// orphaned id lives on UnevaluatedPolicyIDs instead; see orphanVerdicts'
// own doc comment in multi.go for why a per-policy PolicyID split was tried
// and reverted.
func TestIntegration_Multi_OrphanLanguageDeniesNamingIt(t *testing.T) {
	const tenant = "tenant-multilang-orphan-integration"
	const purpose = "orphan-language proof"

	policyID := seedPolicyLang(t, tenant, "orphan-rego-policy", "rego", regoPurposeCondition(purpose), "allow")

	registry := fullRegistry()
	delete(registry, "rego") // the one language this registry deliberately does not implement.
	multi := policy.NewMulti(store.New(testDB, tenant), registry)

	verdicts := multi.Evaluate(t.Context(), policy.EvaluationInput{
		Delegation: policy.DelegationContext{Purpose: purpose},
	})
	t.Logf("Evaluate() for a tenant whose only policy is in an unregistered language -> %+v", verdicts)

	if len(verdicts) != 1 {
		t.Fatalf("got %d verdicts, want 1", len(verdicts))
	}
	v := verdicts[0]
	if v.Effect != authz.EffectDeny {
		t.Fatalf("Effect = %v, want EffectDeny — an unevaluatable policy must deny, not be silently skipped", v.Effect)
	}
	if v.Source != "rego" {
		t.Errorf("Source = %q, want %q", v.Source, "rego")
	}
	if v.PolicyID != "" {
		t.Errorf("PolicyID = %q, want empty: this verdict is about the whole language, not one policy", v.PolicyID)
	}
	if want := []string{policyID}; !slices.Equal(v.UnevaluatedPolicyIDs, want) {
		t.Errorf("UnevaluatedPolicyIDs = %v, want %v — audit_chain.unevaluated_policy_ids must be queryable for "+
			"this denial", v.UnevaluatedPolicyIDs, want)
	}
	// Singular "policy": this tenant's only rego policy is the whole
	// orphaned set, so the "how many" signal (countSuffix, multi.go) must
	// say so explicitly rather than reading as though a count was merely
	// omitted.
	wantReason := "principal: no rego engine registered; cannot evaluate 1 rego policy for this tenant"
	if v.Reason != wantReason {
		t.Errorf("Reason = %q, want %q — the effect alone is not enough; D10 requires naming the unregistered "+
			"language and how many orphaned policies exist", v.Reason, wantReason)
	}
}

// narrowRegistryMissingLanguage is the one language deploy/docker/
// docker-compose.yml's pdp-narrow service deliberately leaves out of its own
// STRATIUM_POLICY_LANGUAGES (cedar,json,xacml) — reproduced here the same
// deliberate way noPoliciesReason (above) reproduces policy.Multi's own
// literal text, rather than imported: this test only ever reaches
// pdp-narrow's configuration through its observable behaviour over gRPC, the
// same way a real operator would, never by reading its environment.
const narrowRegistryMissingLanguage = "rego"

// TestIntegration_Live_OrphanLanguageDeniesNamingIt is the live counterpart
// to TestIntegration_Multi_OrphanLanguageDeniesNamingIt above, and the
// permanent test this file's own "Phase 4 Task 6" banner used to claim was
// impossible (see the correction inside that banner). policy.Multi.Evaluate
// is exercised directly there, never through pdpgrpc.Server.Decide or its
// toResponse/appendAudit — so a regression in how a decision's provenance is
// copied onto the wire response and the audit row would leave that test
// green while operators silently stopped being told which language went
// unevaluated. Only a test that goes all the way over gRPC, as this one
// does, exercises that copy at all.
//
// The tenant here carries TWO languages, deliberately, not one: a Cedar
// forbid (which pdp-narrow's registry CAN evaluate) alongside orphaned rego
// policies (which it cannot — narrowRegistryMissingLanguage). This is the
// combination an earlier version of this test — one policy, one language,
// orphaned rego alone — could never have caught: authz.FoldVerdicts
// attributes a decision to the lexicographically smallest (Source,
// PolicyID), Source is the language name, and "cedar" sorts before "rego" —
// so the moment ANY Cedar verdict is also present, it wins that tie-break
// over an orphaned rego verdict every time, regardless of how the orphan
// fact is shaped. A prior fix (commit 7522731) tried to make the orphaned
// policy's id reach audit_chain.policy_id by splitting into one deny
// verdict per orphaned policy — which this exact scenario proves could
// never have worked, since every one of those split verdicts still has
// Source "rego" and still loses to Cedar's. The real fix is
// audit_chain.unevaluated_policy_ids (migrations/000010): populated by
// aggregating UnevaluatedPolicyIDs across authz.Decide's WHOLE verdict
// slice (internal/authz/compound.go), not just the one FoldVerdicts
// attributes the decision to, so it survives regardless of who wins.
//
// Reaching this case live needs a second, independently configured PDP —
// deploy/docker/docker-compose.yml's pdp-narrow, with its own
// STRATIUM_TENANT_ID and a STRATIUM_POLICY_LANGUAGES one language short —
// rather than a second tenant on pdpClient's own PDP: main.go builds one
// tenant-scoped store.Store and one policy.Multi at startup and neither
// varies per request, so `pdp` can never be asked about a tenant, let alone
// a registry, other than the one it was started with.
func TestIntegration_Live_OrphanLanguageDeniesNamingIt(t *testing.T) {
	const purpose = "live orphan-language proof"

	agentID := uuid.New()
	seedAgent(t, narrowTenant, agentID, "integration-agent-narrow-registry", models.TrustTierUnverified)
	acting := singleHopDelegation(t, narrowTenant, agentID, models.ActionTierInternalModify, purpose)

	// An unconditional forbid: pdp-narrow registers cedar, so this is
	// actually evaluated and actually denies — the decision this whole
	// request must be attributed to.
	cedarForbidID := seedPolicyLang(t, narrowTenant, "live-orphan-cedar-forbid", "cedar",
		`forbid(principal, action, resource);`, "deny")
	// Two orphaned rego policies, not one: proves UnevaluatedPolicyIDs is a
	// real aggregate, not a single id that happens to work.
	regoID1 := seedPolicyLang(t, narrowTenant, "live-orphan-rego-policy-1", narrowRegistryMissingLanguage,
		regoPurposeCondition(purpose), "allow")
	regoID2 := seedPolicyLang(t, narrowTenant, "live-orphan-rego-policy-2", narrowRegistryMissingLanguage,
		regoPurposeCondition(purpose), "allow")

	resp, err := narrowPdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
		Token:   mintToken(t, narrowPdpClient, acting.ID),
		AgentId: agentID.String(),
		Subject: "live-orphan-subject@example.com",
		Tool:    "Bash",
	})
	if err != nil {
		t.Fatalf("Decide() against pdp-narrow error = %v, want a decision", err)
	}
	t.Logf("Decide() against pdp-narrow (registered: cedar,json,xacml; missing: %s) for a tenant with a cedar "+
		"forbid AND two orphaned rego policies -> effect=%s denied_leg=%q principal_reason=%q decided_source=%q "+
		"(present=%t) decided_policy_id=%q (present=%t)",
		narrowRegistryMissingLanguage, resp.GetEffect(), resp.GetDeniedLeg(), resp.GetPrincipalReason(),
		resp.GetDecidedSource(), resp.DecidedSource != nil, resp.GetDecidedPolicyId(), resp.DecidedPolicyId != nil)

	if resp.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
		t.Fatalf("Effect = %v, want EFFECT_DENY — an unevaluatable policy must deny, not be silently skipped", resp.GetEffect())
	}
	if resp.GetDeniedLeg() != "principal" {
		t.Errorf("DeniedLeg = %q, want %q", resp.GetDeniedLeg(), "principal")
	}

	// Attribution: Cedar, correctly — one decision, one attributed policy.
	// "cedar" sorts before "rego" lexicographically, so FoldVerdicts' own
	// tie-break picks Cedar's verdict over the orphan-language one no matter
	// how many rego policies are orphaned — this is what makes this exact
	// tenant shape (not the single-rego-policy shape the old version of this
	// test used) the one that actually exercises the bug the per-policy
	// split never fixed.
	if resp.DecidedSource == nil || resp.GetDecidedSource() != "cedar" {
		t.Errorf("DecidedSource = %v, want present and %q", resp.DecidedSource, "cedar")
	}
	if resp.DecidedPolicyId == nil || resp.GetDecidedPolicyId() != cedarForbidID {
		t.Errorf("DecidedPolicyId = %v, want present and %q (the cedar forbid, not either orphaned rego policy)",
			resp.DecidedPolicyId, cedarForbidID)
	}
	if principalReason := resp.GetPrincipalReason(); strings.Contains(principalReason, narrowRegistryMissingLanguage) {
		t.Errorf("PrincipalReason = %q must not name %q — the decision is cedar's, not rego's orphan fact",
			principalReason, narrowRegistryMissingLanguage)
	}

	// The audit row's provenance pair agrees with the response — the general
	// "response and row agree" property is covered elsewhere in this file
	// (audit_row_provenance_matches_response); this is the specific instance
	// that matters here: the orphaned rego policies must NOT have leaked
	// into policy_source/policy_id just because they are also present.
	source, auditPolicyID := auditRowProvenance(t, narrowTenant)
	if !source.Valid || source.String != "cedar" {
		t.Errorf("stored policy_source = %q (valid=%t), want %q", source.String, source.Valid, "cedar")
	}
	if !auditPolicyID.Valid || auditPolicyID.String != cedarForbidID {
		t.Errorf("stored policy_id = %q (valid=%t), want %q", auditPolicyID.String, auditPolicyID.Valid, cedarForbidID)
	}

	// The assertion this test exists for: the orphaned rego ids still reach
	// a real audit_chain row, in the purpose-built column, even though the
	// decision itself is attributed to cedar. This is
	// authz.Result.UnevaluatedPolicyIDs, aggregated across authz.Decide's
	// whole verdict slice (internal/authz/compound.go) rather than read off
	// Deciding alone — the aggregation mutation-tested in that package's own
	// TestDecide_UnevaluatedPolicyIDsSurviveLosingTheFold, proven here live,
	// end to end, against a real orphaned language and a real deciding
	// Cedar policy together.
	wantIDs := []string{regoID1, regoID2}
	slices.Sort(wantIDs)
	gotIDs := auditRowUnevaluatedPolicyIDs(t, narrowTenant)
	slices.Sort(gotIDs)
	if !slices.Equal(gotIDs, wantIDs) {
		t.Errorf("audit_chain.unevaluated_policy_ids = %v, want %v — both orphaned rego policies must reach "+
			"this column even though the decision itself is attributed to cedar", gotIDs, wantIDs)
	}
}

// TestIntegration_Live_ResourceIdentityEnforcement is Phase 7 Task 4's Part
// 1: the four integration proofs the task brief asks for, each a real
// Decide() call over real gRPC against pdp-resource
// (deploy/docker/docker-compose.yml) and its own dedicated tenant
// (resourceTenant) — see that service's own doc comment, and the
// resourcePdpClient/resourceTenant package vars above, for why neither
// pdpClient's tenant nor narrowPdpClient's can serve these safely.
//
// One agent and one unconditional cedar permit policy
// (`permit(principal, action, resource);`), shared by every subtest below:
// this tenant is touched by nothing else in this file, so there is no
// cross-subtest scoping concern an unconditional permit would create the
// way TestEndToEnd's own subtests each scope a cedar policy to one named
// principal. Every subtest still checks PrincipalEffect/AgentEffect
// alongside the outcome it cares about — the same discipline
// proof9_cedar_permit_cannot_exceed_delegation_ceiling and
// proof12_decide_with_clamped_delegation_denies_above_granted_tier use — so
// a DENY is attributable to the delegation leg's resource/cap check
// specifically, never to some other leg that happened to deny first, and an
// ALLOW is a genuine three-leg allow, not a side effect of a leg's zero
// value.
//
// Tool is "Read" throughout: catalogued READ_ONLY (authz.DefaultCatalog),
// so the derived tier never depends on parsing RawInput and
// TrustTierUnverified is sufficient on the agent leg
// (authz.DefaultTrustTable) — the same reasoning proof12 documents for its
// own use of Read.
func TestIntegration_Live_ResourceIdentityEnforcement(t *testing.T) {
	const subject = "resource-identity-proof@example.com"

	agentID := uuid.New()
	seedAgent(t, resourceTenant, agentID, "integration-agent-resource-identity", models.TrustTierUnverified)
	seedPolicy(t, resourceTenant, "permit-resource-identity-proof",
		`permit(principal, action, resource);`, "allow")

	// newDelegation builds and seeds one well-formed root delegation (the
	// same shape singleHopDelegation, above, builds — reproduced rather than
	// reused because this test needs ClassificationCaps/ResourceConstraints
	// as per-call parameters, which singleHopDelegation's own signature does
	// not expose to its ~15 existing callers).
	newDelegation := func(purpose string, caps, constraints map[string]string) *models.Delegation {
		id := uuid.New()
		return seedDelegation(t, &models.Delegation{
			ID: id, TenantID: resourceTenant, UserID: "integration-test-user", AgentID: agentID,
			ApprovedTools: []string{}, MaxActionTier: models.ActionTierInternalModify,
			ClassificationCaps: caps, ResourceConstraints: constraints,
			Purpose: purpose, ExpiresAt: time.Now().Add(time.Hour),
			RootDelegationID: id, Depth: 0, ChainAgentIDs: []uuid.UUID{agentID},
		})
	}

	decide := func(t *testing.T, delegationID uuid.UUID, resource map[string]string) *pdpgrpc.DecideResponse {
		t.Helper()
		resp, err := resourcePdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
			Token:    mintToken(t, resourcePdpClient, delegationID),
			AgentId:  agentID.String(),
			Subject:  subject,
			Tool:     "Read",
			Resource: resource,
		})
		if err != nil {
			t.Fatalf("Decide() error = %v, want a decision", err)
		}
		return resp
	}

	// proof1Delegation is shared with proof2, below, by design: the brief
	// asks for "the same delegation" to both permit a matching request and
	// deny one that omits the constrained key entirely — proof2 depends on
	// this subtest having run first, the same ordered-subtest-state idiom
	// TestEndToEnd's own delegationGateResp uses.
	var proof1Delegation *models.Delegation

	// proof1: {project: alpha} in the request matches the delegation's own
	// constraint and permits; {project: beta} carries the same key with a
	// different value and denies — the exact-match rule
	// TestDelegationLeg_AllowsResourceConstraintExactMatch and
	// TestDelegationLeg_ResourceConstraintComparisonIsExactNotPrefix already
	// pin at the unit level (internal/authz/delegation_test.go), proven here
	// over real gRPC against a real running PDP.
	t.Run("proof1_resource_constraint_matching_value_permits_mismatched_denies", func(t *testing.T) {
		proof1Delegation = newDelegation("proof1/2: resource constraint project=alpha", nil, map[string]string{"project": "alpha"})

		matching := decide(t, proof1Delegation.ID, map[string]string{"project": "alpha"})
		t.Logf("Decide() with a matching resource constraint -> effect=%s principal=%s agent=%s delegation=%s",
			matching.GetEffect(), matching.GetPrincipalEffect(), matching.GetAgentEffect(), matching.GetDelegationEffect())
		if matching.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Fatalf("Effect = %v, want EFFECT_ALLOW (project=alpha matches the delegation's own constraint)", matching.GetEffect())
		}
		if matching.GetDelegationEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Errorf("DelegationEffect = %v, want EFFECT_ALLOW", matching.GetDelegationEffect())
		}

		mismatched := decide(t, proof1Delegation.ID, map[string]string{"project": "beta"})
		t.Logf("Decide() with a mismatched resource constraint -> effect=%s denied_leg=%q reason=%q",
			mismatched.GetEffect(), mismatched.GetDeniedLeg(), mismatched.GetReason())
		if mismatched.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Fatalf("Effect = %v, want EFFECT_DENY (project=beta does not match the delegation's project=alpha)",
				mismatched.GetEffect())
		}
		if mismatched.GetDeniedLeg() != "delegation" {
			t.Errorf("DeniedLeg = %q, want %q", mismatched.GetDeniedLeg(), "delegation")
		}
		if mismatched.GetPrincipalEffect() != pdpgrpc.Effect_EFFECT_ALLOW || mismatched.GetAgentEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Errorf("PrincipalEffect/AgentEffect = %v/%v, want ALLOW/ALLOW (isolating the delegation leg)",
				mismatched.GetPrincipalEffect(), mismatched.GetAgentEffect())
		}
		if !strings.Contains(mismatched.GetReason(), `does not match request value "beta"`) {
			t.Errorf("Reason = %q, want it to name the mismatched value", mismatched.GetReason())
		}
	})

	// proof2: Task 2's load-bearing rule, over the wire rather than in a
	// unit test (TestDelegationLeg_DeniesResourceConstraintAbsentFromRequest
	// pins it at the unit level already) — the same delegation proof1 just
	// permitted denies a request that never mentions "project" at all, even
	// though the request still carries some other resource identity ("id").
	// Silently passing here would recreate, for identity, exactly the
	// CheckCap defect this whole phase exists to fix for classification.
	t.Run("proof2_resource_constraint_absent_key_denies", func(t *testing.T) {
		if proof1Delegation == nil {
			t.Fatal("proof1Delegation is nil: proof1_resource_constraint_matching_value_permits_mismatched_denies must run before this subtest")
		}

		resp := decide(t, proof1Delegation.ID, map[string]string{"id": "doc-1"}) // carries identity, but never "project"
		t.Logf("Decide() with the constrained key entirely absent from the request -> effect=%s denied_leg=%q reason=%q",
			resp.GetEffect(), resp.GetDeniedLeg(), resp.GetReason())
		if resp.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Fatalf(`Effect = %v, want EFFECT_DENY (the delegation requires "project", and this request never names it)`,
				resp.GetEffect())
		}
		if resp.GetDeniedLeg() != "delegation" {
			t.Errorf("DeniedLeg = %q, want %q", resp.GetDeniedLeg(), "delegation")
		}
		if resp.GetPrincipalEffect() != pdpgrpc.Effect_EFFECT_ALLOW || resp.GetAgentEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Errorf("PrincipalEffect/AgentEffect = %v/%v, want ALLOW/ALLOW (isolating the delegation leg)",
				resp.GetPrincipalEffect(), resp.GetAgentEffect())
		}
		if !strings.Contains(resp.GetReason(), `resource constraint "project" is required but absent from the request`) {
			t.Errorf("Reason = %q, want it to name the load-bearing rule (Task 2's own wording)", resp.GetReason())
		}
	})

	// proof3: a classification cap denies a resource that declares none at
	// all (R2, Task 3), in both the wire response AND the persisted audit
	// row. Mirrors internal/authz's
	// TestDelegationLeg_DeniesConfiguredCapWhenResourceHasNoClassification at
	// the live-stack layer, with the audit row read back from Postgres rather
	// than only the RPC response.
	//
	// The EXCEEDS half of this proof, and the "these two reasons must differ"
	// comparison, moved to TestIntegration_Live_ResourceLabelling (below).
	// They used to live here and to assert a classification the CALLER sent,
	// which was the only source that existed -- R3's gap. Resource labelling
	// closed that gap, and closed the wire as a source with it: a label is
	// resolved only against an id the PDP extracted through the tenant's own
	// catalog row (R1/R4, internal/pdpgrpc/label.go). Tool "Read" here has no
	// catalog row, deliberately -- proofs 1, 2 and 4 need the wire's Resource
	// to reach the delegation leg unchanged -- so no resource in THIS test can
	// carry a label at all, and asserting the exceeds path here would have
	// meant asserting it through a path production cannot take.
	t.Run("proof3_classification_cap_denies_an_unlabelled_resource", func(t *testing.T) {
		d := newDelegation("proof3: classification cap nato=CONFIDENTIAL", map[string]string{"nato": "CONFIDENTIAL"}, nil)
		before := fetchAuditChain(t, resourceTenant)

		uncheckable := decide(t, d.ID, map[string]string{"id": "doc-uncheckable"}) // identity, but nothing labels it
		t.Logf("Decide() with a classification cap against an unlabelled resource -> effect=%s reason=%q",
			uncheckable.GetEffect(), uncheckable.GetReason())
		if uncheckable.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Fatalf("Effect = %v, want EFFECT_DENY (an uncheckable cap must deny, not pass uncontested)", uncheckable.GetEffect())
		}
		if uncheckable.GetDeniedLeg() != "delegation" {
			t.Errorf("DeniedLeg = %q, want %q", uncheckable.GetDeniedLeg(), "delegation")
		}
		if !strings.Contains(uncheckable.GetReason(), "cannot be evaluated") {
			t.Errorf("Reason = %q, want it to contain %q (pkg/classification.CheckCap's uncheckable wording)",
				uncheckable.GetReason(), "cannot be evaluated")
		}

		after := fetchAuditChain(t, resourceTenant)
		newRows := after[len(before):]
		if len(newRows) != 1 {
			t.Fatalf("this subtest made 1 Decide() call, want 1 new audit row, got %d", len(newRows))
		}
		row := newRows[0]
		t.Logf("audit row: decision=%q reason=%q", row.Decision, row.Reason)
		if row.Decision != "DENY" {
			t.Fatalf("audit row Decision = %q, want DENY", row.Decision)
		}
		if row.Reason != uncheckable.GetReason() {
			t.Errorf("audit row reason = %q, want %q (the response's own reason)", row.Reason, uncheckable.GetReason())
		}
	})

	// proof4: the regression guard. A delegation with no classification caps
	// and no resource constraints configured is unaffected by this phase —
	// the property that proves the change is targeted rather than a blanket
	// tightening: a version of this phase that denied every request with a
	// resource attached would still pass proofs 1-3 above, but not this one.
	// The request deliberately carries a "project" value the delegation
	// never constrained AND a classification claim, so this proof cannot
	// pass by accident of an empty resource map — it must be the empty
	// configuration, not an empty request, that makes this an allow. (The
	// classification claim is discarded before the delegation leg ever sees
	// it, since resource labelling shipped; it is left in the fixture as
	// adversarial payload, not because it is believed.)
	t.Run("proof4_no_caps_no_constraints_unaffected_regression_guard", func(t *testing.T) {
		d := newDelegation("proof4: no caps, no constraints (regression guard)", nil, nil)

		resp := decide(t, d.ID, map[string]string{
			"project": "whatever-the-agent-happens-to-send", "classification": "TOP-SECRET", "hierarchy": "nato",
		})
		t.Logf("Decide() against a delegation with no caps and no constraints -> effect=%s", resp.GetEffect())
		if resp.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Fatalf("Effect = %v, want EFFECT_ALLOW — a delegation with no caps and no constraints must be "+
				"unaffected by this phase, even against a resource that would exceed a cap or fail a constraint "+
				"if either were configured; this is the regression guard proving the change is targeted, not a "+
				"blanket tightening", resp.GetEffect())
		}
		if resp.GetDelegationEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Errorf("DelegationEffect = %v, want EFFECT_ALLOW", resp.GetDelegationEffect())
		}
	})

	// proof5: R1, enforced rather than merely intended, over real gRPC. A
	// caller declares its own resource UNCLASSIFIED under a CONFIDENTIAL cap
	// and is denied anyway, because the PDP discards the classification and
	// hierarchy attributes the wire carried and consults only the tenant's
	// own rules (internal/pdpgrpc/label.go).
	//
	// Not a duplicate of proof3's uncheckable half. That one carries no
	// classification at all; this one carries an entirely valid, entirely
	// satisfying claim, and the denial is attributable to the claim being
	// ignored rather than to there being nothing to check. Before resource
	// labelling, this request ALLOWED — the cheapest possible cap bypass,
	// available to any caller that can reach the PDP, and the reason
	// "no PEP in this repo sends one" was never the guarantee.
	//
	// Tool "Read" has no catalog row here, which is the path on which this
	// property is load-bearing: ApplyExtraction replaces the resource map
	// wholesale for a CATALOGED tool, so the claim would be gone before
	// labelResource ever ran. On the uncataloged path the caller's map
	// survives intact, and stripping the two label keys is the only thing
	// standing between this claim and a satisfied cap.
	t.Run("proof5_wire_supplied_classification_is_not_believed", func(t *testing.T) {
		d := newDelegation("proof5: classification cap nato=CONFIDENTIAL", map[string]string{"nato": "CONFIDENTIAL"}, nil)

		resp := decide(t, d.ID, map[string]string{
			"id": "doc-claiming-its-own-label", "classification": "UNCLASSIFIED", "hierarchy": "nato",
		})
		t.Logf("Decide() with a caller-declared classification under a cap -> effect=%s reason=%q",
			resp.GetEffect(), resp.GetReason())
		if resp.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Fatalf("Effect = %v, want EFFECT_DENY — a caller-supplied classification must never satisfy a "+
				"cap (R1: a client asserting a security-relevant fact the server cannot check is D1 relocated)",
				resp.GetEffect())
		}
		if resp.GetDeniedLeg() != "delegation" {
			t.Errorf("DeniedLeg = %q, want %q", resp.GetDeniedLeg(), "delegation")
		}
		if !strings.Contains(resp.GetReason(), "cannot be evaluated") {
			t.Errorf("Reason = %q, want the uncheckable-cap wording: the claim is discarded, leaving the "+
				"resource unlabelled", resp.GetReason())
		}
	})
}

// TestIntegration_Live_ToolCatalogEnforcement is Phase 8 Task 4's Part 2:
// the five integration proofs the task brief asks for, against a live
// stack. Runs against pdp-resource and resourceTenant -- the same service
// and tenant TestIntegration_Live_ResourceIdentityEnforcement (Phase 7 Task
// 4) already uses, for the same reason that test's own doc comment gives:
// neither pdpClient's tenant nor narrowPdpClient's can host a new live
// proof safely (see deploy/docker/docker-compose.yml's own comment on
// pdp-resource). This test seeds its own agent, its own unconditional cedar
// permit, and its own delegations -- not reused from the other test in this
// file -- so it passes standalone (e.g. `go test -run
// TestIntegration_Live_ToolCatalogEnforcement`) without depending on a
// different top-level test function having run first in the same process;
// the two tests share only the tenant.
//
// tool_catalog rows this test seeds ("read_file", "write_file") never
// collide with anything TestIntegration_Live_ResourceIdentityEnforcement
// uses (tool "Read" only, and no tool_catalog row at all) --
// migrations/000013_tool_catalog's own UNIQUE(tenant_id, tool_name) is
// case-sensitive and exact-match only.
//
// proof4 (the regression guard) is declared and runs FIRST, deliberately,
// and depends on doing so: "a tenant with no catalog rows is unaffected"
// can only be checked live at a moment this tenant genuinely has zero
// tool_catalog rows, and every other subtest below seeds one. This is the
// same ordered-subtest-state idiom
// TestIntegration_Live_ResourceIdentityEnforcement's own proof1/proof2 pair
// already uses in this file. Confirmed safe by grep, not merely assumed:
// catalog_integration_test.go's three tests each seed into their own
// dedicated tenant, none of them resourceTenant.
//
// Proof 5 ("the serving role cannot write the catalog") is not reproduced
// here: TestIntegration_ToolCatalog_ServingRoleCannotWrite
// (catalog_integration_test.go, Task 1) already proves it against a live
// Postgres, in its own dedicated tenant, and this task's brief does not ask
// for a second proof of a grant Task 1 already covered.
func TestIntegration_Live_ToolCatalogEnforcement(t *testing.T) {
	const subject = "tool-catalog-proof@example.com"

	agentID := uuid.New()
	// PLATFORM_TRUSTED, the ceiling: this test's proofs are about the
	// delegation leg and the catalog's effect on the derived tier, not agent
	// trust, so the agent leg must never itself be able to deny or confound
	// a result -- the same reasoning proof9/proof12 (above, in this file)
	// give their own agents, and Phase 6/7 Task 4's own real-agent runs give
	// their own main agent.
	seedAgent(t, resourceTenant, agentID, "integration-agent-tool-catalog", models.TrustTierPlatformTrusted)
	seedPolicy(t, resourceTenant, "permit-tool-catalog-proof", `permit(principal, action, resource);`, "allow")

	newDelegation := func(purpose string, maxTier models.ActionTier, constraints map[string]string) *models.Delegation {
		id := uuid.New()
		return seedDelegation(t, &models.Delegation{
			ID: id, TenantID: resourceTenant, UserID: "integration-test-user", AgentID: agentID,
			ApprovedTools: []string{}, MaxActionTier: maxTier,
			ResourceConstraints: constraints,
			Purpose:             purpose, ExpiresAt: time.Now().Add(time.Hour),
			RootDelegationID: id, Depth: 0, ChainAgentIDs: []uuid.UUID{agentID},
		})
	}

	// decide sends tool/rawInput and nothing else -- no wire Resource, no
	// declared_tier -- exactly what a real hook/mcp PEP request carries
	// (mcp_authorize.go's own decideAndRelay). This is the deliberate
	// difference from TestIntegration_Live_ResourceIdentityEnforcement's own
	// decide() helper, which sends Resource directly: that test proves the
	// delegation leg's constraint CHECK; this one proves the catalog's
	// server-side EXTRACTION feeding that same check from raw_input alone --
	// Phase 7 Task 4's own Finding B, closed by this phase. Sending Resource
	// directly here instead would silently test the old, pre-Phase-8
	// mechanism this task exists to replace.
	decide := func(t *testing.T, delegationID uuid.UUID, tool, rawInput string) *pdpgrpc.DecideResponse {
		t.Helper()
		resp, err := resourcePdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
			Token:    mintToken(t, resourcePdpClient, delegationID),
			AgentId:  agentID.String(),
			Subject:  subject,
			Tool:     tool,
			RawInput: rawInput,
		})
		if err != nil {
			t.Fatalf("Decide() error = %v, want a decision", err)
		}
		return resp
	}

	// readOnlyDelegation is shared by proof4, proof1, and proof2 -- the same
	// delegation, decided against three times as its tool_catalog rows
	// change underneath it, by design: proof4 proves what it does BEFORE any
	// row exists, proof1 proves what changes once "read_file" is cataloged,
	// and proof2 proves "write_file" still denies under the identical
	// delegation once IT is cataloged too -- isolating the catalog row as
	// the only thing that changed between each Decide() call.
	var readOnlyDelegation *models.Delegation

	t.Run("proof4_no_catalog_rows_unaffected_regression_guard", func(t *testing.T) {
		got, err := store.New(testDB, resourceTenant).LoadToolCatalog(t.Context())
		if err != nil {
			t.Fatalf("LoadToolCatalog() error = %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("resourceTenant already has %d tool_catalog row(s) before this subtest seeds any -- "+
				"this subtest must run first (see this test's own doc comment); got %+v", len(got), got)
		}

		readOnlyDelegation = newDelegation("proof1/2/4: read_file/write_file under a READ_ONLY delegation ceiling",
			models.ActionTierReadOnly, nil)

		// "read_file" is Phase 6's own negative 1's tool, with no catalog row
		// -- reproducing exactly the pre-Phase-8 gap, live, as the
		// counterfactual proof1 (below) closes: with no row to fix its tier,
		// it falls to BuiltinTier's own "unrecognized -> assume it modifies"
		// default (a JSON blob positively matches nothing), derives
		// INTERNAL_MODIFY, and exceeds a READ_ONLY ceiling.
		resp := decide(t, readOnlyDelegation.ID, "read_file", `{"path":"/tmp/tool-catalog-proof/notes.txt"}`)
		t.Logf("Decide() for an uncataloged read_file -> effect=%s derived_tier=%d denied_leg=%q reason=%q",
			resp.GetEffect(), resp.GetDerivedTier(), resp.GetDeniedLeg(), resp.GetReason())
		if resp.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Fatalf("Effect = %v, want EFFECT_DENY -- an uncataloged read_file must derive INTERNAL_MODIFY "+
				"(BuiltinTier's own default) and exceed a READ_ONLY delegation ceiling, exactly as it did "+
				"before this phase's tool_catalog existed at all", resp.GetEffect())
		}
		if resp.GetDerivedTier() != int32(models.ActionTierInternalModify) {
			t.Errorf("DerivedTier = %d, want %d (INTERNAL_MODIFY)", resp.GetDerivedTier(), models.ActionTierInternalModify)
		}
		if resp.GetDeniedLeg() != "delegation" {
			t.Errorf("DeniedLeg = %q, want %q", resp.GetDeniedLeg(), "delegation")
		}
		if resp.GetPrincipalEffect() != pdpgrpc.Effect_EFFECT_ALLOW || resp.GetAgentEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Errorf("PrincipalEffect/AgentEffect = %v/%v, want ALLOW/ALLOW (isolating the delegation leg)",
				resp.GetPrincipalEffect(), resp.GetAgentEffect())
		}
		if !strings.Contains(resp.GetReason(), "action tier INTERNAL_MODIFY exceeds delegation max_action_tier READ_ONLY") {
			t.Errorf("Reason = %q, want it to name the tier-ceiling denial", resp.GetReason())
		}
	})

	// proof1 is Phase 6's negative 1, closed: the identical delegation that
	// just denied read_file (proof4, above) now permits it, once -- and
	// only once -- a tool_catalog row exists for it.
	t.Run("proof1_cataloged_read_file_permits_under_read_only_delegation", func(t *testing.T) {
		if readOnlyDelegation == nil {
			t.Fatal("proof4_no_catalog_rows_unaffected_regression_guard must run before this subtest")
		}
		resourceField := "path"
		seedToolCatalogEntry(t, resourceTenant, "read_file", tierPtr(models.ActionTierReadOnly), "read", &resourceField, nil)

		resp := decide(t, readOnlyDelegation.ID, "read_file", `{"path":"/tmp/tool-catalog-proof/notes.txt"}`)
		t.Logf("Decide() for a READ_ONLY-cataloged read_file -> effect=%s derived_tier=%d",
			resp.GetEffect(), resp.GetDerivedTier())
		if resp.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Fatalf("Effect = %v, want EFFECT_ALLOW -- read_file is now cataloged READ_ONLY, at the "+
				"delegation's own ceiling; this is Phase 6 Task 4's negative 1, closed", resp.GetEffect())
		}
		if resp.GetDerivedTier() != int32(models.ActionTierReadOnly) {
			t.Errorf("DerivedTier = %d, want %d (READ_ONLY)", resp.GetDerivedTier(), models.ActionTierReadOnly)
		}
		if resp.GetDelegationEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Errorf("DelegationEffect = %v, want EFFECT_ALLOW", resp.GetDelegationEffect())
		}

		// Persisted, not just the RPC response: the closed loop this proof
		// claims should show up in the audit trail an operator would
		// actually read.
		rows := fetchAuditChain(t, resourceTenant)
		if len(rows) == 0 || rows[len(rows)-1].Decision != "ALLOW" {
			t.Fatalf("most recent audit row for resourceTenant, want Decision=ALLOW, got %+v", rows[len(rows)-1])
		}
	})

	// proof2: the same delegation, still capped at READ_ONLY, denies
	// write_file once it too is cataloged -- at INTERNAL_MODIFY, not
	// READ_ONLY. This is what proves the catalog ROW is doing the work: a
	// version of this phase that simply permitted every cataloged tool,
	// without deriving ITS OWN tier per row, would still pass proof1 above.
	t.Run("proof2_cataloged_write_file_denied_under_same_read_only_delegation", func(t *testing.T) {
		if readOnlyDelegation == nil {
			t.Fatal("proof4_no_catalog_rows_unaffected_regression_guard must run before this subtest")
		}
		resourceField := "path"
		seedToolCatalogEntry(t, resourceTenant, "write_file", tierPtr(models.ActionTierInternalModify), "write", &resourceField, nil)

		resp := decide(t, readOnlyDelegation.ID, "write_file", `{"path":"/tmp/tool-catalog-proof/report.txt","content":"hello"}`)
		t.Logf("Decide() for an INTERNAL_MODIFY-cataloged write_file under a READ_ONLY delegation -> "+
			"effect=%s derived_tier=%d reason=%q", resp.GetEffect(), resp.GetDerivedTier(), resp.GetReason())
		if resp.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Fatalf("Effect = %v, want EFFECT_DENY -- write_file is cataloged INTERNAL_MODIFY, above this "+
				"delegation's READ_ONLY ceiling; an ALLOW here would mean cataloging permits everything "+
				"regardless of its own declared tier", resp.GetEffect())
		}
		if resp.GetDerivedTier() != int32(models.ActionTierInternalModify) {
			t.Errorf("DerivedTier = %d, want %d (INTERNAL_MODIFY)", resp.GetDerivedTier(), models.ActionTierInternalModify)
		}
		if resp.GetDeniedLeg() != "delegation" {
			t.Errorf("DeniedLeg = %q, want %q", resp.GetDeniedLeg(), "delegation")
		}
		if resp.GetPrincipalEffect() != pdpgrpc.Effect_EFFECT_ALLOW || resp.GetAgentEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Errorf("PrincipalEffect/AgentEffect = %v/%v, want ALLOW/ALLOW (isolating the delegation leg)",
				resp.GetPrincipalEffect(), resp.GetAgentEffect())
		}
		if !strings.Contains(resp.GetReason(), "action tier INTERNAL_MODIFY exceeds delegation max_action_tier READ_ONLY") {
			t.Errorf("Reason = %q, want it to name the tier-ceiling denial", resp.GetReason())
		}
	})

	// proof3 is Phase 7 Task 4's Finding B, closed: a resource constraint can
	// now discriminate on the MCP surface at all, because "read_file"'s own
	// catalog row (seeded in proof1, above) names resource_field "path" --
	// the PDP extracts it from raw_input itself; nothing on the wire ever
	// carries a caller-supplied Resource (see decide's own doc comment).
	// Before this phase, mcp mode always sent an EMPTY resource map for a
	// third-party tool (cmd/stratium-pep/resource.go's resourceIDFields knew
	// only Claude Code's own tool names), so a ResourceConstraints entry
	// could never distinguish one MCP call from another -- it would simply
	// deny every one of them, unconditionally, on the constrained key's
	// absence from an always-empty resource map.
	t.Run("proof3_resource_constraint_discriminates_on_the_mcp_surface", func(t *testing.T) {
		const allowed = "/tmp/tool-catalog-proof/allowed.txt"
		const other = "/tmp/tool-catalog-proof/other.txt"
		constrained := newDelegation("proof3: resource constraint scoped via read_file's own catalog resource_field",
			models.ActionTierReadOnly, map[string]string{"id": allowed})

		matching := decide(t, constrained.ID, "read_file", `{"path":"`+allowed+`"}`)
		t.Logf("Decide() for read_file at its constrained path -> effect=%s", matching.GetEffect())
		if matching.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Fatalf("Effect = %v, want EFFECT_ALLOW (raw_input's own \"path\" matches the constraint)",
				matching.GetEffect())
		}

		mismatched := decide(t, constrained.ID, "read_file", `{"path":"`+other+`"}`)
		t.Logf("Decide() for read_file at a different path -> effect=%s denied_leg=%q reason=%q",
			mismatched.GetEffect(), mismatched.GetDeniedLeg(), mismatched.GetReason())
		if mismatched.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Fatalf("Effect = %v, want EFFECT_DENY (raw_input's own \"path\" does not match the constraint)",
				mismatched.GetEffect())
		}
		if mismatched.GetDeniedLeg() != "delegation" {
			t.Errorf("DeniedLeg = %q, want %q", mismatched.GetDeniedLeg(), "delegation")
		}
		if mismatched.GetPrincipalEffect() != pdpgrpc.Effect_EFFECT_ALLOW || mismatched.GetAgentEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Errorf("PrincipalEffect/AgentEffect = %v/%v, want ALLOW/ALLOW (isolating the delegation leg)",
				mismatched.GetPrincipalEffect(), mismatched.GetAgentEffect())
		}
		if !strings.Contains(mismatched.GetReason(), `does not match request value "`+other+`"`) {
			t.Errorf("Reason = %q, want it to name the mismatched value extracted from raw_input", mismatched.GetReason())
		}
	})
}

// TestIntegration_Live_ResourceLabelling is Phase 7 Task 3's live proof of
// resource labelling (spec §3.9.1): a tenant's own resource_label_rules rows
// decide a resource's classification, and the delegation's cap is enforced
// against that label over real gRPC, against a real PDP, with the audit rows
// read back from Postgres.
//
// Placed AFTER TestIntegration_Live_ToolCatalogEnforcement, and that is
// structural rather than cosmetic. Every proof here needs a tool with a
// tool_catalog row naming a resource_field, because a label may only ever be
// resolved against an id the PDP extracted for itself (R1/R4) -- and that
// test's proof4 asserts resourceTenant has ZERO catalog rows before it seeds
// any, which is its own counterfactual. So this test reuses the "read_file"
// row proof1 seeded there (READ_ONLY, resource_field "path") rather than
// seeding a second one earlier and breaking that assertion. There is no
// DeleteToolCatalogEntry to undo one with, by design (store/catalog.go).
//
// So proofs 1-3 DEPEND ON RESIDUE from another test, which this project
// otherwise removes on sight. Left deliberately, and it is the mild form:
// run in isolation the row is simply absent, read_file falls to BuiltinTier's
// unrecognized-means-it-modifies default, derives INTERNAL_MODIFY and exceeds
// these delegations' READ_ONLY ceiling -- so every assertion fails loudly on
// the tier, never passes falsely on a label that was not applied. Seeding the
// row here instead is what proof4's zero-rows assertion forbids, and fighting
// that fixture would trade a loud failure for a broken counterfactual.
// proof5 depends on no residue at all: it needs a tool with NO row.
func TestIntegration_Live_ResourceLabelling(t *testing.T) {
	const subject = "resource-labelling-proof@example.com"
	const secretPath = "/label-proof/secret/q3.pdf"
	const publicPath = "/label-proof/public/brochure.pdf"
	const unlabelledPath = "/label-proof-elsewhere/notes.txt"

	agentID := uuid.New()
	seedAgent(t, resourceTenant, agentID, "integration-agent-resource-labelling", models.TrustTierPlatformTrusted)

	// The rule set: a strict tree with a public carve-out inside it (R6's own
	// example), and nothing at all covering unlabelledPath.
	createRule(t, resourceTenant, classification.Rule{
		Prefix: "/label-proof/", Hierarchy: "nato", Level: "TOP-SECRET",
	})
	createRule(t, resourceTenant, classification.Rule{
		Prefix: "/label-proof/public/", Hierarchy: "nato", Level: "UNCLASSIFIED",
	})

	newDelegation := func(purpose string, caps map[string]string) *models.Delegation {
		id := uuid.New()
		return seedDelegation(t, &models.Delegation{
			ID: id, TenantID: resourceTenant, UserID: "integration-test-user", AgentID: agentID,
			ApprovedTools: []string{}, MaxActionTier: models.ActionTierReadOnly,
			ClassificationCaps: caps, Purpose: purpose, ExpiresAt: time.Now().Add(time.Hour),
			RootDelegationID: id, Depth: 0, ChainAgentIDs: []uuid.UUID{agentID},
		})
	}

	// resource is a parameter here, unlike TestIntegration_Live_ToolCatalog
	// Enforcement's own decide(), precisely so proof3 below can send a
	// competing caller-supplied id and prove it inert.
	decide := func(t *testing.T, delegationID uuid.UUID, rawInput string, resource map[string]string) *pdpgrpc.DecideResponse {
		t.Helper()
		resp, err := resourcePdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
			Token:    mintToken(t, resourcePdpClient, delegationID),
			AgentId:  agentID.String(),
			Subject:  subject,
			Tool:     "read_file",
			RawInput: rawInput,
			Resource: resource,
		})
		if err != nil {
			t.Fatalf("Decide() error = %v, want a decision", err)
		}
		return resp
	}

	// proof1: the headline. A tenant rule labels the resource TOP-SECRET, the
	// delegation caps nato at CONFIDENTIAL, and the decision denies naming
	// the level -- distinctly from the uncheckable denial an unmatched
	// resource gets, in the wire response AND the persisted audit row. This
	// carries the property that used to live in
	// TestIntegration_Live_ResourceIdentityEnforcement's proof3, moved here
	// because reaching the exceeds path now requires a server-extracted id.
	t.Run("proof1_label_enforces_the_cap_and_reads_differently_from_an_unlabelled_resource", func(t *testing.T) {
		d := newDelegation("label proof1: classification cap nato=CONFIDENTIAL", map[string]string{"nato": "CONFIDENTIAL"})
		before := fetchAuditChain(t, resourceTenant)

		exceeds := decide(t, d.ID, `{"path":"`+secretPath+`"}`, nil)
		t.Logf("Decide() for a TOP-SECRET-labelled resource under a CONFIDENTIAL cap -> effect=%s reason=%q",
			exceeds.GetEffect(), exceeds.GetReason())
		if exceeds.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Fatalf("Effect = %v, want EFFECT_DENY (TOP-SECRET exceeds a CONFIDENTIAL cap)", exceeds.GetEffect())
		}
		if exceeds.GetDeniedLeg() != "delegation" {
			t.Errorf("DeniedLeg = %q, want %q", exceeds.GetDeniedLeg(), "delegation")
		}
		if !strings.Contains(exceeds.GetReason(), "exceeds delegation cap") {
			t.Errorf("Reason = %q, want it to contain %q", exceeds.GetReason(), "exceeds delegation cap")
		}

		uncheckable := decide(t, d.ID, `{"path":"`+unlabelledPath+`"}`, nil)
		t.Logf("Decide() for a resource no rule labels -> effect=%s reason=%q",
			uncheckable.GetEffect(), uncheckable.GetReason())
		if uncheckable.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Fatalf("Effect = %v, want EFFECT_DENY: an unmatched resource is unlabelled and R2/R7 deny it "+
				"-- no default level, no fallback", uncheckable.GetEffect())
		}
		if !strings.Contains(uncheckable.GetReason(), "cannot be evaluated") {
			t.Errorf("Reason = %q, want the uncheckable-cap wording", uncheckable.GetReason())
		}
		if exceeds.GetReason() == uncheckable.GetReason() {
			t.Fatalf("the exceeds-cap and uncheckable-cap reasons must differ over the wire, both were %q",
				exceeds.GetReason())
		}

		after := fetchAuditChain(t, resourceTenant)
		newRows := after[len(before):]
		if len(newRows) != 2 {
			t.Fatalf("this subtest made 2 Decide() calls, want 2 new audit rows, got %d", len(newRows))
		}
		exceedsRow, uncheckableRow := newRows[0], newRows[1]
		t.Logf("audit rows: exceeds reason=%q uncheckable reason=%q", exceedsRow.Reason, uncheckableRow.Reason)
		if exceedsRow.Reason != exceeds.GetReason() || uncheckableRow.Reason != uncheckable.GetReason() {
			t.Errorf("audit row reasons = %q/%q, want the responses' own reasons %q/%q",
				exceedsRow.Reason, uncheckableRow.Reason, exceeds.GetReason(), uncheckable.GetReason())
		}
		if exceedsRow.Reason == uncheckableRow.Reason {
			t.Fatalf("the audit rows must distinguish the two denials, both were %q", exceedsRow.Reason)
		}
	})

	// proof2: R6's carve-out, live. The public subtree inside the secret one
	// is genuinely public, longest prefix wins, and the decision ALLOWS under
	// the same cap that denied proof1 -- the whole reason R6 departs from the
	// raise-only pattern.
	t.Run("proof2_lowering_carve_out_is_honoured", func(t *testing.T) {
		d := newDelegation("label proof2: classification cap nato=CONFIDENTIAL", map[string]string{"nato": "CONFIDENTIAL"})

		resp := decide(t, d.ID, `{"path":"`+publicPath+`"}`, nil)
		t.Logf("Decide() for a resource under the public carve-out -> effect=%s", resp.GetEffect())
		if resp.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Fatalf("Effect = %v (%q), want EFFECT_ALLOW: the longest matching prefix carves this subtree "+
				"down to UNCLASSIFIED, which is under the cap (R6)", resp.GetEffect(), resp.GetReason())
		}
		if resp.GetDelegationEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Errorf("DelegationEffect = %v, want EFFECT_ALLOW", resp.GetDelegationEffect())
		}
	})

	// proof3: the label follows the id the PDP extracted through read_file's
	// catalog row, and the wire's competing id is inert.
	//
	// Defence in depth, and credited as such rather than as C1's live proof,
	// which it cannot be: read_file IS catalogued, so ApplyExtraction has
	// already replaced the map with {"id": secretPath} before labelResource
	// runs. Under a full revert of the C1 fix, labelled["id"] IS the extracted
	// id, this still denies naming TOP-SECRET, and this subtest stays green.
	// Two independent mechanisms hold the property here and no single
	// mutation reaches it -- the same honest credit
	// TestDecide_CatalogedToolLabelsTheExtractedIDNotTheWireID carries at the
	// unit layer. C1's own case is proof5, below.
	//
	// The distinction matters because it is the defect that produced C1: R11
	// recorded a closure that was half true, and the closure sentence is what
	// stopped anyone looking further. A comment claiming a proof it cannot
	// carry does the same job.
	t.Run("proof3_the_caller_cannot_choose_which_rule_labels_it", func(t *testing.T) {
		d := newDelegation("label proof3: classification cap nato=CONFIDENTIAL", map[string]string{"nato": "CONFIDENTIAL"})

		resp := decide(t, d.ID, `{"path":"`+secretPath+`"}`, map[string]string{
			"id":             publicPath,     // the caller names the permissive rule
			"classification": "UNCLASSIFIED", // and, for good measure, the label itself
			"hierarchy":      "nato",
		})
		t.Logf("Decide() with raw_input naming the secret path and the wire naming the public one -> effect=%s reason=%q",
			resp.GetEffect(), resp.GetReason())
		if resp.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Fatalf("Effect = %v, want EFFECT_DENY: the label must follow the id the PDP extracted from "+
				"raw_input, never the one the caller sent", resp.GetEffect())
		}
		if !strings.Contains(resp.GetReason(), "TOP-SECRET") {
			t.Errorf("Reason = %q, want the extracted path's own TOP-SECRET label to have decided", resp.GetReason())
		}
	})

	// proof5: C1's own case, live -- an UNCATALOGUED tool, where the caller's
	// resource["id"] is a string it simply typed and nothing links it to
	// raw_input. "Read" has no tool_catalog row for this tenant (only
	// read_file and write_file do), so ExtractFromCatalog returns its zero
	// value and nothing may be labelled.
	//
	// The id names the PERMISSIVE rule seeded above, which is what makes this
	// a real proof rather than a restatement of proof1's unmatched case:
	// before the fix this resolved to UNCLASSIFIED and ALLOWED. Now the
	// resource is unlabelled and R2 denies it. Verified by mutation, live:
	// the full revert of the C1 fix turns this subtest green-to-red.
	t.Run("proof5_an_uncatalogued_tools_wire_id_labels_nothing", func(t *testing.T) {
		d := newDelegation("label proof5: classification cap nato=CONFIDENTIAL", map[string]string{"nato": "CONFIDENTIAL"})

		resp, err := resourcePdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
			Token:   mintToken(t, resourcePdpClient, d.ID),
			AgentId: agentID.String(),
			Subject: subject,
			Tool:    "Read", // deliberately NOT read_file: no catalog row for this tenant
			// The caller names the permissive carve-out, and would have been
			// labelled UNCLASSIFIED by it before the fix.
			Resource: map[string]string{"id": publicPath},
		})
		if err != nil {
			t.Fatalf("Decide() error = %v, want a decision", err)
		}
		t.Logf("Decide() for an uncatalogued tool whose caller named the public carve-out -> effect=%s reason=%q",
			resp.GetEffect(), resp.GetReason())
		if resp.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Fatalf("Effect = %v, want EFFECT_DENY: a caller-typed id is not an identity this PDP derived, "+
				"so no rule may label it -- naming the UNCLASSIFIED carve-out must not buy its label",
				resp.GetEffect())
		}
		if resp.GetDeniedLeg() != "delegation" {
			t.Errorf("DeniedLeg = %q, want %q", resp.GetDeniedLeg(), "delegation")
		}
		if !strings.Contains(resp.GetReason(), "cannot be evaluated") {
			t.Errorf("Reason = %q, want the uncheckable-cap wording: the resource is unlabelled, not labelled "+
				"from the caller's claim", resp.GetReason())
		}
	})

	// proof4: the regression guard, restated for this feature. A delegation
	// with no classification cap is unaffected by the rules entirely, even on
	// a resource labelled TOP-SECRET -- the boundary between shipping
	// labelling and shipping a change that denies more (R2's own narrowness).
	t.Run("proof4_uncapped_delegation_is_unaffected_by_the_rules", func(t *testing.T) {
		d := newDelegation("label proof4: no classification caps (regression guard)", nil)

		resp := decide(t, d.ID, `{"path":"`+secretPath+`"}`, nil)
		t.Logf("Decide() against an uncapped delegation on a TOP-SECRET resource -> effect=%s", resp.GetEffect())
		if resp.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Fatalf("Effect = %v (%q), want EFFECT_ALLOW: a delegation with no caps places no restriction "+
				"on this axis and never did", resp.GetEffect(), resp.GetReason())
		}
	})

	// proof6: R6's log line, in the DEPLOYED PDP's own stdout.
	//
	// Phase 7 Task 6. proof2 above already proves the carve-out is HONOURED
	// live, and internal/pdpgrpc/label_test.go already pins what the line
	// SAYS -- both rules' three fields, and no resource id -- over the real
	// Decide path. Neither can reach the one channel this does: whether the
	// shipped binary's own logger actually emits an Info record where an
	// operator can read it. cmd/stratium-pdp/main.go builds a TextHandler on
	// os.Stdout with nil options, so the level is Info by inheritance from a
	// nil field, and Docker has to be capturing that stream. Both are facts
	// about the deployment, not about labelling, and a unit test cannot
	// observe either.
	//
	// It is proven here because Task 6's operator documentation tells an
	// operator to grep their PDP log for this line. A negative claim about
	// what a system can observe is a claim to check, not to reason to -- and
	// a positive one directing an operator to look somewhere is the same
	// claim with the burden reversed.
	//
	// The absence half is scoped to THIS test's three ids, deliberately, and
	// not to "no path anywhere in the log". Only the scoped claim is this
	// test's to make: another proof against this same container may log an
	// id of its own for its own reasons, and a blanket assertion would fail
	// for a reason that has nothing to do with labelling. Scoped, it is still
	// the broader claim than label_test.go's -- that one proves logCarveOut
	// does not leak the id, this one proves nothing ELSE in the whole
	// deployed process did either, for the ids this test actually sent.
	t.Run("proof6_the_carve_out_line_reaches_the_deployed_pdps_own_log", func(t *testing.T) {
		d := newDelegation("label proof6: classification cap nato=CONFIDENTIAL", map[string]string{"nato": "CONFIDENTIAL"})

		resp := decide(t, d.ID, `{"path":"`+publicPath+`"}`, nil)
		if resp.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Fatalf("Effect = %v (%q), want EFFECT_ALLOW -- the line under test is emitted only when the "+
				"carve-out actually won, so this has to be the same allow proof2 gets", resp.GetEffect(), resp.GetReason())
		}

		// Both rules by prefix: the line's whole purpose is naming the pair,
		// and a line carrying only the winner would send an operator looking
		// for a row they cannot find.
		want := []string{
			"resource label carve-out lowers the classification it overrides",
			`rule_prefix=/label-proof/public/`,
			`overrides_prefix=/label-proof/`,
		}
		logs := awaitContainerLog(t, "pdp-resource", want)

		// R6's line is deliberately id-free (labelResource's own doc comment):
		// a resource id is derived from client-supplied raw_input and a process
		// log may be shipped somewhere the subject matter should not go.
		for _, id := range []string{secretPath, publicPath, unlabelledPath} {
			if strings.Contains(logs, id) {
				t.Errorf("the deployed PDP's log contains the resource id %q -- ids are attacker-influenced "+
					"content (§4.4.2 T2) and this log is shipped off-box", id)
			}
		}
	})
}

// awaitContainerLog returns the named compose service's captured stdout+stderr
// once every string in want appears in it, failing the test if they have not
// all arrived within the settle window.
//
// Polled rather than read once. slog's TextHandler writes each record in one
// Write and does not buffer, but nothing makes Docker's log driver expose that
// write to `docker logs` synchronously with the gRPC response this test
// already has in hand -- so a single read races the daemon, and a test that
// fails one run in fifty for that reason would be read as flakiness in
// labelling.
//
// The container is found by the label compose puts on everything it creates
// (com.docker.compose.service), not by a container name, a project name, or a
// published port. Those are all conventions this test would be guessing at;
// the label is Docker's own and is set by the same `docker compose up` the
// Makefile's integration target runs. Exactly one match is required, so a
// second stack on the host running a service of the same name fails loudly
// here rather than being silently read instead of ours.
func awaitContainerLog(t *testing.T, service string, want []string) string {
	t.Helper()

	out, err := exec.CommandContext(t.Context(), "docker", "ps", "--quiet",
		"--filter", "label=com.docker.compose.service="+service).Output()
	if err != nil {
		t.Fatalf("docker ps for compose service %q: %v -- this proof reads the deployed process's own "+
			"stdout, so it needs the same docker `make integration` already required", service, err)
	}
	ids := strings.Fields(string(out))
	if len(ids) != 1 {
		t.Fatalf("docker ps matched %d containers for compose service %q, want exactly 1 (%v)",
			len(ids), service, ids)
	}

	var logs string
	deadline := time.Now().Add(15 * time.Second)
	for {
		raw, err := exec.CommandContext(t.Context(), "docker", "logs", ids[0]).CombinedOutput()
		if err != nil {
			t.Fatalf("docker logs %s: %v", ids[0], err)
		}
		logs = string(raw)

		missing := make([]string, 0, len(want))
		for _, w := range want {
			if !strings.Contains(logs, w) {
				missing = append(missing, w)
			}
		}
		if len(missing) == 0 {
			return logs
		}
		if time.Now().After(deadline) {
			t.Fatalf("the deployed %s never logged %q -- R6's carve-out line is the operator's ONLY signal "+
				"that a carve-out is doing something, and the operator documentation sends them here to grep "+
				"for it", service, missing)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// Phase 9 Task 5 (docs/superpowers/sdd/2026-08-13-phase-9-tokens/
// task-5-brief.md): the five live-stack token proofs. Placed here,
// immediately after TestIntegration_Live_ToolCatalogEnforcement and before
// TestIntegration_Multi_OneEnginePrepareFailureDoesNotSuppressAnother/
// TestEndToEnd — not a new file — for a file-ordering reason that WAS real
// and no longer is. Go runs top-level tests within one file in declaration
// order and concatenates a package's files in filename order, and
// TestEndToEnd's own proof6 revokes the serving role's INSERT on audit_chain
// (role-level, not tenant-scoped — every tenant's Decide calls stop auditing
// while it is in effect). Until Phase 14 Task 8 that revoke was never
// restored, so a new file sorting after "store_integration_test.go" (e.g.
// "token_integration_test.go") would have registered its tests after it and
// broken every proof expecting an audited ALLOW/DENY.
//
// proof6 now restores both grants in a t.Cleanup and verifies they came back
// (restoreAuditChainInsert, bottom of this file), so the revoke lasts only
// for that subtest and NO FILENAME IN THIS PACKAGE IS LOAD-BEARING ANY MORE.
// Splitting these proofs into a file of their own is a free choice today,
// whatever it is called. They stay here only because moving them buys
// nothing; this paragraph exists so the next person to consider the split is
// not talked out of it by a constraint that has been deleted.
//
// TestIntegration_Live_TokenAuthentication proves proofs 1, 2, and 4 against
// the REAL containerized PDP (resourcePdpClient/resourceTenant) — the actual
// Dockerfile-baked signing key and main.go's real token.Load wiring, not a
// stand-in — because none of the three needs control over what key the
// server trusts. resourceTenant, not a fresh tenant: this test seeds its own
// agent, policy, and delegations, the same "safe to add to" discipline
// TestIntegration_Live_ToolCatalogEnforcement (above) already established
// for this exact tenant — see that test's own doc comment for why.
//
// TestIntegration_Live_TokenKeyRotation and
// TestIntegration_Live_TokenCrossTenantNotFound (proofs 3 and 5, below) do
// need control over which key a server trusts, which none of the three
// docker-compose services can give this process: their signing keys are
// generated fresh inside the image at build time and never reach this test
// (mintToken's own doc comment), and none is configured with a previous key
// (deploy/docker/docker-compose.yml only ever sets
// STRATIUM_TOKEN_SIGNING_KEY_PATH). Both use an in-process pdpgrpc.Server
// against real Postgres instead — the same tool
// escalation_integration_test.go's own banner already established as
// genuinely "live" for exactly this reason (only the transport differs, not
// the database, the schema, RLS, or the production Server.Decide/IssueToken
// code).
func TestIntegration_Live_TokenAuthentication(t *testing.T) {
	const subject = "token-auth-proof@example.com"

	agentID := uuid.New()
	seedAgent(t, resourceTenant, agentID, "integration-agent-token-auth", models.TrustTierPlatformTrusted)
	seedPolicy(t, resourceTenant, "permit-token-auth-proof", escalationBlanketPermit, "allow")

	// proof 1: session-start (CreateDelegation, which mints a token as its
	// last step — delegation.go) then hook (Decide, spending that token) —
	// end to end, over the real gRPC client, exactly the round trip a real
	// PEP performs.
	t.Run("session_start_then_hook_allows", func(t *testing.T) {
		createResp, err := resourcePdpClient.CreateDelegation(t.Context(), &pdpgrpc.CreateDelegationRequest{
			Subject: subject, AgentId: agentID.String(),
			RequestedScope: &pdpgrpc.RequestedScope{
				MaxActionTier: int32(models.ActionTierDestructive), Tools: []string{"Read"},
			},
			Purpose: "token auth proof: session-start mints a token", TtlSeconds: 3600,
		})
		if err != nil {
			t.Fatalf("CreateDelegation() (session-start) error = %v", err)
		}
		if createResp.GetToken() == "" {
			t.Fatal("CreateDelegation() token is empty")
		}
		if createResp.GetToken() == createResp.GetDelegationId() {
			t.Fatal("token equals the bare delegation id -- session-start must never hand out a bare id as a token")
		}

		// Tool is "Read" -- catalogued READ_ONLY by authz.DefaultCatalog, no
		// tool_catalog row involved (see TestIntegration_Live_
		// ResourceIdentityEnforcement's own comment on this exact tool) --
		// well under this delegation's DESTRUCTIVE ceiling either way.
		resp, err := resourcePdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
			Token: createResp.GetToken(), AgentId: agentID.String(), Subject: subject, Tool: "Read",
		})
		if err != nil {
			t.Fatalf("Decide() (hook) error = %v", err)
		}
		if resp.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Fatalf("Effect = %v, want EFFECT_ALLOW (reason %q)", resp.GetEffect(), resp.GetReason())
		}
	})

	// proof 1's second half: a denied call still denies for the same reason
	// it did before tokens existed. The tier-ceiling wording comes from
	// internal/authz/delegation.go's DelegationLeg, untouched by Phase 9 --
	// wrapping the delegation reference in a verified token changes nothing
	// about what that leg decides, only how the caller identified which
	// delegation to load.
	t.Run("denied_call_same_reason_as_before_tokens", func(t *testing.T) {
		id := uuid.New()
		lowCeiling := seedDelegation(t, &models.Delegation{
			ID: id, TenantID: resourceTenant, UserID: subject, AgentID: agentID,
			ApprovedTools: []string{}, MaxActionTier: models.ActionTierReadOnly,
			ClassificationCaps: map[string]string{}, ResourceConstraints: map[string]string{},
			Purpose: "token auth proof: denial reason unchanged by tokens", ExpiresAt: time.Now().Add(time.Hour),
			RootDelegationID: id, Depth: 0, ChainAgentIDs: []uuid.UUID{agentID},
		})

		// A deliberately fictitious tool name: guaranteed absent from both
		// authz.DefaultCatalog and this tenant's own tool_catalog rows (which
		// by now include "read_file"/"write_file" from
		// TestIntegration_Live_ToolCatalogEnforcement, above), so it falls to
		// BuiltinTier's own "unrecognized -> assume it modifies" default --
		// INTERNAL_MODIFY -- deterministically, independent of what any
		// earlier test in this file has cataloged. RawInput must be non-empty
		// for that default to apply at all: BuiltinTier only reaches
		// classifyInput's "unrecognized" fallback when there is a raw string
		// to classify (destructiveEvidence/haveRaw both require a.RawInput !=
		// "") -- an empty RawInput skips straight past it to the verb/floor
		// default (ActionTierReasoning), which this delegation's READ_ONLY
		// ceiling would not deny. "{}" matches none of tier.go's shell
		// patterns, the same non-match ToolCatalogEnforcement's own proof4
		// relies on for "read_file"'s JSON blob.
		resp, err := resourcePdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
			Token: mintToken(t, resourcePdpClient, lowCeiling.ID), AgentId: agentID.String(), Subject: subject,
			Tool: "Phase9TokenProofUncatalogedTool", RawInput: "{}",
		})
		if err != nil {
			t.Fatalf("Decide() error = %v", err)
		}
		if resp.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Fatalf("Effect = %v, want EFFECT_DENY", resp.GetEffect())
		}
		if resp.GetDeniedLeg() != "delegation" {
			t.Errorf("DeniedLeg = %q, want %q", resp.GetDeniedLeg(), "delegation")
		}
		const wantReason = "action tier INTERNAL_MODIFY exceeds delegation max_action_tier READ_ONLY at depth 0"
		if !strings.Contains(resp.GetReason(), wantReason) {
			t.Errorf("Reason = %q, want it to contain %q -- the exact tier-ceiling wording this system "+
				"produced before tokens existed", resp.GetReason(), wantReason)
		}
	})

	// proof 2 (K3): a token naming a REVOKED delegation is denied AT THE
	// DELEGATION LEG, not the token check -- the property that makes a token
	// a reference and not a capability. The token itself is completely
	// genuine (real signature, unexpired, well-formed, minted while the
	// delegation was still active); only the row's own Revoked flag,
	// discovered by the LoadChain call authentication success leads to, can
	// produce this denial. Two independent checks make this specific, not
	// just "denied somehow": Reason carries DelegationLeg's own exact
	// wording and does NOT mention "token", and the audit entry's
	// DelegationID is populated -- which only happens once LoadChain has
	// actually run (server.go's appendAudit), never on a pure
	// authentication failure.
	t.Run("token_naming_revoked_delegation_denies_at_delegation_leg", func(t *testing.T) {
		id := uuid.New()
		revocable := seedDelegation(t, &models.Delegation{
			ID: id, TenantID: resourceTenant, UserID: subject, AgentID: agentID,
			ApprovedTools: []string{}, MaxActionTier: models.ActionTierDestructive,
			ClassificationCaps: map[string]string{}, ResourceConstraints: map[string]string{},
			Purpose:          "token auth proof: K3 -- a token names a reference, not a capability",
			ExpiresAt:        time.Now().Add(time.Hour),
			RootDelegationID: id, Depth: 0, ChainAgentIDs: []uuid.UUID{agentID},
		})
		tok := mintToken(t, resourcePdpClient, revocable.ID) // minted while still active

		withTenantTx(t, resourceTenant, func(tx *sql.Tx) {
			res, err := tx.ExecContext(t.Context(), `UPDATE delegations SET revoked = true WHERE id = $1`, revocable.ID.String())
			if err != nil {
				t.Fatalf("revoke delegation: %v", err)
			}
			if n, err := res.RowsAffected(); err != nil || n != 1 {
				t.Fatalf("revoke delegation: RowsAffected = %d, err = %v, want 1, nil", n, err)
			}
		})

		resp, err := resourcePdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
			Token: tok, AgentId: agentID.String(), Subject: subject, Tool: "Read",
		})
		if err != nil {
			t.Fatalf("Decide() error = %v, want a decision", err)
		}
		if resp.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Fatalf("Effect = %v, want EFFECT_DENY", resp.GetEffect())
		}
		if resp.GetDeniedLeg() != "delegation" {
			t.Errorf("DeniedLeg = %q, want %q", resp.GetDeniedLeg(), "delegation")
		}
		if !strings.Contains(resp.GetReason(), "is revoked") {
			t.Errorf("Reason = %q, want DelegationLeg's own revocation wording (\"... is revoked\") -- "+
				"anything else means this was denied somewhere other than the real delegation-leg "+
				"re-evaluation", resp.GetReason())
		}
		if strings.Contains(resp.GetReason(), "token") {
			t.Errorf("Reason = %q, mentions \"token\" -- a revoked-delegation denial must come from "+
				"DelegationLeg, which knows nothing about tokens, not from authenticateToken", resp.GetReason())
		}

		rows := fetchAuditChain(t, resourceTenant)
		if len(rows) == 0 {
			t.Fatal("no audit rows for resourceTenant")
		}
		last := rows[len(rows)-1]
		if last.DelegationID == nil || *last.DelegationID != revocable.ID {
			t.Fatalf("audit entry DelegationID = %v, want %s -- proves LoadChain actually ran (a "+
				"token-authentication failure's audit row never has one)", last.DelegationID, revocable.ID)
		}
	})

	// proof 4 (K4): a request with no token is denied, and -- the proof the
	// phase exists for -- there is no bare-id fallback anywhere. Two
	// subcases: no token at all, and a REAL, well-formed, currently-active
	// delegation id sent bare, unwrapped, exactly the pre-K4 wire shape. The
	// second is the load-bearing one: it proves the fallback A10's attacker
	// would reach for (omit the token, send the id an old caller used to
	// send) is not merely absent from the happy path but actively rejected
	// even when the id it carries is genuine.
	t.Run("no_token_denies_and_bare_delegation_id_is_never_a_fallback", func(t *testing.T) {
		id := uuid.New()
		real := seedDelegation(t, &models.Delegation{
			ID: id, TenantID: resourceTenant, UserID: subject, AgentID: agentID,
			ApprovedTools: []string{}, MaxActionTier: models.ActionTierDestructive,
			ClassificationCaps: map[string]string{}, ResourceConstraints: map[string]string{},
			Purpose: "token auth proof: K4 -- no bare-id fallback", ExpiresAt: time.Now().Add(time.Hour),
			RootDelegationID: id, Depth: 0, ChainAgentIDs: []uuid.UUID{agentID},
		})

		t.Run("empty_token", func(t *testing.T) {
			resp, err := resourcePdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
				Token: "", AgentId: agentID.String(), Subject: subject, Tool: "Read",
			})
			if err != nil {
				t.Fatalf("Decide() error = %v, want a DENY decision, not an RPC error", err)
			}
			if resp.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
				t.Fatalf("Effect = %v, want EFFECT_DENY", resp.GetEffect())
			}
			if resp.GetReason() != "no token provided" {
				t.Errorf("Reason = %q, want %q", resp.GetReason(), "no token provided")
			}
		})

		t.Run("a_real_delegation_id_sent_bare_as_the_token", func(t *testing.T) {
			resp, err := resourcePdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
				Token: real.ID.String(), AgentId: agentID.String(), Subject: subject, Tool: "Read",
			})
			if err != nil {
				t.Fatalf("Decide() error = %v, want a DENY decision, not an RPC error", err)
			}
			if resp.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
				t.Fatalf("Effect = %v, want EFFECT_DENY -- a real delegation id must never authenticate "+
					"when sent bare, not wrapped in a signed token", resp.GetEffect())
			}
			if resp.GetDeniedLeg() != "delegation" {
				t.Errorf("DeniedLeg = %q, want %q", resp.GetDeniedLeg(), "delegation")
			}
			if !strings.Contains(resp.GetReason(), "malformed") {
				t.Errorf("Reason = %q, want it to name malformedness", resp.GetReason())
			}
		})
	})
}

// freshECKeyPath generates a fresh EC (P-256) private key and writes it as a
// PEM file inside a fresh t.TempDir(), returning the path rather than a
// loaded *token.Signer -- escalationSigner (escalation_integration_test.go,
// this file's sibling in the same package) already does that and is reused
// directly below wherever only a signer, not its path, is needed.
// TestIntegration_Live_TokenKeyRotation needs the path itself: the same key
// must be loadable two different ways -- alone, and as another signer's own
// previous key -- which only a path, not an already-loaded Signer, can do.
func freshECKeyPath(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate EC key: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal EC key: %v", err)
	}
	path := filepath.Join(t.TempDir(), "key.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// TestIntegration_Live_TokenKeyRotation is proof 3: a token signed by the
// previous key still verifies; one signed by an unrelated, never-loaded key
// does not (K1's rotation promise). See this section's own banner for why
// this needs an in-process server rather than one of the three
// docker-compose PDPs.
func TestIntegration_Live_TokenKeyRotation(t *testing.T) {
	const tenant = "tenant-token-rotation-integration"
	const subject = "token-rotation-proof@example.com"

	agentID := uuid.New()
	seedAgent(t, tenant, agentID, "token-rotation-agent", models.TrustTierPlatformTrusted)
	seedPolicy(t, tenant, "token-rotation-blanket-permit", escalationBlanketPermit, "allow")
	delegationID := uuid.New()
	delegation := seedDelegation(t, &models.Delegation{
		ID: delegationID, TenantID: tenant, UserID: subject, AgentID: agentID,
		ApprovedTools: []string{}, MaxActionTier: models.ActionTierDestructive,
		ClassificationCaps: map[string]string{}, ResourceConstraints: map[string]string{},
		Purpose: "token rotation proof", ExpiresAt: time.Now().Add(time.Hour),
		RootDelegationID: delegationID, Depth: 0, ChainAgentIDs: []uuid.UUID{agentID},
	})

	oldKeyPath := freshECKeyPath(t)
	newKeyPath := freshECKeyPath(t)
	oldSigner, err := token.Load(oldKeyPath, "")
	if err != nil {
		t.Fatalf("token.Load(old) = %v, want success", err)
	}
	tokenOld := escalationToken(t, oldSigner, delegation.ID)

	// current=new, previous=old -- the post-rotation shape: mount a new
	// current key, keep the old one loaded for verification only (K1).
	rotatedSigner, err := token.Load(newKeyPath, oldKeyPath)
	if err != nil {
		t.Fatalf("token.Load(new, old) = %v, want success", err)
	}
	repo := store.New(testDB, tenant)
	cfg := config.Config{TenantID: tenant, MaxDepth: 5, ApprovalTTL: time.Hour}
	rotatedServer := pdpgrpc.NewServer(repo, policy.NewMulti(repo, escalationRegistry()), cfg, rotatedSigner)

	decide := func(t *testing.T, srv *pdpgrpc.Server, tok string) *pdpgrpc.DecideResponse {
		t.Helper()
		resp, err := srv.Decide(t.Context(), &pdpgrpc.DecideRequest{
			Token: tok, AgentId: agentID.String(), Subject: subject, Tool: "Read",
		})
		if err != nil {
			t.Fatalf("Decide() error = %v, want a decision", err)
		}
		return resp
	}

	t.Run("previous_key_still_verifies", func(t *testing.T) {
		resp := decide(t, rotatedServer, tokenOld)
		if resp.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Fatalf("Effect = %v, want EFFECT_ALLOW (reason %q) -- a token signed moments before "+
				"rotation must still authenticate and reach the real three-leg evaluation",
				resp.GetEffect(), resp.GetReason())
		}

		// Independent double-check -- the same discipline Phase 9 Task 2/3
		// both learned the hard way (verifying and minting through the same
		// signer instance cannot tell "verified" apart from "verified
		// because it happened to be signed by current"). A SEPARATE server
		// trusting ONLY the new key, nothing to fall back to, must reject
		// this exact same token -- otherwise the ALLOW above would prove
		// nothing about the previous key specifically.
		currentOnlySigner, err := token.Load(newKeyPath, "")
		if err != nil {
			t.Fatalf("token.Load(new only) = %v, want success", err)
		}
		currentOnlyServer := pdpgrpc.NewServer(repo, policy.NewMulti(repo, escalationRegistry()), cfg, currentOnlySigner)
		resp2 := decide(t, currentOnlyServer, tokenOld)
		if resp2.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Fatalf("Effect = %v, want EFFECT_DENY: a signer trusting ONLY the new key must not accept "+
				"a token signed by the old one", resp2.GetEffect())
		}
		if !strings.Contains(resp2.GetReason(), "signature") {
			t.Errorf("Reason = %q, want it to name the signature specifically", resp2.GetReason())
		}
	})

	t.Run("unknown_key_denies", func(t *testing.T) {
		attacker := escalationSigner(t) // fresh, unrelated key -- never loaded by rotatedServer
		tokenUnknown := escalationToken(t, attacker, delegation.ID)
		resp := decide(t, rotatedServer, tokenUnknown)
		if resp.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Fatalf("Effect = %v, want EFFECT_DENY", resp.GetEffect())
		}
		if !strings.Contains(resp.GetReason(), "signature") {
			t.Errorf("Reason = %q, want it to name the signature specifically", resp.GetReason())
		}
	})
}

// TestIntegration_Live_TokenCrossTenantNotFound is proof 5: a token naming a
// real, live delegation in one tenant is NotFound -- an RPC error, never a
// denial -- when presented to a PDP configured for a different tenant. RLS
// is the only tenant boundary a token crosses
// (internal/pdpgrpc/authenticate.go's own doc comment: the token's own
// tenant_id claim is deliberately never read or compared at authentication
// time), so this has to be provable even when both tenants' PDPs trust the
// identical signing key -- which is the realistic deployment shape K2
// assumes (the PDP verifies; a shared key infrastructure with RLS as the
// sole tenant boundary) and exactly why both servers below share ONE
// *token.Signer rather than two independently generated ones: this proof
// must not depend on whether two docker-compose services' own
// independently-built keys happen to collide (see
// TestIntegration_Live_TokenKeyRotation's own doc comment for the identical
// caution about that file's own key material). With a shared signer,
// verification is guaranteed to succeed by construction, so a NotFound
// result can only come from LoadChain's own RLS scoping, never from an
// accident of which keys happened to match.
func TestIntegration_Live_TokenCrossTenantNotFound(t *testing.T) {
	const tenantOwning = "tenant-token-cross-owner-integration"
	const tenantForeign = "tenant-token-cross-foreign-integration"

	signer := escalationSigner(t) // shared by both servers below -- see doc comment

	ownerAgentID := uuid.New()
	seedAgent(t, tenantOwning, ownerAgentID, "cross-tenant-owner-agent", models.TrustTierPlatformTrusted)
	ownerDelegationID := uuid.New()
	ownerDelegation := seedDelegation(t, &models.Delegation{
		ID: ownerDelegationID, TenantID: tenantOwning, UserID: "owner@example.com", AgentID: ownerAgentID,
		ApprovedTools: []string{}, MaxActionTier: models.ActionTierDestructive,
		ClassificationCaps: map[string]string{}, ResourceConstraints: map[string]string{},
		Purpose: "cross-tenant proof: belongs to tenantOwning only", ExpiresAt: time.Now().Add(time.Hour),
		RootDelegationID: ownerDelegationID, Depth: 0, ChainAgentIDs: []uuid.UUID{ownerAgentID},
	})
	ownerToken := escalationToken(t, signer, ownerDelegation.ID)

	// A real agent seeded IN tenantForeign, deliberately: this proof is about
	// the DELEGATION being foreign, not the agent
	// (proof4_cross_tenant_agent_is_not_found, above, inside TestEndToEnd,
	// already covers the agent-is-foreign case) -- LoadAgent must succeed
	// here so the NotFound below is unambiguously LoadChain's own doing, not
	// an earlier short-circuit.
	foreignAgentID := uuid.New()
	seedAgent(t, tenantForeign, foreignAgentID, "cross-tenant-foreign-agent", models.TrustTierPlatformTrusted)

	foreignRepo := store.New(testDB, tenantForeign)
	foreignCfg := config.Config{TenantID: tenantForeign, MaxDepth: 5, ApprovalTTL: time.Hour}
	foreignServer := pdpgrpc.NewServer(foreignRepo, policy.NewMulti(foreignRepo, escalationRegistry()), foreignCfg, signer)

	before := fetchAuditChain(t, tenantForeign)
	resp, err := foreignServer.Decide(t.Context(), &pdpgrpc.DecideRequest{
		Token: ownerToken, AgentId: foreignAgentID.String(), Subject: "cross-tenant-subject@example.com", Tool: "Read",
	})
	if resp != nil {
		t.Fatalf("Decide() response = %+v, want nil", resp)
	}
	st := wantCode(t, err, codes.NotFound)
	t.Logf("Decide() for tenant %q's delegation, against a PDP configured for %q -> NotFound: %s",
		tenantOwning, tenantForeign, st.Message())

	after := fetchAuditChain(t, tenantForeign)
	if len(after) != len(before) {
		t.Errorf("audit rows for tenantForeign went from %d to %d, want unchanged -- NotFound is an RPC "+
			"error, not a denial, and must never be audited", len(before), len(after))
	}
}

// TestIntegration_Multi_OneEnginePrepareFailureDoesNotSuppressAnother is
// proof 4: a malformed XACML policy alongside a valid Cedar forbid. XACML's
// Prepare fails for the whole tenant (one malformed policy poisons that
// language's group — see policy.PolicyEngine.Prepare's own contract), but
// that failure must not take Cedar's own, independently-prepared verdict
// down with it: multiSet.Evaluate folds a per-language prepare failure into
// its own deny verdict (prepareFailureVerdict, multi.go) rather than
// aborting the whole call. Calls Multi.Evaluate directly — the exact method
// pdpgrpc.Server.Decide itself calls — so this exercises the real
// production path, not a hand-rolled PrepareAll+Evaluate substitute.
func TestIntegration_Multi_OneEnginePrepareFailureDoesNotSuppressAnother(t *testing.T) {
	const tenant = "tenant-multilang-partial-prepare-fail-integration"
	const purpose = "partial prepare failure proof"

	cedarID := seedPolicyLang(t, tenant, "partial-fail-cedar-forbid", "cedar",
		fmt.Sprintf(`forbid(principal, action, resource) when { context.delegation.purpose == %q };`, purpose), "deny")
	// Malformed: an unclosed tag, the same "a syntax error is a syntax error
	// in any language" shape xacml/engine_test.go's own Fixtures.Malformed
	// uses — enough to fail Prepare, not merely Validate.
	seedPolicyLang(t, tenant, "partial-fail-xacml-malformed", "xacml",
		`<Policy PolicyId="broken" RuleCombiningAlgId="urn:oasis:names:tc:xacml:1.0:rule-combining-algorithm:deny-overrides">
  <Rule RuleId="r1" Effect="Permit"`, "deny")

	multi := policy.NewMulti(store.New(testDB, tenant), fullRegistry())
	verdicts := multi.Evaluate(t.Context(), policy.EvaluationInput{
		Delegation: policy.DelegationContext{Purpose: purpose},
	})
	t.Logf("Evaluate() with a malformed xacml policy alongside a valid cedar forbid -> %+v", verdicts)

	if len(verdicts) != 2 {
		t.Fatalf("got %d verdicts, want 2 (cedar's forbid AND xacml's prepare-failure deny — "+
			"one engine's failure must not suppress the other's verdict)", len(verdicts))
	}
	var sawCedar, sawXACML bool
	for _, v := range verdicts {
		if v.Effect != authz.EffectDeny {
			t.Errorf("verdict %+v: Effect = %v, want EffectDeny", v, v.Effect)
		}
		switch v.Source {
		case "cedar":
			sawCedar = true
			if v.PolicyID != cedarID {
				t.Errorf("cedar verdict PolicyID = %q, want %q", v.PolicyID, cedarID)
			}
		case "xacml":
			sawXACML = true
			if !strings.Contains(v.Reason, "xacml") {
				t.Errorf("xacml verdict Reason = %q, want it to name xacml", v.Reason)
			}
		}
	}
	if !sawCedar {
		t.Error("no verdict from cedar — its valid forbid must still appear despite xacml's prepare failure")
	}
	if !sawXACML {
		t.Error("no verdict from xacml — its prepare failure must still surface as a deny verdict, not vanish silently")
	}
}

// TestIntegration_Multi_CrossTenantIsolationAcrossLanguages is proof 6:
// tenantA and tenantB both hold a policy for the SAME subject
// ("laura@example.com"), in different languages, deliberately — if RLS ever
// leaked tenant B's rows into tenant A's LoadAllPolicies, tenant B's cedar
// forbid would join tenant A's fold and flip its verdict list from a single
// rego allow to an additional cedar deny, which is exactly the
// discriminating signal this proof relies on (the same "same identifiers
// across a tenant boundary" logic TestEndToEnd's own proof4/proof5/proof14
// already use for cross-tenant checks, applied here across two different
// policy languages instead of within one, and via policy.Multi.Evaluate
// directly rather than pdpClient — see this file's own "Phase 4 Task 6"
// banner above for why pdpClient cannot reach a second tenant at all).
// LoadAllPolicies is checked first, at the data layer — the exact seam
// policy.Multi's own isolation depends on — before the same property is
// confirmed one layer up, through Multi.Evaluate itself, which is what a
// real Decide call for either tenant would actually consult.
func TestIntegration_Multi_CrossTenantIsolationAcrossLanguages(t *testing.T) {
	const tenantA = "tenant-multilang-cross-a-integration"
	const tenantB = "tenant-multilang-cross-b-integration"
	const subject = "laura@example.com"

	regoAllowID := seedPolicyLang(t, tenantA, "laura-a-rego-allow", "rego", fmt.Sprintf(`package stratium.policy

allow if {
	input.principal.subject == %q
}`, subject), "allow")
	cedarForbidID := seedPolicy(t, tenantB, "laura-b-cedar-forbid",
		fmt.Sprintf(`forbid(principal == User::"%s", action, resource);`, subject), "deny")

	polsA, err := store.New(testDB, tenantA).LoadAllPolicies(t.Context())
	if err != nil {
		t.Fatalf("LoadAllPolicies(tenantA) error = %v", err)
	}
	if len(polsA) != 1 || polsA[0].ID != regoAllowID {
		t.Fatalf("LoadAllPolicies(tenantA) = %+v, want exactly tenant A's own rego policy (%s), never tenant B's", polsA, regoAllowID)
	}
	polsB, err := store.New(testDB, tenantB).LoadAllPolicies(t.Context())
	if err != nil {
		t.Fatalf("LoadAllPolicies(tenantB) error = %v", err)
	}
	if len(polsB) != 1 || polsB[0].ID != cedarForbidID {
		t.Fatalf("LoadAllPolicies(tenantB) = %+v, want exactly tenant B's own cedar policy (%s), never tenant A's", polsB, cedarForbidID)
	}

	// The decisive check, one layer up: evaluate exactly the same way a
	// real Decide call would (policy.Multi.Evaluate, the method
	// pdpgrpc.Server.Decide itself calls) for the SAME subject in both
	// tenants. If tenant B's cedar forbid ever leaked into tenant A's fold,
	// tenant A would report two verdicts instead of one; if tenant A's rego
	// allow ever leaked into tenant B's, tenant B would report a spurious
	// allow verdict alongside its own forbid.
	verdictsA := policy.NewMulti(store.New(testDB, tenantA), fullRegistry()).
		Evaluate(t.Context(), policy.EvaluationInput{Principal: authz.Principal{Subject: subject}})
	t.Logf("tenant A Evaluate() -> %+v", verdictsA)
	if len(verdictsA) != 1 || verdictsA[0].Source != "rego" || verdictsA[0].PolicyID != regoAllowID || verdictsA[0].Effect != authz.EffectAllow {
		t.Errorf("tenant A verdicts = %+v, want exactly [{rego %s Allow}] — tenant B's cedar forbid must never appear here",
			verdictsA, regoAllowID)
	}

	verdictsB := policy.NewMulti(store.New(testDB, tenantB), fullRegistry()).
		Evaluate(t.Context(), policy.EvaluationInput{Principal: authz.Principal{Subject: subject}})
	t.Logf("tenant B Evaluate() -> %+v", verdictsB)
	if len(verdictsB) != 1 || verdictsB[0].Source != "cedar" || verdictsB[0].PolicyID != cedarForbidID || verdictsB[0].Effect != authz.EffectDeny {
		t.Errorf("tenant B verdicts = %+v, want exactly [{cedar %s Deny}] — tenant A's rego allow must never appear here",
			verdictsB, cedarForbidID)
	}
}

// TestEndToEnd runs the six proofs, in the brief's own order, plus the
// Phase 2a Task 1 concurrency measurements: a single-call latency baseline,
// the ten-way same-tenant burst (now expected 10/0 under the per-tenant
// advisory lock — see audit.go), and a two-tenant check that the lock does
// not serialize unrelated tenants against each other. Subtests run
// sequentially (never t.Parallel()) because later ones depend on earlier
// state: proof 3 needs proof 2's decision already written; the concurrency
// measurements need proof 2's fixture already seeded; proof 6 deliberately
// revokes the application role's INSERT privilege on audit_chain, so it runs
// after every subtest that needs to append one. That revoke is no longer
// permanent — proof 6 restores both grants in a t.Cleanup and verifies they
// came back (restoreAuditChainInsert, bottom of this file); it used to be
// left in place for the life of the process, on the mistaken belief that
// this subtest "runs last" in the package rather than merely last in this
// function. See proof 6's own comment.
//
// Phase 2b Task 4 adds two more, both placed after the concurrency
// measurements (so every "ordinary" proof has already run against the real
// schema before anything riskier happens) and before proof6 (which needs to
// stay last): "audit_row_provenance_matches_response", the strongest
// assertion in this file — it reads the audit row back with its own query
// and compares stored values against what proof2's response actually
// returned, the specific check that would have caught Task 2/3's seam
// defect — and "chain_verifies_across_the_migration_boundary", which
// migrates the live schema down and back up mid-run and so is the one
// subtest that structurally depends on strict sequencing rather than merely
// benefiting from it.
//
// Phase 2c Task 5 adds proof7_cedar_permit_allows_principal_leg,
// cedar_permit_audit_row_matches_response, proof8_cedar_forbid_denies_
// attributed_to_policy, and proof9_cedar_permit_cannot_exceed_delegation_
// ceiling, placed after proof5 and before single_decide_latency_baseline —
// see the package doc for why that position matters (it is what makes the
// latency/concurrency measurements reflect Cedar actually doing work, not a
// zero-policy tenant). Each seeds a dedicated agent, delegation, and
// principal rather than reusing alice's — alice's fixture is what proof2's
// "zero cedar policies" assertion and every measurement after it depend on,
// so nothing about her decisions may change once these subtests seed
// policies for the tenant.
//
// Phase 2d Task 5 (docs/superpowers/sdd/2026-08-10-phase-2d-delegation-gate)
// closes spec defect D3 and adds proof10-proof14, exercising
// PDPService.CreateDelegation — the delegation-creation policy gate — end to
// end for the first time: a clamped grant with removals (proof10), the
// persisted row matching the response field by field (proof11), a Decide
// call against the freshly-created delegation confirming the clamp and the
// runtime ceiling agree (proof12), the audit chain carrying both a creation
// and a decision entry through one verified hash chain (proof13), and
// cross-tenant creation rejected by RLS (proof14). Placed after
// appendaudit_lock_is_per_tenant_not_global and before
// chain_verifies_across_the_migration_boundary: every "ordinary" proof has
// by then already run against the real schema (same reasoning Phase 2b Task
// 4 used for its own placement), and CreateDelegation's own audit step needs
// INSERT on audit_chain, which proof6 revokes for the duration of its own
// subtest — so these run before proof6. That is ordering by convention now,
// not by structure: since Phase 14 Task 8 proof6 restores both grants in a
// t.Cleanup (restoreAuditChainInsert), so a subtest declared after it would
// audit normally too.
//
// CreateDelegation's own INSERT into delegations surfaced a grant gap
// identical in kind to the one 000007_policies_serving_grant.up.sql fixed
// for policies (see that migration's own doc comment): 000005_serving_app_
// grants granted the serving role SELECT only, never INSERT, because
// delegations had no writer until now. migrations/000008_delegations_
// serving_grant.up.sql is the fix — found by this task's own run against a
// real Postgres, exactly as 000007's gap was.
//
// Phase 4 Task 6 (docs/superpowers/sdd/2026-08-11-phase-4-policy-engines/
// task-6-brief.md) adds two more groups of subtests here, not as their own
// top-level functions, and not by coincidence: this file's shared
// docker-compose PDP (what pdpClient talks to) is permanently scoped to
// configuredTenant (main.go fixes cfg.TenantID once at startup), so any
// proof needing a real audit row or a real CreateDelegation RPC can only
// ever run against configuredTenant — which means it can only safely run
// inside this one sequential chain, at a position after whatever earlier
// state it depends on and before proof6's irreversible privilege
// revocation. (This file's own "Phase 4 Task 6" banner above, before this
// function, covers the other four of the six proofs — the ones that build
// policy.Multi directly and so have no such constraint.)
//
//   - proof_multilang_cedar_permit_and_rego_forbid_denies_attributed_to_rego,
//     decide_latency_with_all_four_engines_in_path, and
//     decide_concurrency_with_all_four_engines_in_path are placed after
//     appendaudit_lock_is_per_tenant_not_global and before proof10: after,
//     so seeding heidi's and ivan's policies cannot affect
//     single_decide_latency_baseline or measured_concurrent_decide_split_
//     on_the_same_tail, both of which must stay directly comparable to
//     Phase 2c's own Cedar-only figures; before, because proof10-14 are one
//     tightly sequential unit around delegationGateResp/
//     delegationGateAgentID that must not be split.
//   - The rego-only delegation-creation clamp is placed after proof14 and
//     before chain_verifies_across_the_migration_boundary: after, so it
//     does not disturb frank's own shared state; before the migration
//     dance and proof6's revocation, since it needs both a working
//     CreateDelegation and a working Decide.
//
// heidi, ivan, and gina are principals not reused by any earlier or later
// subtest in this file, so their policies cannot match, and cannot be
// matched by, anyone else's — the same discipline frank's own doc comment
// states for proof10-14.
func TestEndToEnd(t *testing.T) {
	agentID := uuid.New()
	seedAgent(t, configuredTenant, agentID, "integration-agent-tenant-one", models.TrustTierUnverified)
	_, acting := twoHopChain(t, configuredTenant, agentID)
	// Minted once, up front, and reused by every subtest below that shares
	// this outer `acting` (proof2, proof4, the two latency/concurrency
	// measurements, and proof6): the two measurement subtests need a token
	// already in hand so what they time is one Decide call, not a Decide
	// call plus an extra IssueToken round trip, and
	// measured_concurrent_decide_split_on_the_same_tail fires this from ten
	// goroutines at once, where a fresh per-call mintToken (which calls
	// t.Fatalf on failure) would be unsafe — testing.T's own contract
	// requires FailNow to run only on the goroutine executing the test.
	actingToken := mintToken(t, pdpClient, acting.ID)

	// Set by single_decide_latency_baseline, read by
	// measured_concurrent_decide_split_on_the_same_tail — both subtests run
	// sequentially in the same TestEndToEnd, so this ordinary local variable
	// is enough to carry the measurement across them without a package-level
	// var.
	var baselineLatency time.Duration

	// Set by decide_latency_with_all_four_engines_in_path, read by
	// decide_concurrency_with_all_four_engines_in_path — same reasoning as
	// baselineLatency above, for Task 6's own multi-engine measurement.
	var fourEngineLatency time.Duration

	// Set by proof2, read by audit_row_provenance_matches_response — same
	// reasoning as baselineLatency above.
	var proof2Resp *pdpgrpc.DecideResponse

	// Set by proof7_cedar_permit_allows_principal_leg, read by
	// cedar_permit_audit_row_matches_response — same reasoning as
	// proof2Resp above. proof7PolicyID is the seeded policy's own id (the
	// ground truth from the seeding side); proof7Resp is what the server
	// actually returned — audit_row_matches_response compares the stored
	// audit row against proof7Resp specifically, not against proof7PolicyID
	// directly, so that check is a genuine stored-vs-returned comparison,
	// not stored-vs-seeded-twice.
	var proof7Resp *pdpgrpc.DecideResponse
	var proof7PolicyID string

	// Set by proof10_create_delegation_clamps_request_to_principal_authority,
	// read by proof11-13 — same reasoning as proof2Resp above.
	// delegationGateAgentID is the agent the delegation was issued to (needed
	// again by proof12's Decide call, which is a separate RPC); delegationGateResp
	// is what CreateDelegation actually returned.
	var delegationGateAgentID uuid.UUID
	var delegationGateResp *pdpgrpc.CreateDelegationResponse

	t.Run("proof1_migrations_applied_from_pdp_own_startup", func(t *testing.T) {
		// This test never calls migrations.Up() itself — by the time
		// TestMain's health check returned SERVING, the PDP container had
		// already run it from main.go's normal startup path (migrations.Up
		// happens before net.Listen; see cmd/stratium-pdp/main.go). This
		// subtest only OBSERVES the result of that run.
		var version int64
		var dirty bool
		row := testDB.QueryRowContext(t.Context(), `SELECT version, dirty FROM schema_migrations`)
		if err := row.Scan(&version, &dirty); err != nil {
			t.Fatalf("read schema_migrations: %v", err)
		}
		t.Logf("schema_migrations: version=%d dirty=%t", version, dirty)
		if dirty {
			t.Fatalf("schema_migrations.dirty = true, want false")
		}
		if version < 4 {
			t.Fatalf("schema_migrations.version = %d, want >= 4", version)
		}

		wantTables := []string{"agents", "delegations", "policies", "entitlements",
			"tier_overrides", "tenant_epoch", "audit_chain", "schema_migrations"}
		for _, table := range wantTables {
			var exists bool
			err := testDB.QueryRowContext(t.Context(),
				`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema='public' AND table_name=$1)`,
				table).Scan(&exists)
			if err != nil {
				t.Fatalf("check table %s exists: %v", table, err)
			}
			if !exists {
				t.Errorf("table %q does not exist after migrations", table)
			}
		}
		t.Logf("all %d expected tables present", len(wantTables))
	})

	t.Run("proof2_decide_denies_at_principal_leg", func(t *testing.T) {
		resp, err := pdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
			Token:   actingToken,
			AgentId: agentID.String(),
			Subject: "alice@example.com",
			Tool:    "Bash",
		})
		if err != nil {
			t.Fatalf("Decide() error = %v, want a decision", err)
		}
		t.Logf("Decide() -> effect=%s denied_leg=%q reason=%q principal_reason=%q agent_effect=%s delegation_effect=%s "+
			"decided_source=%q (present=%t) decided_policy_id=%q (present=%t)",
			resp.GetEffect(), resp.GetDeniedLeg(), resp.GetReason(), resp.GetPrincipalReason(),
			resp.GetAgentEffect(), resp.GetDelegationEffect(),
			resp.GetDecidedSource(), resp.DecidedSource != nil, resp.GetDecidedPolicyId(), resp.DecidedPolicyId != nil)

		if resp.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Errorf("Effect = %v, want EFFECT_DENY", resp.GetEffect())
		}
		if resp.GetDeniedLeg() != "principal" {
			t.Errorf("DeniedLeg = %q, want %q", resp.GetDeniedLeg(), "principal")
		}
		if resp.GetPrincipalReason() != noPoliciesReason {
			t.Errorf("PrincipalReason = %q, want %q", resp.GetPrincipalReason(), noPoliciesReason)
		}
		// decided_source/decided_policy_id are proto3 optional (*string):
		// nil would mean "no verdict decided this at all" (an empty
		// PrincipalVerdicts slice — see toResponse's own doc comment).
		// policy.Multi, with zero policies stored for this tenant in any
		// language, still returns exactly one verdict (see multiSet.
		// Evaluate's own doc comment on why — the same "exactly one, not
		// zero" discipline Unconfigured established), so both fields must
		// be present here, not merely equal to the zero value a nil
		// pointer's Get accessor would also produce.
		if resp.DecidedSource == nil {
			t.Error("DecidedSource = nil, want present (a real verdict decided this)")
		} else if *resp.DecidedSource != "none" {
			t.Errorf("DecidedSource = %q, want %q (no policies in any language means no engine's Prepare was even invoked — see policy.Multi's own doc comment on why this differs from Configured's single-language \"cedar\")", *resp.DecidedSource, "none")
		}
		if resp.DecidedPolicyId == nil {
			t.Error("DecidedPolicyId = nil, want present (an empty string, not absent)")
		} else if *resp.DecidedPolicyId != "" {
			t.Errorf("DecidedPolicyId = %q, want %q (no cedar policy exists yet to name)", *resp.DecidedPolicyId, "")
		}
		// The agent and delegation legs were seeded to independently allow
		// (see twoHopChain) — confirming the DENY really is attributable to
		// principal alone, not a side effect of a different leg also
		// denying and racing it for attribution.
		if resp.GetAgentEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Errorf("AgentEffect = %v, want EFFECT_ALLOW (fixture is well-formed on this leg)", resp.GetAgentEffect())
		}
		if resp.GetDelegationEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Errorf("DelegationEffect = %v, want EFFECT_ALLOW (fixture is well-formed on this leg)", resp.GetDelegationEffect())
		}

		proof2Resp = resp
	})

	t.Run("proof3_audit_row_written_and_chain_verifies", func(t *testing.T) {
		entries := fetchAuditChain(t, configuredTenant)
		t.Logf("audit_chain for %q has %d entr(y/ies) after one Decide call", configuredTenant, len(entries))
		if len(entries) != 1 {
			t.Fatalf("len(entries) = %d, want 1 (one Decide call so far)", len(entries))
		}

		got := entries[0]
		if got.Decision != "DENY" || got.DeniedLeg != "principal" {
			t.Errorf("audit entry decision=%q denied_leg=%q, want DENY/principal", got.Decision, got.DeniedLeg)
		}
		if got.DelegationID == nil || *got.DelegationID != acting.ID {
			t.Errorf("audit entry DelegationID = %v, want %s", got.DelegationID, acting.ID)
		}
		if got.AgentID == nil || *got.AgentID != agentID {
			t.Errorf("audit entry AgentID = %v, want %s", got.AgentID, agentID)
		}

		if err := audit.Verify(entries); err != nil {
			t.Fatalf("audit.Verify() error = %v, want nil", err)
		}
		t.Logf("audit.Verify() passed over the tenant's full %d-entry chain", len(entries))
	})

	// audit_row_provenance_matches_response is the specific check that would
	// have caught Task 2/3's seam defect. Task 2 added PolicySource/PolicyID
	// to audit.Entry, the migration, and store.AppendAudit's carrying of
	// them; every one of its tests passed because they all tested the
	// plumbing — the field exists, Hash() covers it, the column is present,
	// a chain with provenance verifies. None of them tested that a real
	// Decide call's verdict actually reached the column, because
	// server.go's appendAudit never read Result.Deciding at all — every real
	// decision would have written NULL forever, silently, into an
	// append-only table. This reads the row back with its own query,
	// independent of proof2's in-memory resp, and compares stored bytes
	// against returned bytes — the assertion that closes that gap.
	t.Run("audit_row_provenance_matches_response", func(t *testing.T) {
		if proof2Resp == nil {
			t.Fatal("proof2Resp is nil: proof2_decide_denies_at_principal_leg must run before this subtest")
		}

		entries := fetchAuditChain(t, configuredTenant)
		if len(entries) != 1 {
			t.Fatalf("len(entries) = %d, want 1", len(entries))
		}
		got := entries[0]

		wantSource, wantPolicyID := proof2Resp.GetDecidedSource(), proof2Resp.GetDecidedPolicyId()
		t.Logf("response vs stored row: response decided_source=%q decided_policy_id=%q; stored policy_source=%q policy_id=%q",
			wantSource, wantPolicyID, got.PolicySource, got.PolicyID)
		if got.PolicySource != wantSource {
			t.Errorf("stored policy_source = %q, want %q (the response's decided_source)", got.PolicySource, wantSource)
		}
		if got.PolicyID != wantPolicyID {
			t.Errorf("stored policy_id = %q, want %q (the response's decided_policy_id)", got.PolicyID, wantPolicyID)
		}
		if got.PolicySource != "none" {
			t.Errorf("stored policy_source = %q, want %q (this tenant has no policies in any language yet, so no engine's Prepare was invoked)", got.PolicySource, "none")
		}

		// The comparison above goes through audit.Entry's plain string
		// fields, which cannot tell "stored as ''" apart from "stored as
		// NULL" — fetchAuditChain deliberately decodes both to the same
		// zero value (that collapse is what keeps Hash() reproducible
		// across the migration boundary; see the migration-boundary
		// subtest below). That would hide the exact Task 2/3 defect: a
		// column that is always NULL looks byte-for-byte identical, at
		// this layer, to one that is legitimately empty. Read the raw
		// column nullness directly instead — this is the "confirm NOT
		// NULL in practice" check nobody had done before.
		source, policyID := auditRowProvenance(t, configuredTenant)
		t.Logf("raw column check: policy_source IS NOT NULL=%t value=%q, policy_id IS NOT NULL=%t value=%q",
			source.Valid, source.String, policyID.Valid, policyID.String)
		if !source.Valid {
			t.Error("policy_source IS NULL, want NOT NULL — a real decision must populate it")
		}
		if !policyID.Valid {
			t.Error("policy_id IS NULL, want NOT NULL (present, even though empty for Unconfigured()) — " +
				"a real decision must populate it")
		}
		if source.String == "" {
			t.Error(`policy_source stored as empty string, want a non-empty value ("none") for a real decision`)
		}
	})

	t.Run("proof4_cross_tenant_agent_is_not_found", func(t *testing.T) {
		otherAgentID := uuid.New()
		seedAgent(t, secondTenantID, otherAgentID, "integration-agent-tenant-two", models.TrustTierUnverified)

		// The token need not name anything related to otherAgentID: as of
		// Phase 9 Task 3, authentication (verifying the token and reading
		// the delegation id it names) runs BEFORE LoadAgent in Decide (see
		// pdpgrpc/server.go's own comment on that ordering) — the reverse of
		// this proof's pre-Task-3 premise, when a bare, unverified
		// delegation_id cost nothing to check and LoadAgent ran first. A
		// well-formed, VALID token is now a prerequisite for reaching
		// LoadAgent at all, so actingToken (this tenant's own, already
		// proven-valid token, reused from proof2 — it is unrelated to
		// otherAgentID and does not need to be) is what lets this call get
		// far enough to hit the real assertion: an agent unknown to THIS
		// tenant short-circuits at LoadAgent, before the delegation the
		// token names is ever looked up.
		resp, err := pdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
			Token:   actingToken,
			AgentId: otherAgentID.String(),
			Subject: "mallory@example.com",
			Tool:    "Bash",
		})
		if resp != nil {
			t.Fatalf("Decide() response = %+v, want nil", resp)
		}
		st := wantCode(t, err, codes.NotFound)
		t.Logf("Decide() for tenant %q's agent, against a PDP configured for %q -> NotFound: %s",
			secondTenantID, configuredTenant, st.Message())
	})

	t.Run("proof5_cross_tenant_chain_rejected_by_validatechain", func(t *testing.T) {
		otherAgentID := uuid.New()
		seedAgent(t, secondTenantID, otherAgentID, "integration-agent-tenant-two-chain", models.TrustTierUnverified)
		rootID := uuid.New()
		foreignRoot := seedDelegation(t, &models.Delegation{
			ID: rootID, TenantID: secondTenantID, UserID: "integration-test-user", AgentID: otherAgentID,
			ApprovedTools: []string{}, MaxActionTier: models.ActionTierInternalModify,
			ClassificationCaps: map[string]string{}, ResourceConstraints: map[string]string{},
			Purpose: "integration test: belongs to tenant two", ExpiresAt: time.Now().UTC().Add(time.Hour),
			RootDelegationID: rootID, Depth: 0, ChainAgentIDs: []uuid.UUID{otherAgentID},
		})

		// A successful INSERT above, gated by RLS's WITH CHECK, already
		// proves this row is really persisted under tenant_id=secondTenantID
		// — reused here directly rather than read back, since a fresh SELECT
		// would only reconfirm what the write already guaranteed. This is
		// authz.ValidateChain's own defense-in-depth tenant check (see that
		// function's doc comment): the same property proof 4 established via
		// RLS, exercised here as the second, independent layer that a
		// caller assembling a chain without going through the RLS-scoped
		// store.LoadChain — a batch job, a cache, Phase 2's token-claim
		// derivation — would still be caught by.
		err := authz.ValidateChain([]*models.Delegation{foreignRoot}, configuredTenant, otherAgentID)
		if err == nil {
			t.Fatal("ValidateChain() error = nil, want ErrChainInvalid")
		}
		if !errors.Is(err, authz.ErrChainInvalid) {
			t.Fatalf("ValidateChain() error = %v, want errors.Is(_, ErrChainInvalid)", err)
		}
		t.Logf("ValidateChain(tenant-two's chain, expected tenant=%q) -> %v", configuredTenant, err)
	})

	// proof7_cedar_permit_allows_principal_leg seeds a Cedar permit policy
	// scoped to a dedicated principal (carol, not alice — see this
	// function's own doc comment) and confirms Decide returns ALLOW on the
	// principal leg: the first ALLOW this system has ever been able to
	// produce. Every leg is checked, not just the overall effect, so the
	// ALLOW is not an accident of some other leg's zero value; the
	// assertion is on the actual effect, not merely that no error occurred.
	t.Run("proof7_cedar_permit_allows_principal_leg", func(t *testing.T) {
		agentID := uuid.New()
		seedAgent(t, configuredTenant, agentID, "integration-agent-carol", models.TrustTierUnverified)
		acting := singleHopDelegation(t, configuredTenant, agentID, models.ActionTierInternalModify, "cedar permit proof")
		proof7PolicyID = seedPolicy(t, configuredTenant, "permit-carol",
			`permit(principal == User::"carol@example.com", action, resource);`, "allow")

		resp, err := pdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
			Token:   mintToken(t, pdpClient, acting.ID),
			AgentId: agentID.String(),
			Subject: "carol@example.com",
			Tool:    "Bash",
		})
		if err != nil {
			t.Fatalf("Decide() error = %v, want a decision", err)
		}
		t.Logf("Decide() with a cedar permit policy in place -> effect=%s principal_effect=%s agent_effect=%s "+
			"delegation_effect=%s decided_source=%q decided_policy_id=%q",
			resp.GetEffect(), resp.GetPrincipalEffect(), resp.GetAgentEffect(), resp.GetDelegationEffect(),
			resp.GetDecidedSource(), resp.GetDecidedPolicyId())

		if resp.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Fatalf("Effect = %v, want EFFECT_ALLOW — the first ALLOW this system has ever produced", resp.GetEffect())
		}
		if resp.GetPrincipalEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Errorf("PrincipalEffect = %v, want EFFECT_ALLOW", resp.GetPrincipalEffect())
		}
		// Sanity: agent and delegation both legitimately allow too, so the
		// overall ALLOW is attributable to the cedar policy, not a side
		// effect of some other leg's zero value.
		if resp.GetAgentEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Errorf("AgentEffect = %v, want EFFECT_ALLOW (fixture is well-formed on this leg)", resp.GetAgentEffect())
		}
		if resp.GetDelegationEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Errorf("DelegationEffect = %v, want EFFECT_ALLOW (fixture is well-formed on this leg)", resp.GetDelegationEffect())
		}
		if resp.DecidedSource == nil || resp.GetDecidedSource() != "cedar" {
			t.Errorf("DecidedSource = %v, want present and %q", resp.DecidedSource, "cedar")
		}
		if resp.DecidedPolicyId == nil || resp.GetDecidedPolicyId() != proof7PolicyID {
			t.Errorf("DecidedPolicyId = %v, want present and %q (carol's seeded permit policy)", resp.DecidedPolicyId, proof7PolicyID)
		}

		proof7Resp = resp
	})

	// cedar_permit_audit_row_matches_response is the same strength of check
	// audit_row_provenance_matches_response applies to proof2, now against a
	// decision that actually allowed: it reads the audit row back with its
	// own query and compares the stored values against what proof7's
	// response actually returned, not merely that both are non-empty — the
	// exact class of check that would have caught Task 2/3's seam defect,
	// applied here to the first ALLOW this system has produced.
	t.Run("cedar_permit_audit_row_matches_response", func(t *testing.T) {
		if proof7Resp == nil {
			t.Fatal("proof7Resp is nil: proof7_cedar_permit_allows_principal_leg must run before this subtest")
		}

		// The most recent row for the tenant: carol's Decide call above was
		// the last one made against configuredTenant.
		source, policyID := auditRowProvenance(t, configuredTenant)
		t.Logf("stored (raw) policy_source=%q (valid=%t) policy_id=%q (valid=%t); response decided_source=%q decided_policy_id=%q",
			source.String, source.Valid, policyID.String, policyID.Valid,
			proof7Resp.GetDecidedSource(), proof7Resp.GetDecidedPolicyId())

		if !source.Valid || !policyID.Valid {
			t.Fatalf("policy_source/policy_id IS NULL (valid=%t/%t), want NOT NULL — a real decision must populate both",
				source.Valid, policyID.Valid)
		}
		if source.String != proof7Resp.GetDecidedSource() {
			t.Errorf("stored policy_source = %q, want %q (the response's decided_source)", source.String, proof7Resp.GetDecidedSource())
		}
		if policyID.String != proof7Resp.GetDecidedPolicyId() {
			t.Errorf("stored policy_id = %q, want %q (the response's decided_policy_id)", policyID.String, proof7Resp.GetDecidedPolicyId())
		}
		if source.String != "cedar" {
			t.Errorf("stored policy_source = %q, want %q", source.String, "cedar")
		}
		if policyID.String != proof7PolicyID {
			t.Errorf("stored policy_id = %q, want %q (carol's seeded permit policy)", policyID.String, proof7PolicyID)
		}

		entries := fetchAuditChain(t, configuredTenant)
		if len(entries) == 0 {
			t.Fatal("audit chain is empty, want at least the row this Decide call just wrote")
		}
		last := entries[len(entries)-1]
		if last.Decision != "ALLOW" {
			t.Errorf("most recent audit entry decision = %q, want %q", last.Decision, "ALLOW")
		}
		if err := audit.Verify(entries); err != nil {
			t.Fatalf("audit.Verify() error = %v, want nil", err)
		}
	})

	// proof8_cedar_forbid_denies_attributed_to_policy seeds a Cedar forbid
	// policy scoped to a second dedicated principal (dave) and confirms the
	// decision denies with that specific policy attributed — provenance
	// compared against the seeded id, not merely asserted non-empty.
	t.Run("proof8_cedar_forbid_denies_attributed_to_policy", func(t *testing.T) {
		agentID := uuid.New()
		seedAgent(t, configuredTenant, agentID, "integration-agent-dave", models.TrustTierUnverified)
		acting := singleHopDelegation(t, configuredTenant, agentID, models.ActionTierInternalModify, "cedar forbid proof")
		forbidPolicyID := seedPolicy(t, configuredTenant, "forbid-dave",
			`forbid(principal == User::"dave@example.com", action, resource);`, "deny")

		resp, err := pdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
			Token:   mintToken(t, pdpClient, acting.ID),
			AgentId: agentID.String(),
			Subject: "dave@example.com",
			Tool:    "Bash",
		})
		if err != nil {
			t.Fatalf("Decide() error = %v, want a decision", err)
		}
		t.Logf("Decide() with a cedar forbid policy in place -> effect=%s denied_leg=%q decided_source=%q decided_policy_id=%q",
			resp.GetEffect(), resp.GetDeniedLeg(), resp.GetDecidedSource(), resp.GetDecidedPolicyId())

		if resp.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Fatalf("Effect = %v, want EFFECT_DENY", resp.GetEffect())
		}
		if resp.GetDeniedLeg() != "principal" {
			t.Errorf("DeniedLeg = %q, want %q", resp.GetDeniedLeg(), "principal")
		}
		if resp.GetPrincipalEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Errorf("PrincipalEffect = %v, want EFFECT_DENY", resp.GetPrincipalEffect())
		}
		if resp.DecidedSource == nil || resp.GetDecidedSource() != "cedar" {
			t.Errorf("DecidedSource = %v, want present and %q", resp.DecidedSource, "cedar")
		}
		if resp.DecidedPolicyId == nil || resp.GetDecidedPolicyId() != forbidPolicyID {
			t.Errorf("DecidedPolicyId = %v, want present and %q (dave's seeded forbid policy)", resp.DecidedPolicyId, forbidPolicyID)
		}

		source, policyID := auditRowProvenance(t, configuredTenant)
		if !source.Valid || source.String != "cedar" || !policyID.Valid || policyID.String != forbidPolicyID {
			t.Errorf("stored provenance policy_source=%q(valid=%t) policy_id=%q(valid=%t), want cedar/%q, both valid",
				source.String, source.Valid, policyID.String, policyID.Valid, forbidPolicyID)
		}
	})

	// proof9_cedar_permit_cannot_exceed_delegation_ceiling is C14 end to end,
	// with a real engine rather than a synthetic verdict: an unconditional
	// cedar permit for erin, but her delegation's max_action_tier caps at
	// READ_ONLY while the request derives to DESTRUCTIVE. The overall
	// decision must still deny, attributed to delegation — and, distinctly,
	// the principal leg must show it genuinely allowed (a real policy
	// matched), or this proof would not distinguish "the ceiling stopped an
	// allowing policy" from "the policy never mattered because something
	// else already denied."
	t.Run("proof9_cedar_permit_cannot_exceed_delegation_ceiling", func(t *testing.T) {
		agentID := uuid.New()
		// PLATFORM_TRUSTED, not UNVERIFIED: the request below derives to
		// DESTRUCTIVE, which requires PLATFORM_TRUSTED on the agent leg (see
		// authz.DefaultTrustTable) — this proof is about the DELEGATION leg
		// stopping an allowing policy, so the agent leg must legitimately
		// allow too, or the denial here would be ambiguous about which leg
		// caused it.
		seedAgent(t, configuredTenant, agentID, "integration-agent-erin", models.TrustTierPlatformTrusted)
		// A low cap (READ_ONLY); the request below derives to DESTRUCTIVE,
		// well above it.
		acting := singleHopDelegation(t, configuredTenant, agentID, models.ActionTierReadOnly, "cedar ceiling proof")
		permitPolicyID := seedPolicy(t, configuredTenant, "permit-erin-unconditional",
			`permit(principal == User::"erin@example.com", action, resource);`, "allow")

		resp, err := pdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
			Token:   mintToken(t, pdpClient, acting.ID),
			AgentId: agentID.String(),
			Subject: "erin@example.com",
			Tool:    "Bash",
			// Bash carries no catalog entry (DefaultCatalog's own doc
			// comment) and DecideRequest carries no verb field at all after
			// spec §4.4.2 T3, so a destructive RawInput -- not a verb -- is
			// what this proof now needs to reach ActionTierDestructive: raw
			// input's own regex classifier (authz.classifyInput) matches
			// "rm -rf" directly, the same mechanism a real Bash tool call
			// would trigger.
			RawInput: "rm -rf /tmp/erin-ceiling-proof",
		})
		if err != nil {
			t.Fatalf("Decide() error = %v, want a decision", err)
		}
		t.Logf("Decide() with an unconditional cedar permit but an exceeded delegation cap -> effect=%s denied_leg=%q "+
			"derived_tier=%d principal_effect=%s delegation_effect=%s decided_source=%q decided_policy_id=%q",
			resp.GetEffect(), resp.GetDeniedLeg(), resp.GetDerivedTier(), resp.GetPrincipalEffect(), resp.GetDelegationEffect(),
			resp.GetDecidedSource(), resp.GetDecidedPolicyId())

		if resp.GetDerivedTier() != int32(models.ActionTierDestructive) {
			t.Fatalf("DerivedTier = %d, want %d (DESTRUCTIVE) — this proof needs the derived tier to actually exceed the cap",
				resp.GetDerivedTier(), models.ActionTierDestructive)
		}
		// C14: the overall decision denies...
		if resp.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Fatalf("Effect = %v, want EFFECT_DENY (an allowing policy must not exceed the delegation ceiling)", resp.GetEffect())
		}
		// ...attributed to delegation, not principal...
		if resp.GetDeniedLeg() != "delegation" {
			t.Errorf("DeniedLeg = %q, want %q", resp.GetDeniedLeg(), "delegation")
		}
		if resp.GetDelegationEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Errorf("DelegationEffect = %v, want EFFECT_DENY", resp.GetDelegationEffect())
		}
		// ...specifically because the principal leg really did allow (a real
		// cedar permit policy matched).
		if resp.GetPrincipalEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Errorf("PrincipalEffect = %v, want EFFECT_ALLOW (the policy must have genuinely matched for this to prove anything)", resp.GetPrincipalEffect())
		}
		// The principal leg's own provenance still names cedar's permit
		// policy, even though it did not end up deciding the overall
		// outcome — concrete proof (not just the LegResult enum) that the
		// policy really matched.
		if resp.DecidedSource == nil || resp.GetDecidedSource() != "cedar" {
			t.Errorf("DecidedSource = %v, want present and %q", resp.DecidedSource, "cedar")
		}
		if resp.DecidedPolicyId == nil || resp.GetDecidedPolicyId() != permitPolicyID {
			t.Errorf("DecidedPolicyId = %v, want present and %q (erin's seeded permit policy)", resp.DecidedPolicyId, permitPolicyID)
		}
	})

	t.Run("single_decide_latency_baseline", func(t *testing.T) {
		// Uncontended latency for one Decide() call — no other writer
		// racing this tenant's chain tail. This is what the burst
		// subtest's per-call average is compared against below: the
		// difference is the advisory lock's actual per-decision cost,
		// not an assumption.
		//
		// Phase 2c Task 5: by this point in the sequence, configuredTenant
		// has three real, enabled cedar policies (carol's permit, dave's
		// forbid, erin's permit) — none of which match alice, the subject
		// used here, but Configured's Evaluate still loads, prepares, and
		// evaluates all three on this call. This is "Cedar in the path" for
		// real, not a zero-policy fast path, which is why proof7-proof9 run
		// before this subtest rather than after it.
		callStart := time.Now()
		resp, err := pdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
			Token:   actingToken,
			AgentId: agentID.String(),
			Subject: "alice@example.com",
			Tool:    "Bash",
		})
		baselineLatency = time.Since(callStart)
		if err != nil {
			t.Fatalf("Decide() error = %v, want a decision", err)
		}
		if resp == nil {
			t.Fatal("Decide() response = nil, want a decision")
		}
		t.Logf("single uncontended Decide() call: %s", baselineLatency)
	})

	t.Run("measured_concurrent_decide_split_on_the_same_tail", func(t *testing.T) {
		const n = 10
		var (
			wg                            sync.WaitGroup
			succeeded, aborted, otherFail int64
			start                         = make(chan struct{})
		)
		results := make([]string, n)
		before := fetchAuditChain(t, configuredTenant)

		for i := 0; i < n; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				resp, err := pdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
					Token:   actingToken,
					AgentId: agentID.String(),
					Subject: "alice@example.com",
					Tool:    "Bash",
				})
				switch {
				case err == nil && resp != nil:
					atomic.AddInt64(&succeeded, 1)
					results[i] = "ok"
				case status.Code(err) == codes.Aborted:
					atomic.AddInt64(&aborted, 1)
					results[i] = "aborted"
				default:
					atomic.AddInt64(&otherFail, 1)
					results[i] = fmt.Sprintf("other: %v", err)
				}
			}(i)
		}
		burstStart := time.Now()
		close(start) // release every goroutine at once, so they race the same tail
		wg.Wait()
		elapsed := time.Since(burstStart)

		t.Logf("fired %d concurrent Decide() calls for tenant %q in %s (avg %s/call, vs %s single-call baseline): "+
			"%d ok, %d Aborted (ErrConcurrentAppend), %d other failures",
			n, configuredTenant, elapsed, elapsed/n, baselineLatency, succeeded, aborted, otherFail)
		t.Logf("per-call outcomes: %v", results)

		// Post-fix expectation: the per-tenant advisory lock in
		// store.AppendAudit serializes these ten calls onto the same chain
		// tail one at a time, so every one should now succeed and none
		// should collide on UNIQUE(tenant_id, prev_hash). Before that lock
		// existed, Phase 1c measured 3/7, 7/3, 4/6 splits here — a
		// regression to any partial split means the lock has stopped
		// covering this path.
		if succeeded != n || aborted != 0 || otherFail != 0 {
			t.Errorf("succeeded=%d aborted=%d other=%d, want %d/0/0 (advisory lock should serialize every call for one tenant)",
				succeeded, aborted, otherFail, n)
		}

		after := fetchAuditChain(t, configuredTenant)
		if err := audit.Verify(after); err != nil {
			t.Fatalf("audit.Verify() after the concurrent burst error = %v, want nil (chain must stay linked under a race)", err)
		}
		gotNewRows := int64(len(after) - len(before))
		if gotNewRows != succeeded {
			t.Errorf("audit_chain grew by %d rows, want %d (one per successful decision)", gotNewRows, succeeded)
		}
		t.Logf("chain still verifies after the burst: %d total entries (%d new, matching %d successful decisions)",
			len(after), gotNewRows, succeeded)
	})

	t.Run("appendaudit_lock_is_per_tenant_not_global", func(t *testing.T) {
		// The 10/0 result above is necessary but not sufficient: a single
		// GLOBAL lock (not keyed by tenant) would also serialize every
		// tenant's appends through one mutex and would still produce 10/0
		// for each tenant measured individually — it would just also make
		// unrelated tenants queue behind each other, invisibly to a
		// count-only check. audit.go's lock key is hashtext(tenant_id), not
		// a constant; the two checks below confirm that holds against a
		// real database, not just that it reads that way in the source.
		const n = 10
		storeA := store.New(testDB, configuredTenant)
		storeB := store.New(testDB, secondTenantID)

		probe := func(tenant, label string, i int) audit.Entry {
			return audit.Entry{
				TenantID:   tenant,
				OccurredAt: time.Now(),
				EventType:  "decision",
				Actor:      "integration-test:" + label,
				ToolName:   "Bash",
				Action:     "read",
				Decision:   "DENY",
				Reason:     fmt.Sprintf("%s probe %d", label, i),
			}
		}

		// Check 1, informational: both tenants fire a 10-call burst
		// released at the same instant, on independent goroutine sets
		// sharing nothing but *sql.DB and the one Postgres instance
		// underneath it. Both must still land 10/0 — a deadlock or a lock
		// keyed wrongly enough to cross-link two tenants' chains would show
		// up here even though it doesn't by itself distinguish a per-tenant
		// lock from a global one (a global lock still produces 10/0 for
		// each tenant measured separately; see above).
		var wg sync.WaitGroup
		var aOK, aAborted, aOther, bOK, bAborted, bOther int64
		start := make(chan struct{})
		fire := func(st *store.Store, tenant, label string, i int, ok, aborted, other *int64) {
			defer wg.Done()
			<-start
			switch err := st.AppendAudit(t.Context(), probe(tenant, label, i)); {
			case err == nil:
				atomic.AddInt64(ok, 1)
			case errors.Is(err, store.ErrConcurrentAppend):
				atomic.AddInt64(aborted, 1)
			default:
				atomic.AddInt64(other, 1)
				t.Logf("tenant %q AppendAudit unexpected error: %v", tenant, err)
			}
		}
		for i := 0; i < n; i++ {
			wg.Add(2)
			go fire(storeA, configuredTenant, "interleaved-a", i, &aOK, &aAborted, &aOther)
			go fire(storeB, secondTenantID, "interleaved-b", i, &bOK, &bAborted, &bOther)
		}
		burstStart := time.Now()
		close(start)
		wg.Wait()
		burstElapsed := time.Since(burstStart)
		t.Logf("interleaved burst, both tenants at once, %d calls each in %s: tenant %q %d ok/%d aborted/%d other, tenant %q %d ok/%d aborted/%d other",
			n, burstElapsed, configuredTenant, aOK, aAborted, aOther, secondTenantID, bOK, bAborted, bOther)
		if aOK != n || aAborted != 0 || aOther != 0 {
			t.Errorf("tenant %q: %d ok, %d aborted, %d other, want %d/0/0", configuredTenant, aOK, aAborted, aOther, n)
		}
		if bOK != n || bAborted != 0 || bOther != 0 {
			t.Errorf("tenant %q: %d ok, %d aborted, %d other, want %d/0/0", secondTenantID, bOK, bAborted, bOther, n)
		}

		// Check 2, decisive: hold tenant A's lock open on purpose and
		// confirm a concurrent call for tenant A blocks behind it while a
		// concurrent call for tenant B does not. This is deliberately not a
		// throughput/timing-ratio comparison — an earlier version of this
		// test compared aggregate wall-clock for two tenants' bursts run
		// separately vs. interleaved, and it was too noisy in a small local
		// Docker Compose stack to be a reliable signal: server-side
		// contention (WAL fsync, CPU, connection setup) affects both the
		// global-lock and per-tenant-lock cases and can mask the
		// difference at n=10. Controlling one lock holder's duration
		// directly removes that noise: unblocked is a few milliseconds,
		// blocked is at least the hold duration, and there is no middle
		// ground to misread.
		const holdFor = 300 * time.Millisecond
		holderTx, err := testDB.BeginTx(t.Context(), nil)
		if err != nil {
			t.Fatalf("begin lock-holder tx: %v", err)
		}
		defer func() { _ = holderTx.Rollback() }() // safety net if a Fatal below skips the release timer
		if _, err := holderTx.ExecContext(t.Context(), `SELECT set_config('app.tenant_id', $1, true)`, configuredTenant); err != nil {
			t.Fatalf("lock-holder set_config: %v", err)
		}
		// Same literal statement and tenant string audit.go's AppendAudit
		// uses, so this acquires the identical lock key a real AppendAudit
		// call for configuredTenant would.
		if _, err := holderTx.ExecContext(t.Context(), `SELECT pg_advisory_xact_lock(hashtext($1))`, configuredTenant); err != nil {
			t.Fatalf("lock-holder acquire lock: %v", err)
		}
		releaseTimer := time.AfterFunc(holdFor, func() { _ = holderTx.Rollback() })
		defer releaseTimer.Stop()

		call := func(st *store.Store, tenant string) (elapsed time.Duration, err error) {
			callStart := time.Now()
			err = st.AppendAudit(t.Context(), probe(tenant, "hold-probe", 0))
			return time.Since(callStart), err
		}
		var aElapsed, bElapsed time.Duration
		var aErr, bErr error
		wg.Add(2)
		go func() { defer wg.Done(); aElapsed, aErr = call(storeA, configuredTenant) }()
		go func() { defer wg.Done(); bElapsed, bErr = call(storeB, secondTenantID) }()
		wg.Wait()

		if aErr != nil {
			t.Fatalf("tenant %q AppendAudit while its own lock is held error = %v, want nil (should block, then succeed once released)",
				configuredTenant, aErr)
		}
		if bErr != nil {
			t.Fatalf("tenant %q AppendAudit while tenant %q's lock is held error = %v, want nil", secondTenantID, configuredTenant, bErr)
		}
		t.Logf("while tenant %q held its own lock for %s: a same-tenant call took %s, a different-tenant call took %s",
			configuredTenant, holdFor, aElapsed, bElapsed)

		if aElapsed < holdFor {
			t.Errorf("same-tenant call took %s, want >= %s — it should have blocked behind the held lock "+
				"(if it did not, this test's control isn't verifying anything)", aElapsed, holdFor)
		}
		if bElapsed >= holdFor {
			t.Errorf("different-tenant call took %s, want well under %s — it blocked behind another tenant's "+
				"lock, which means the lock is not scoped per tenant", bElapsed, holdFor)
		}

		for _, tenant := range []string{configuredTenant, secondTenantID} {
			entries := fetchAuditChain(t, tenant)
			if err := audit.Verify(entries); err != nil {
				t.Fatalf("audit.Verify() for tenant %q error = %v, want nil", tenant, err)
			}
		}
	})

	// proof_multilang_cedar_permit_and_rego_forbid_denies_attributed_to_rego
	// is Task 6's proof 1: a Cedar permit and a Rego forbid on the same
	// request. Deny-overrides must hold across languages exactly as it
	// holds within one — authz.FoldVerdicts sees both verdicts regardless
	// of which engine produced them — so the decision denies, and the
	// audit trail attributes it to rego specifically (the only verdict
	// with EffectDeny; cedar's permit is not a deny candidate at all, so
	// this is not a coincidence of alphabetical ordering — see
	// authz.FoldVerdicts' own doc comment on decisiveVerdict).
	t.Run("proof_multilang_cedar_permit_and_rego_forbid_denies_attributed_to_rego", func(t *testing.T) {
		const subject = "heidi@example.com"
		heidiAgentID := uuid.New()
		seedAgent(t, configuredTenant, heidiAgentID, "integration-agent-heidi", models.TrustTierUnverified)
		heidiActing := singleHopDelegation(t, configuredTenant, heidiAgentID, models.ActionTierInternalModify, "cedar+rego deny-overrides proof")

		seedPolicy(t, configuredTenant, "heidi-cedar-permit",
			fmt.Sprintf(`permit(principal == User::"%s", action, resource);`, subject), "allow")
		regoPolicyID := seedPolicyLang(t, configuredTenant, "heidi-rego-forbid", "rego", fmt.Sprintf(`package stratium.policy

deny if {
	input.principal.subject == %q
}`, subject), "deny")

		resp, err := pdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
			Token:   mintToken(t, pdpClient, heidiActing.ID),
			AgentId: heidiAgentID.String(),
			Subject: subject,
			Tool:    "Bash",
		})
		if err != nil {
			t.Fatalf("Decide() error = %v, want a decision", err)
		}
		t.Logf("Decide() with a cedar permit + rego forbid on the same request -> effect=%s principal_reason=%q decided_source=%q decided_policy_id=%q",
			resp.GetEffect(), resp.GetPrincipalReason(), resp.GetDecidedSource(), resp.GetDecidedPolicyId())

		if resp.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Fatalf("Effect = %v, want EFFECT_DENY — deny-overrides must hold across languages, not just within one", resp.GetEffect())
		}
		if resp.GetDeniedLeg() != "principal" {
			t.Errorf("DeniedLeg = %q, want %q", resp.GetDeniedLeg(), "principal")
		}
		if resp.DecidedSource == nil || resp.GetDecidedSource() != "rego" {
			t.Fatalf("DecidedSource = %v, want present and %q — the cedar permit must not out-rank the rego forbid", resp.DecidedSource, "rego")
		}
		if resp.DecidedPolicyId == nil || resp.GetDecidedPolicyId() != regoPolicyID {
			t.Errorf("DecidedPolicyId = %v, want present and %q (heidi's seeded rego forbid)", resp.DecidedPolicyId, regoPolicyID)
		}
		// The reason string, not merely the effect: a caller reading only
		// Effect/DeniedLeg cannot tell this apart from a denial some other
		// policy caused.
		if !strings.Contains(resp.GetPrincipalReason(), regoPolicyID) {
			t.Errorf("PrincipalReason = %q, want it to name the deciding policy %q", resp.GetPrincipalReason(), regoPolicyID)
		}

		// The audit row is independent, stored evidence of the same
		// attribution — auditRowProvenance reads the tenant's latest row,
		// which this call's own append is (nothing else writes
		// configuredTenant's audit_chain between this Decide call and this
		// read), the same strength audit_row_provenance_matches_response
		// applies to proof2 above.
		source, policyID := auditRowProvenance(t, configuredTenant)
		t.Logf("raw column check: policy_source=%q policy_id=%q", source.String, policyID.String)
		if source.String != "rego" || policyID.String != regoPolicyID {
			t.Errorf("stored policy_source/policy_id = %q/%q, want %q/%q", source.String, policyID.String, "rego", regoPolicyID)
		}
	})

	// decide_latency_with_all_four_engines_in_path and
	// decide_concurrency_with_all_four_engines_in_path are Task 6's own
	// measurement (brief items 3-4): end-to-end decision latency and 10-way
	// concurrency with all four engines actually loading, preparing, and
	// evaluating real policies on every call, against Phase 1c's ~2.5ms
	// baseline and Phase 2c's Cedar-only figure — not a synthetic minimal
	// case: by this point configuredTenant already carries carol's, dave's,
	// and erin's cedar policies (proof7-9) plus heidi's cedar+rego pair
	// (above), and ivan's own four-language set below adds json and xacml
	// for the first time, so this call and every one of the burst below
	// exercises the tenant's full, real, cross-language policy set. See
	// task-6-report.md for the full comparison table — these two subtests'
	// own t.Logf lines are that number's source.
	ivanAgentID := uuid.New()
	seedAgent(t, configuredTenant, ivanAgentID, "integration-agent-ivan", models.TrustTierUnverified)
	const ivanPurpose = "four-engine end-to-end latency proof"
	ivanActing := singleHopDelegation(t, configuredTenant, ivanAgentID, models.ActionTierInternalModify, ivanPurpose)
	// Pre-minted, same reasoning as actingToken above: both subtests below
	// share this token, one to keep the latency measurement to a single
	// Decide call and the other because it fires from ten concurrent
	// goroutines where a per-call mintToken (t.Fatalf on failure) would be
	// unsafe.
	ivanActingToken := mintToken(t, pdpClient, ivanActing.ID)
	seedPolicyLang(t, configuredTenant, "ivan-cedar", "cedar", cedarPurposeCondition(ivanPurpose), "allow")
	seedPolicyLang(t, configuredTenant, "ivan-rego", "rego", regoPurposeCondition(ivanPurpose), "allow")
	seedPolicyLang(t, configuredTenant, "ivan-json", "json", jsonPurposeCondition(ivanPurpose), "allow")
	seedPolicyLang(t, configuredTenant, "ivan-xacml", "xacml", xacmlPurposeCondition("ivan-xacml", ivanPurpose), "allow")

	t.Run("decide_latency_with_all_four_engines_in_path", func(t *testing.T) {
		callStart := time.Now()
		resp, err := pdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
			Token:   ivanActingToken,
			AgentId: ivanAgentID.String(),
			Subject: "ivan@example.com",
			Tool:    "Bash",
		})
		fourEngineLatency = time.Since(callStart)
		if err != nil {
			t.Fatalf("Decide() error = %v, want a decision", err)
		}
		t.Logf("single uncontended Decide() call with all four engines in the path: %s", fourEngineLatency)
		if resp.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Errorf("Effect = %v, want EFFECT_ALLOW (every one of ivan's four seeded policies allows)", resp.GetEffect())
		}
	})

	t.Run("decide_concurrency_with_all_four_engines_in_path", func(t *testing.T) {
		const n = 10
		var succeeded, aborted, otherFail int64
		var wg sync.WaitGroup
		start := make(chan struct{})
		before := fetchAuditChain(t, configuredTenant)

		for i := 0; i < n; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, err := pdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
					Token:   ivanActingToken,
					AgentId: ivanAgentID.String(),
					Subject: "ivan@example.com",
					Tool:    "Bash",
				})
				switch {
				case err == nil:
					atomic.AddInt64(&succeeded, 1)
				case status.Code(err) == codes.Aborted:
					atomic.AddInt64(&aborted, 1)
				default:
					atomic.AddInt64(&otherFail, 1)
				}
			}()
		}
		burstStart := time.Now()
		close(start)
		wg.Wait()
		elapsed := time.Since(burstStart)
		t.Logf("fired %d concurrent Decide() calls (four engines each) in %s (avg %s/call, vs %s single-call baseline): "+
			"%d ok, %d Aborted, %d other failures", n, elapsed, elapsed/n, fourEngineLatency, succeeded, aborted, otherFail)

		if succeeded != n || aborted != 0 || otherFail != 0 {
			t.Errorf("succeeded=%d aborted=%d other=%d, want %d/0/0 (advisory lock should serialize every call for one tenant, four engines or one)",
				succeeded, aborted, otherFail, n)
		}
		after := fetchAuditChain(t, configuredTenant)
		if err := audit.Verify(after); err != nil {
			t.Fatalf("audit.Verify() after the concurrent burst error = %v, want nil", err)
		}
		if gotNewRows := int64(len(after) - len(before)); gotNewRows != succeeded {
			t.Errorf("audit_chain grew by %d rows, want %d (one per successful decision)", gotNewRows, succeeded)
		}
	})

	// proof10_create_delegation_clamps_request_to_principal_authority is
	// Phase 2d Task 5's first proof: a principal (frank) whose cedar policies
	// permit only INTERNAL_MODIFY and the "Read" tool requests DESTRUCTIVE
	// with three tools, two of which ("Bash", "Write") he does not hold. The
	// response must grant INTERNAL_MODIFY with exactly ["Read"] and list all
	// three removals.
	//
	// Two cedar policies, deliberately split so each probe dimension is
	// answered by exactly the policy meant for it:
	//
	//   - The tier-ceiling policy conditions on "context.derived_tier > 0" as
	//     well as the ceiling itself. authz.Clamp's tier walk (clampTier)
	//     never probes the zero-value tier REASONING, and its tool walk
	//     (clampTools) always probes at exactly that zero-value tier — so
	//     "> 0" is true for every tier-ceiling probe and false for every tool
	//     probe. Without it, an unconditional "action, resource" tier policy
	//     would also permit every tool (all tool probes carry
	//     derived_tier=0, which is <= INTERNAL_MODIFY), silently defeating
	//     this proof's own tool-denial half.
	//   - The tool policy names Action::"Read" specifically and carries no
	//     tier condition, so it answers the tool probe (which never varies
	//     its tier) independent of whichever tier the walk is currently on.
	//
	// frank is a name not reused by any earlier subtest in this file
	// (alice/bob/carol/dave/erin/mallory), so his policies cannot match, and
	// cannot be matched by, any of theirs.
	t.Run("proof10_create_delegation_clamps_request_to_principal_authority", func(t *testing.T) {
		delegationGateAgentID = uuid.New()
		// PLATFORM_TRUSTED, not UNVERIFIED: CreateDelegation itself never
		// evaluates agent trust (LoadAgent only confirms the agent exists —
		// see delegation.go's own doc comment), so this choice is inert here.
		// It matters to proof12 below, a separate Decide call reusing this
		// same agent, which needs the agent leg to legitimately allow a
		// DESTRUCTIVE-deriving action for that proof to attribute its denial
		// to the delegation leg unambiguously.
		seedAgent(t, configuredTenant, delegationGateAgentID, "integration-agent-frank", models.TrustTierPlatformTrusted)

		seedPolicy(t, configuredTenant, "frank-tier-ceiling-internal-modify",
			fmt.Sprintf(`permit(principal == User::"frank@example.com", action, resource) when `+
				`{ context.derived_tier > 0 && context.derived_tier <= %d };`, int(models.ActionTierInternalModify)),
			"allow")
		seedPolicy(t, configuredTenant, "frank-can-read",
			`permit(principal == User::"frank@example.com", action == Action::"Read", resource);`, "allow")

		resp, err := pdpClient.CreateDelegation(t.Context(), &pdpgrpc.CreateDelegationRequest{
			Subject: "frank@example.com",
			AgentId: delegationGateAgentID.String(),
			RequestedScope: &pdpgrpc.RequestedScope{
				MaxActionTier: int32(models.ActionTierDestructive),
				Tools:         []string{"Read", "Bash", "Write"},
			},
			Purpose:    "integration test: delegation-creation gate (D3/C6)",
			TtlSeconds: 3600,
		})
		if err != nil {
			t.Fatalf("CreateDelegation() error = %v, want a response", err)
		}
		t.Logf("CreateDelegation() -> delegation_id=%s granted max_action_tier=%d tools=%v removed=%d",
			resp.GetDelegationId(), resp.GetGrantedScope().GetMaxActionTier(),
			resp.GetGrantedScope().GetTools(), len(resp.GetGrantedScope().GetRemoved()))
		for _, r := range resp.GetGrantedScope().GetRemoved() {
			t.Logf("  removed: dimension=%s value=%s reason=%s", r.GetDimension(), r.GetValue(), r.GetReason())
		}

		if resp.GetGrantedScope().GetMaxActionTier() != int32(models.ActionTierInternalModify) {
			t.Errorf("granted max_action_tier = %d, want %d (INTERNAL_MODIFY: frank's own ceiling)",
				resp.GetGrantedScope().GetMaxActionTier(), models.ActionTierInternalModify)
		}
		if !slices.Equal(resp.GetGrantedScope().GetTools(), []string{"Read"}) {
			t.Errorf("granted tools = %v, want [Read] (Bash and Write are not frank's)", resp.GetGrantedScope().GetTools())
		}
		if len(resp.GetGrantedScope().GetRemoved()) != 3 {
			t.Fatalf("removed = %d entries, want exactly 3 (tier DESTRUCTIVE, tool Bash, tool Write)",
				len(resp.GetGrantedScope().GetRemoved()))
		}
		if r := findRemoval(resp.GetGrantedScope().GetRemoved(), "tier", models.ActionTierDestructive.String()); r == nil || r.GetReason() != "denied" {
			t.Errorf("tier removal = %+v, want {tier, DESTRUCTIVE, denied}", r)
		}
		for _, tool := range []string{"Bash", "Write"} {
			if r := findRemoval(resp.GetGrantedScope().GetRemoved(), "tool", tool); r == nil || r.GetReason() != "denied" {
				t.Errorf("removal for tool %s = %+v, want {tool, %s, denied}", tool, r, tool)
			}
		}
		if r := findRemoval(resp.GetGrantedScope().GetRemoved(), "tool", "Read"); r != nil {
			t.Errorf("Read was removed (%+v), want it granted", r)
		}

		delegationGateResp = resp
	})

	// proof11_persisted_delegation_matches_response is Task 5's second proof:
	// the persisted row, read back with its own query, must match the
	// response field by field — not merely exist. max_action_tier and
	// approved_tools are compared directly against granted_scope; depth and
	// root_delegation_id have no dedicated wire field (CreateDelegationResponse
	// carries only delegation_id and granted_scope — see the proto's own doc
	// comment on why: neither is a caller input), so "what the response
	// reported" for those two is the structural consequence of the response's
	// own delegation_id naming a ROOT grant (this request never set
	// parent_delegation_id): depth 0 and a root_delegation_id that
	// self-references that same id (store.CreateDelegation's own doc comment
	// — a root's root_delegation_id/depth are computed server-side, never
	// trusted from the caller). Asserting the actual persisted VALUES here,
	// not just that the columns are non-NULL, is what the brief's own warning
	// about provenance fields being "structurally present but never
	// populated" requires.
	t.Run("proof11_persisted_delegation_matches_response", func(t *testing.T) {
		if delegationGateResp == nil {
			t.Fatal("delegationGateResp is nil: proof10_create_delegation_clamps_request_to_principal_authority must run before this subtest")
		}
		id, err := uuid.Parse(delegationGateResp.GetDelegationId())
		if err != nil {
			t.Fatalf("parse delegation_id %q from response: %v", delegationGateResp.GetDelegationId(), err)
		}

		gotTier, gotTools, gotDepth, gotRoot := fetchDelegationRow(t, configuredTenant, id)
		t.Logf("persisted row: max_action_tier=%d approved_tools=%v depth=%d root_delegation_id=%s",
			gotTier, gotTools, gotDepth, gotRoot)

		if wantTier := int64(delegationGateResp.GetGrantedScope().GetMaxActionTier()); gotTier != wantTier {
			t.Errorf("persisted max_action_tier = %d, want %d (the response's granted_scope.max_action_tier)", gotTier, wantTier)
		}
		if wantTools := delegationGateResp.GetGrantedScope().GetTools(); !slices.Equal(gotTools, wantTools) {
			t.Errorf("persisted approved_tools = %v, want %v (the response's granted_scope.tools)", gotTools, wantTools)
		}
		if gotDepth != 0 {
			t.Errorf("persisted depth = %d, want 0 (a root delegation: this request set no parent_delegation_id)", gotDepth)
		}
		if gotRoot.String() != delegationGateResp.GetDelegationId() {
			t.Errorf("persisted root_delegation_id = %s, want %s (self-referencing: a root's own id)",
				gotRoot, delegationGateResp.GetDelegationId())
		}
	})

	// proof12_decide_with_clamped_delegation_denies_above_granted_tier is
	// Task 5's third proof: a Decide call presenting the delegation proof10
	// just created must deny an action above the granted (clamped) ceiling,
	// attributed to the delegation leg — and, so this is a genuine boundary
	// rather than a blanket denial, must ALLOW an action exactly AT that
	// ceiling first. Principal and agent are both confirmed to have
	// genuinely allowed on the denying call (same reasoning
	// proof9_cedar_permit_cannot_exceed_delegation_ceiling documents): only
	// then does the delegation leg's denial prove the ceiling itself is what
	// stopped this, not some other leg denying first.
	t.Run("proof12_decide_with_clamped_delegation_denies_above_granted_tier", func(t *testing.T) {
		if delegationGateResp == nil {
			t.Fatal("delegationGateResp is nil: proof10_create_delegation_clamps_request_to_principal_authority must run before this subtest")
		}

		atCeiling, err := pdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
			Token:   delegationGateResp.GetToken(),
			AgentId: delegationGateAgentID.String(),
			Subject: "frank@example.com",
			Tool:    "Read",
			// Read is catalogued READ_ONLY (Phase 3c), so this sits UNDER the
			// INTERNAL_MODIFY ceiling rather than exactly at it. DecideRequest
			// carries no verb field at all after spec §4.4.2 T3, so there is
			// nothing left to set here anyway. What this call establishes is
			// unchanged and is all the proof below needs: the tool itself is
			// permitted, so the denial that follows is attributable to the
			// tier and not to the tool check.
		})
		if err != nil {
			t.Fatalf("Decide() at the granted ceiling: error = %v, want a decision", err)
		}
		t.Logf("Decide() UNDER the granted ceiling (Read -> READ_ONLY) -> effect=%s", atCeiling.GetEffect())
		if atCeiling.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Fatalf("Decide() at the granted ceiling: effect = %v, want EFFECT_ALLOW "+
				"(otherwise a denial above it would not prove where the boundary actually sits)", atCeiling.GetEffect())
		}

		aboveCeiling, err := pdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
			Token:   delegationGateResp.GetToken(),
			AgentId: delegationGateAgentID.String(),
			Subject: "frank@example.com",
			Tool:    "Read",
			// The tier has to come from the input, not a verb -- which no
			// longer exists on the wire at all (spec §4.4.2 T3): Read's
			// catalog entry pins a catalogued tool's tier, and only a
			// destructive raw input can raise above it. That is the evidence
			// rule in DeriveTier, and routing this proof through it means the
			// same call also demonstrates that a benign tool name cannot mask
			// a hostile payload. Read stays the tool because it is the only
			// one proof10's clamp granted; anything else would deny at the
			// tool check and prove nothing about the ceiling.
			RawInput: `{"command":"rm -rf /var/data"}`,
		})
		if err != nil {
			t.Fatalf("Decide() above the granted ceiling: error = %v, want a decision", err)
		}
		t.Logf("Decide() ABOVE the granted ceiling -> effect=%s denied_leg=%q derived_tier=%d "+
			"principal_effect=%s agent_effect=%s delegation_effect=%s delegation_reason=%q",
			aboveCeiling.GetEffect(), aboveCeiling.GetDeniedLeg(), aboveCeiling.GetDerivedTier(),
			aboveCeiling.GetPrincipalEffect(), aboveCeiling.GetAgentEffect(), aboveCeiling.GetDelegationEffect(),
			aboveCeiling.GetDelegationReason())

		if aboveCeiling.GetDerivedTier() != int32(models.ActionTierDestructive) {
			t.Fatalf("DerivedTier = %d, want %d (DESTRUCTIVE) — this proof needs the derived tier to actually exceed the granted ceiling",
				aboveCeiling.GetDerivedTier(), models.ActionTierDestructive)
		}
		if aboveCeiling.GetEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Fatalf("Effect = %v, want EFFECT_DENY (an action above the clamped ceiling must be denied)", aboveCeiling.GetEffect())
		}
		if aboveCeiling.GetDeniedLeg() != "delegation" {
			t.Errorf("DeniedLeg = %q, want %q — the clamp (proof10) and the runtime ceiling must agree on WHERE this is enforced",
				aboveCeiling.GetDeniedLeg(), "delegation")
		}
		if aboveCeiling.GetDelegationEffect() != pdpgrpc.Effect_EFFECT_DENY {
			t.Errorf("DelegationEffect = %v, want EFFECT_DENY", aboveCeiling.GetDelegationEffect())
		}
		if aboveCeiling.GetPrincipalEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Errorf("PrincipalEffect = %v, want EFFECT_ALLOW (frank's unconditional Read permit must have matched)",
				aboveCeiling.GetPrincipalEffect())
		}
		if aboveCeiling.GetAgentEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Errorf("AgentEffect = %v, want EFFECT_ALLOW (PLATFORM_TRUSTED is sufficient for DESTRUCTIVE)",
				aboveCeiling.GetAgentEffect())
		}
	})

	// proof13_audit_chain_records_creation_and_verifies_with_decisions is
	// Task 5's fourth proof: the tenant's real audit chain — already carrying
	// many "decision" entries from every earlier subtest in this file, plus
	// proof12's two Decide calls — must also carry proof10's "delegation_
	// created" entry, and audit.Verify must pass over the whole mixed chain,
	// not a two-entry slice assembled just for this check. Verifying the
	// real, full chain is strictly stronger: a hashing defect specific to the
	// creation entry's shape would break the WHOLE chain's linkage from that
	// entry forward, not just an isolated pair.
	//
	// The creation entry's fields are compared against proof10/11's own known
	// values, not merely asserted non-nil/non-zero — the same discipline
	// audit_row_provenance_matches_response established for Decide's audit
	// entries, applied here to CreateDelegation's for the first time.
	t.Run("proof13_audit_chain_records_creation_and_verifies_with_decisions", func(t *testing.T) {
		if delegationGateResp == nil {
			t.Fatal("delegationGateResp is nil: proof10_create_delegation_clamps_request_to_principal_authority must run before this subtest")
		}
		delegationID, err := uuid.Parse(delegationGateResp.GetDelegationId())
		if err != nil {
			t.Fatalf("parse delegation_id: %v", err)
		}

		entries := fetchAuditChain(t, configuredTenant)
		t.Logf("audit_chain for %q has %d entries by this point in the run", configuredTenant, len(entries))

		var creation *audit.Entry
		decisionCount := 0
		for i := range entries {
			switch entries[i].EventType {
			case "delegation_created":
				if entries[i].DelegationID != nil && *entries[i].DelegationID == delegationID {
					creation = &entries[i]
				}
			case "decision":
				decisionCount++
			}
		}
		if creation == nil {
			t.Fatal("no delegation_created audit entry found for proof10's delegation")
		}
		if decisionCount == 0 {
			t.Fatal("no decision audit entries found — this chain must contain at least one of each event type")
		}
		t.Logf("chain contains 1 delegation_created entry for %s plus %d decision entries", delegationID, decisionCount)

		if creation.AgentID == nil || *creation.AgentID != delegationGateAgentID {
			t.Errorf("creation entry AgentID = %v, want %s", creation.AgentID, delegationGateAgentID)
		}
		if creation.DelegationID == nil || *creation.DelegationID != delegationID {
			t.Errorf("creation entry DelegationID = %v, want %s", creation.DelegationID, delegationID)
		}
		if creation.RootDelegationID == nil || *creation.RootDelegationID != delegationID {
			t.Errorf("creation entry RootDelegationID = %v, want %s (self-referencing root)", creation.RootDelegationID, delegationID)
		}
		if creation.ChainDepth != 0 {
			t.Errorf("creation entry ChainDepth = %d, want 0", creation.ChainDepth)
		}
		if creation.Decision != "ALLOW" {
			t.Errorf("creation entry Decision = %q, want ALLOW", creation.Decision)
		}
		if creation.DeniedAtDepth != -1 {
			t.Errorf("creation entry DeniedAtDepth = %d, want -1 (audit only runs on CreateDelegation's success path)", creation.DeniedAtDepth)
		}
		if creation.DeclaredTier != int16(models.ActionTierDestructive) {
			t.Errorf("creation entry DeclaredTier = %d, want %d (DESTRUCTIVE: what proof10 REQUESTED)",
				creation.DeclaredTier, models.ActionTierDestructive)
		}
		if creation.DerivedTier != int16(models.ActionTierInternalModify) {
			t.Errorf("creation entry DerivedTier = %d, want %d (INTERNAL_MODIFY: what was actually GRANTED after the clamp)",
				creation.DerivedTier, models.ActionTierInternalModify)
		}

		if err := audit.Verify(entries); err != nil {
			t.Fatalf("audit.Verify() error = %v, want nil — a chain with both a creation and decision entry must still verify", err)
		}
		t.Logf("audit.Verify() PASSED over the tenant's full %d-entry chain, containing both delegation_created and decision event types",
			len(entries))
	})

	// proof14_cross_tenant_create_delegation_is_not_found is Task 5's fifth
	// proof, the CreateDelegation counterpart to proof4 above: a second
	// tenant's principal cannot create a delegation referencing the first
	// tenant's agent. CreateDelegation calls store.LoadAgent first, exactly
	// as Decide does, and that query carries no tenant_id in its WHERE clause
	// (see internal/store/store.go's loadAgentQuery and package doc) — RLS is
	// what makes an agent belonging to secondTenantID invisible to a PDP
	// configured for configuredTenant, surfacing identically to "does not
	// exist" (store.ErrNotFound) either way.
	t.Run("proof14_cross_tenant_create_delegation_is_not_found", func(t *testing.T) {
		otherAgentID := uuid.New()
		seedAgent(t, secondTenantID, otherAgentID, "integration-agent-tenant-two-create-delegation", models.TrustTierUnverified)

		resp, err := pdpClient.CreateDelegation(t.Context(), &pdpgrpc.CreateDelegationRequest{
			Subject: "mallory@example.com",
			AgentId: otherAgentID.String(),
			RequestedScope: &pdpgrpc.RequestedScope{
				MaxActionTier: int32(models.ActionTierReadOnly),
				Tools:         []string{"Read"},
			},
			Purpose:    "integration test: cross-tenant create must not resolve the agent",
			TtlSeconds: 3600,
		})
		if resp != nil {
			t.Fatalf("CreateDelegation() response = %+v, want nil", resp)
		}
		st := wantCode(t, err, codes.NotFound)
		t.Logf("CreateDelegation() for tenant %q's agent, against a PDP configured for %q -> NotFound: %s",
			secondTenantID, configuredTenant, st.Message())
	})

	// proof_multilang_rego_only_clamps_like_cedar_would is Task 6's proof 5.
	// It mirrors proof10 above exactly in shape — same split into a
	// tier-ceiling policy and a tool policy, same reasoning for why
	// (policy.Probe, called from authz.Clamp inside CreateDelegation, leaves
	// Delegation at its zero value: there is no delegation yet at creation
	// time, only Principal/Action.Tool/DerivedTier — see policy.GrantProbe's
	// own doc comment, which is why this cannot key off Delegation.Purpose
	// the way the direct-Multi proofs in this file's earlier section do) —
	// but gina's authority is granted entirely in rego, never cedar. Before
	// Task 6 wired more than cedar into the registry a delegation-creation
	// gate ever consults, a rego-only grant would have clamped to nothing
	// (an unregistered language behaves as "no policy" — orphanVerdict) and
	// this call would have failed with PermissionDenied instead of
	// narrowing. A later Decide call against the freshly-clamped delegation
	// must then agree with what the probe granted, in both directions: the
	// tool it was granted (Read) is allowed, and a tool it was not (Bash)
	// is still denied, now at the delegation leg specifically
	// (internal/authz/delegation.go's own ApprovedTools check).
	t.Run("proof_multilang_rego_only_clamps_like_cedar_would", func(t *testing.T) {
		const subject = "gina@example.com"
		ginaAgentID := uuid.New()
		// PLATFORM_TRUSTED for the same reason proof10 gives: inert to
		// CreateDelegation itself (LoadAgent only confirms the agent
		// exists), but needed so the later Decide calls' agent leg
		// legitimately allows.
		seedAgent(t, configuredTenant, ginaAgentID, "integration-agent-gina", models.TrustTierPlatformTrusted)

		seedPolicyLang(t, configuredTenant, "gina-tier-ceiling-internal-modify", "rego", fmt.Sprintf(`package stratium.policy

allow if {
	input.principal.subject == %q
	input.derived_tier > 0
	input.derived_tier <= %d
}`, subject, int(models.ActionTierInternalModify)), "allow")
		seedPolicyLang(t, configuredTenant, "gina-can-read", "rego", fmt.Sprintf(`package stratium.policy

allow if {
	input.principal.subject == %q
	input.action.tool == "Read"
}`, subject), "allow")

		resp, err := pdpClient.CreateDelegation(t.Context(), &pdpgrpc.CreateDelegationRequest{
			Subject: subject,
			AgentId: ginaAgentID.String(),
			RequestedScope: &pdpgrpc.RequestedScope{
				MaxActionTier: int32(models.ActionTierDestructive),
				Tools:         []string{"Read", "Bash", "Write"},
			},
			Purpose:    "integration test: rego-only delegation-creation clamp",
			TtlSeconds: 3600,
		})
		if err != nil {
			t.Fatalf("CreateDelegation() error = %v, want a response — a rego-only grant must clamp, not fail", err)
		}
		t.Logf("CreateDelegation() (rego-only principal) -> max_action_tier=%d tools=%v removed=%d",
			resp.GetGrantedScope().GetMaxActionTier(), resp.GetGrantedScope().GetTools(), len(resp.GetGrantedScope().GetRemoved()))

		if resp.GetGrantedScope().GetMaxActionTier() != int32(models.ActionTierInternalModify) {
			t.Errorf("granted max_action_tier = %d, want %d (INTERNAL_MODIFY: gina's rego ceiling)",
				resp.GetGrantedScope().GetMaxActionTier(), models.ActionTierInternalModify)
		}
		if !slices.Equal(resp.GetGrantedScope().GetTools(), []string{"Read"}) {
			t.Errorf("granted tools = %v, want [Read] (Bash and Write are not gina's, per her rego policy)", resp.GetGrantedScope().GetTools())
		}
		if len(resp.GetGrantedScope().GetRemoved()) != 3 {
			t.Fatalf("removed = %d entries, want exactly 3 (tier DESTRUCTIVE, tool Bash, tool Write)", len(resp.GetGrantedScope().GetRemoved()))
		}

		// Agreement, direction 1: what the clamp granted (Read, within
		// INTERNAL_MODIFY) is allowed at runtime too — both the
		// creation-time probe and the principal leg must agree, now that
		// both consult rego.
		decideResp, err := pdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
			Token:   resp.GetToken(),
			AgentId: ginaAgentID.String(),
			Subject: subject,
			Tool:    "Read",
		})
		if err != nil {
			t.Fatalf("Decide() error = %v, want a decision", err)
		}
		t.Logf("Decide() against the freshly-clamped rego delegation (Read) -> effect=%s principal_effect=%s decided_source=%q",
			decideResp.GetEffect(), decideResp.GetPrincipalEffect(), decideResp.GetDecidedSource())
		if decideResp.GetEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Errorf("Effect = %v, want EFFECT_ALLOW — the clamp (probe-time) and Decide (runtime) must agree gina may use Read", decideResp.GetEffect())
		}
		if decideResp.GetPrincipalEffect() != pdpgrpc.Effect_EFFECT_ALLOW {
			t.Errorf("PrincipalEffect = %v, want EFFECT_ALLOW", decideResp.GetPrincipalEffect())
		}
		if decideResp.DecidedSource == nil || decideResp.GetDecidedSource() != "rego" {
			t.Errorf("DecidedSource = %v, want present and %q", decideResp.DecidedSource, "rego")
		}

		// Agreement, direction 2: a tool the clamp removed (Bash) is still
		// denied at runtime, using the SAME delegation — the delegation
		// leg's own ApprovedTools check, independent of what the principal
		// leg says.
		//
		// RawInput carries a bare, non-destructive command so this call
		// derives READ_ONLY via BuiltinTier's raw-input classifier: Bash has
		// no catalog entry and (after spec §4.4.2 T3) no verb on the wire
		// either, so an empty RawInput here would derive REASONING (tier 0)
		// — which gina-tier-ceiling-internal-modify's own `derived_tier > 0`
		// condition rejects, denying at the PRINCIPAL leg for an unrelated
		// reason and masking the delegation-leg property this subtest
		// exists to prove. A non-zero tier is what makes the denial
		// attributable to ApprovedTools specifically, the same way it was
		// before this task when a wire-supplied verb produced it instead.
		bashResp, err := pdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
			Token:    resp.GetToken(),
			AgentId:  ginaAgentID.String(),
			Subject:  subject,
			Tool:     "Bash",
			RawInput: "ls -la",
		})
		if err != nil {
			t.Fatalf("Decide() error = %v, want a decision", err)
		}
		t.Logf("Decide() against the freshly-clamped rego delegation (Bash, never granted) -> effect=%s denied_leg=%q",
			bashResp.GetEffect(), bashResp.GetDeniedLeg())
		if bashResp.GetEffect() != pdpgrpc.Effect_EFFECT_DENY || bashResp.GetDeniedLeg() != "delegation" {
			t.Errorf("Decide() for Bash = %v/%s, want EFFECT_DENY/delegation — the clamp's removal must hold at runtime too",
				bashResp.GetEffect(), bashResp.GetDeniedLeg())
		}
	})

	// chain_verifies_across_the_migration_boundary: a chain that started
	// before migrations/000006_audit_policy_provenance and
	// 000010_audit_unevaluated_policy_ids added their columns, migrated live
	// while that chain already had an entry, then grew a second entry with
	// real provenance through the real store.AppendAudit path — must still
	// verify. audit.Link/Hash reconstruct a full Entry from whatever the
	// tail read returns (see store.scanAuditTail's own doc comment); a
	// column silently absent from that read — the exact shape of the Task
	// 2/3 seam defect — changes the recomputed hash and breaks the chain
	// invisibly, not loudly. This is a permanent, automated version of the
	// manual proof described in the Task 2 report.
	//
	// A dedicated tenant that no other subtest touches: the down/up
	// migration below changes audit_chain's SCHEMA (ALTER TABLE, not a
	// per-row or per-tenant operation) for the window between the two
	// Migrate calls. That is safe only because every subtest in this file
	// runs sequentially and nothing else writes to audit_chain concurrently
	// (see TestEndToEnd's own doc comment) — this is the one subtest that
	// structurally depends on that rather than merely benefiting from it, so
	// it runs late, after every other proof in this file has already
	// completed against the real schema, and before proof6's irreversible
	// revoke.
	t.Run("chain_verifies_across_the_migration_boundary", func(t *testing.T) {
		const boundaryTenant = "tenant-migration-boundary-integration"

		migConn, err := sql.Open("postgres", os.Getenv("STRATIUM_IT_DATABASE_URL"))
		if err != nil {
			t.Fatalf("open dedicated migration connection: %v", err)
		}
		defer func() { _ = migConn.Close() }()

		m := newMigrator(t, migConn)
		defer func() { _, _ = m.Close() }()

		restored := false
		defer func() {
			// Best effort: if a step below fails before the explicit
			// migrate-to-latest call runs, try once more to leave the schema
			// at the latest version so a failure here doesn't cascade into
			// every later subtest — not just ones calling store.AppendAudit
			// (whose INSERT always names policy_source/policy_id), but also,
			// since Phase 2c Task 5, proof6's pdpClient.Decide() call, which
			// needs the stratium_app role's SELECT grant on policies that
			// migrations/000007_policies_serving_grant restores. The stack
			// this test itself brought up is destroyed on the way out
			// regardless (see Makefile's integration target) — this only
			// limits blast radius within one run.
			if restored {
				return
			}
			if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
				t.Logf("best-effort restore to the latest migration after a failure in this subtest: %v", err)
			}
		}()

		if err := m.Migrate(migrationBeforeProvenance); err != nil {
			t.Fatalf("migrate down to v%d (pre-provenance): %v", migrationBeforeProvenance, err)
		}
		t.Logf("migrated to v%d: policy_source/policy_id do not exist", migrationBeforeProvenance)

		genesis := audit.Link(nil, audit.Entry{
			TenantID:      boundaryTenant,
			OccurredAt:    time.Now().UTC(),
			EventType:     "decision",
			Actor:         "integration-test:boundary-pre-migration",
			ToolName:      "Bash",
			Action:        "read",
			Decision:      "DENY",
			DeniedLeg:     "principal",
			DeniedAtDepth: -1,
			Reason:        "pre-migration entry: written before policy_source/policy_id existed",
		})
		genesisHash := genesis.Hash()
		withTenantTx(t, boundaryTenant, func(tx *sql.Tx) {
			if _, err := tx.ExecContext(t.Context(), preProvenanceAuditInsertQuery,
				genesis.TenantID, genesis.PrevHash[:], genesisHash[:], genesis.OccurredAt, genesis.EventType, genesis.Actor,
				genesis.AgentID, genesis.DelegationID, genesis.RootDelegationID, genesis.ChainDepth,
				genesis.ToolName, genesis.Action, genesis.DeclaredTier, genesis.DerivedTier,
				genesis.Decision, genesis.DeniedLeg, genesis.DeniedAtDepth, genesis.Reason, genesis.InputDigest[:],
			); err != nil {
				t.Fatalf("insert pre-migration genesis entry: %v", err)
			}
		})
		t.Logf("inserted genesis audit entry for tenant %q under the pre-migration schema (no provenance columns)", boundaryTenant)

		if err := m.Migrate(migrationWithProvenance); err != nil {
			t.Fatalf("migrate up to v%d (unevaluated_policy_ids, which also carries the schema through "+
				"000006's own policy_source/policy_id along the way): %v", migrationWithProvenance, err)
		}
		t.Logf("migrated to v%d: the genesis row's new columns now read back NULL", migrationWithProvenance)

		second := audit.Entry{
			TenantID:             boundaryTenant,
			OccurredAt:           time.Now(),
			EventType:            "decision",
			Actor:                "integration-test:boundary-post-migration",
			ToolName:             "Bash",
			Action:               "read",
			Decision:             "DENY",
			DeniedAtDepth:        -1,
			Reason:               "post-migration entry: real provenance through the real AppendAudit path",
			PolicySource:         "cedar-synthetic",
			PolicyID:             "policy-boundary-42",
			UnevaluatedPolicyIDs: []string{"boundary-orphan-1", "boundary-orphan-2"},
		}
		if err := store.New(testDB, boundaryTenant).AppendAudit(t.Context(), second); err != nil {
			t.Fatalf("AppendAudit for the post-migration entry: %v", err)
		}

		entries := fetchAuditChain(t, boundaryTenant)
		if len(entries) != 2 {
			t.Fatalf("len(entries) = %d, want 2 (one pre-migration, one post-migration)", len(entries))
		}
		if entries[0].PolicySource != "" || entries[0].PolicyID != "" {
			t.Errorf("pre-migration entry PolicySource/PolicyID = %q/%q, want empty (NULL decoded to the zero value)",
				entries[0].PolicySource, entries[0].PolicyID)
		}
		if len(entries[0].UnevaluatedPolicyIDs) != 0 {
			t.Errorf("pre-migration entry UnevaluatedPolicyIDs = %v, want empty (NULL decoded to the zero value)",
				entries[0].UnevaluatedPolicyIDs)
		}
		if entries[1].PolicySource != "cedar-synthetic" || entries[1].PolicyID != "policy-boundary-42" {
			t.Errorf("post-migration entry PolicySource/PolicyID = %q/%q, want %q/%q",
				entries[1].PolicySource, entries[1].PolicyID, "cedar-synthetic", "policy-boundary-42")
		}
		if want := []string{"boundary-orphan-1", "boundary-orphan-2"}; !slices.Equal(entries[1].UnevaluatedPolicyIDs, want) {
			t.Errorf("post-migration entry UnevaluatedPolicyIDs = %v, want %v", entries[1].UnevaluatedPolicyIDs, want)
		}

		if err := audit.Verify(entries); err != nil {
			t.Fatalf("audit.Verify() across the migration boundary error = %v, want nil", err)
		}
		t.Logf("audit.Verify() PASSED over a %d-entry chain spanning migrations/000006_audit_policy_provenance "+
			"and 000010_audit_unevaluated_policy_ids", len(entries))

		// The boundary this subtest exists to prove is exactly v5->v6, so
		// everything above deliberately stops at v6, not "the latest."
		// Catching up the rest of the way here — rather than leaving the
		// schema sitting at v6 for the remainder of the run — is what keeps
		// every later subtest's assumptions true. Concretely, since Phase 2c
		// Task 5: migrations/000007_policies_serving_grant grants
		// stratium_app SELECT on policies, and that grant is what makes it
		// possible for a down-migration through v7 to have revoked it (down
		// migrations run in descending order, so migrating to v5 above ran
		// both v7's and v6's down scripts) — proof6 below calls
		// pdpClient.Decide(), which needs that grant to reach the audit-write
		// failure it is actually testing, not an unrelated permission error
		// on policies.
		if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
			t.Fatalf("migrate up to the latest version (past v%d): %v", migrationWithProvenance, err)
		}
		restored = true
		t.Logf("migrated the rest of the way to the latest version — the schema is fully current again")
	})

	t.Run("proof6_failed_audit_append_blocks_the_decision", func(t *testing.T) {
		// A genuine failure, not a mock: revoke the application role's own
		// INSERT privilege on audit_chain, live, on the real database this
		// test is connected to. Both grants are revoked because the role
		// this stack connects as (see deploy/docker/init-db.sql) inherits
		// INSERT via two independent paths — ownership of audit_chain
		// (stratium_audit_owner) and the narrower grant
		// migrations/000004_audit_ownership.up.sql makes to stratium_app —
		// revoking only one would leave the other still granting it.
		//
		// The revoke is scoped to this subtest by the t.Cleanup below, and
		// that is a correctness requirement, not tidiness. This revoke is
		// role-level, not tenant-scoped: while it is in effect NO Decide
		// call anywhere in this package can append an audit row, on any
		// tenant, through any PDP instance. It used to be left in place
		// permanently, on the stated grounds that this subtest "runs last"
		// — it does not. go test concatenates a package's test files in
		// FILENAME order, so every integration file sorting after
		// store_integration_test.go ran with INSERT already revoked and
		// failed with "permission denied for table audit_chain" in the full
		// suite while passing in isolation. Two files (Phase 12's
		// revocation_epoch_e2e_ and Phase 14 Task 7's decide_tier_override_)
		// were named to sort BEFORE this one specifically to dodge that,
		// which made two filenames load-bearing with nothing saying so here,
		// where a rename would happen. Restoring the grants removes that
		// trap; "deliberately irreversible" was a statement of consequence,
		// not of impossibility.
		auditInsertRoles := []string{"stratium_app", "stratium_audit_owner"}
		t.Cleanup(func() { restoreAuditChainInsert(t, auditInsertRoles) })
		for _, role := range auditInsertRoles {
			if _, err := testDB.ExecContext(t.Context(), fmt.Sprintf("REVOKE INSERT ON audit_chain FROM %s", role)); err != nil {
				t.Fatalf("revoke INSERT from %s: %v", role, err)
			}
		}

		resp, err := pdpClient.Decide(t.Context(), &pdpgrpc.DecideRequest{
			Token:   actingToken,
			AgentId: agentID.String(),
			Subject: "alice@example.com",
			Tool:    "Bash",
		})
		if resp != nil {
			t.Fatalf("Decide() response = %+v, want nil: a decision must not escape a failed audit write", resp)
		}
		// codes.Internal, not codes.Aborted: this is a real permission
		// failure (Postgres SQLSTATE 42501), a different failure class from
		// the unique-violation/ErrConcurrentAppend case measured above —
		// store.AppendAudit only maps 23505 specifically to Aborted, so
		// this asserts the two are not being conflated.
		st := wantCode(t, err, codes.Internal)
		t.Logf("Decide() with INSERT revoked on audit_chain -> no decision returned, code=%v message=%q",
			st.Code(), st.Message())

		if _, confirmErr := testDB.ExecContext(t.Context(), "SELECT 1"); confirmErr != nil {
			t.Errorf("test's own database connection broke unexpectedly: %v", confirmErr)
		}
	})
}

// restoreAuditChainInsert re-GRANTs INSERT on audit_chain to roles and then
// CONFIRMS it, rather than assuming the GRANT statement did what it says.
// A half-working restore is strictly worse than the permanent revoke it
// replaces: the revoke failed loudly and identically on every later Decide
// call, while a restore that silently covered only one of the two roles
// would leave a failure that depends on which grant path a given connection
// happens to inherit INSERT through — the definition of a flake.
//
// has_table_privilege is the right question to ask of BOTH roles, including
// stratium_audit_owner, which owns the table: an owner's implicit
// privileges are materialised into relacl as soon as anything is granted or
// revoked, so a REVOKE from the owner genuinely removes INSERT and
// has_table_privilege genuinely reports false until it is granted back
// (confirmed live against this stack's own postgres:16, not assumed from
// the documentation).
//
// context.Background with an explicit timeout, not t.Context(): as of Go
// 1.24 a test's context is cancelled BEFORE its cleanup functions run, so
// t.Context() here would fail every statement with "context canceled" and
// restore nothing.
func restoreAuditChainInsert(t *testing.T, roles []string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, role := range roles {
		if _, err := testDB.ExecContext(ctx, fmt.Sprintf("GRANT INSERT ON audit_chain TO %s", role)); err != nil {
			t.Errorf("restoring INSERT on audit_chain to %s: %v — every later test in this package "+
				"that calls Decide will now fail with a permission error that has nothing to do with "+
				"what it is testing", role, err)
		}
	}
	for _, role := range roles {
		var granted bool
		if err := testDB.QueryRowContext(ctx,
			`SELECT has_table_privilege($1, 'audit_chain', 'INSERT')`, role).Scan(&granted); err != nil {
			t.Errorf("checking restored INSERT on audit_chain for %s: %v", role, err)
			continue
		}
		if !granted {
			t.Errorf("INSERT on audit_chain is still absent for %s after the restoring GRANT — "+
				"the restore did not work, and later tests in this package will fail unpredictably "+
				"depending on which role their connection inherits INSERT through", role)
		}
	}
}
