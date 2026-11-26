// Package config loads the PDP's configuration from the environment.
//
// Required values have no defaults. A PDP that starts with a guessed database
// URL or a guessed tenant is worse than one that refuses to start.
package config

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	DatabaseURL string // STRATIUM_DATABASE_URL (required) — the serving connection.
	// MigrationDatabaseURL (optional) is used only to apply migrations, on a
	// connection closed before serving begins — see cmd/stratium-pdp/main.go.
	// Left empty, the PDP skips migrations and assumes an already-migrated
	// schema, logging that assumption plainly rather than guessing.
	MigrationDatabaseURL string        // STRATIUM_MIGRATION_DATABASE_URL (optional)
	TenantID             string        // STRATIUM_TENANT_ID (required)
	ListenAddr           string        // STRATIUM_LISTEN_ADDR, default ":50051"
	MaxDepth             int           // STRATIUM_MAX_DELEGATION_DEPTH, default 5
	DBTimeout            time.Duration // STRATIUM_DB_TIMEOUT, default 5s
	// DBMaxOpenConns caps the serving connection pool (store.LimitPool). A
	// decision uses one connection at a time, so this is also how many
	// decisions can be in the database at once.
	DBMaxOpenConns int // STRATIUM_DB_MAX_OPEN_CONNS, default 20

	// MaxDelegationTTL is the longest lifetime CreateDelegation grants; a
	// request above it is refused. Zero, which Load never produces, means no
	// maximum.
	MaxDelegationTTL time.Duration // STRATIUM_MAX_DELEGATION_TTL, default 24h
	// PolicyEvalTimeout bounds one evaluation of the tenant's policy set; an
	// evaluation that runs past it denies. Zero, which Load never produces,
	// means no deadline.
	PolicyEvalTimeout time.Duration // STRATIUM_POLICY_EVAL_TIMEOUT, default 2s
	// RequestTimeout is the longest one call may run, start to finish. A
	// caller's own shorter deadline still applies. The default sits above
	// the PEP's default deadline (STRATIUM_PEP_CONNECT_TIMEOUT, 5s), so it
	// only decides for a caller that set a longer one or none.
	RequestTimeout time.Duration // STRATIUM_REQUEST_TIMEOUT, default 10s
	// MaxRequestBytes is the largest request message the PDP reads. It is
	// what bounds raw_input, the tool call itself; every other field has a
	// limit of its own (Limits, below). The default is grpc-go's.
	MaxRequestBytes int // STRATIUM_MAX_REQUEST_BYTES, default 4194304 (4 MiB)
	// MaxConcurrentStreams is the most calls one client connection may have
	// in flight; one more waits for one of them to finish.
	MaxConcurrentStreams uint32 // STRATIUM_MAX_CONCURRENT_STREAMS, default 256
	// MaxConnectionIdle is how long a connection with no call in flight is
	// kept before the PDP closes it. The client reconnects on its next call.
	MaxConnectionIdle time.Duration // STRATIUM_MAX_CONNECTION_IDLE, default 5m
	// Limits is the longest each request field may be.
	Limits RequestLimits
	// How often Decide may write an audit row for a token that does not
	// authenticate: a sustained rate and a burst above it. A failure past
	// both is still denied, and is logged instead (pdpgrpc/token_failure.go). A
	// zero burst, which Load never produces, means no cap.
	FailedTokenAuditPerSecond float64 // STRATIUM_FAILED_TOKEN_AUDIT_PER_SECOND, default 5
	FailedTokenAuditBurst     int     // STRATIUM_FAILED_TOKEN_AUDIT_BURST, default 20
	// How fast one session, a root delegation and everything delegated
	// under it, may call the PDP: a sustained rate and a burst above it. A
	// call past both is refused before any store work (pdpgrpc/budget.go).
	// A zero burst, which Load never produces, means no budget.
	SessionCallsPerSecond float64 // STRATIUM_SESSION_CALLS_PER_SECOND, default 20
	SessionCallsBurst     int     // STRATIUM_SESSION_CALLS_BURST, default 100

	// gRPC transport (see tls.go). TLS is required unless GRPCInsecure is set.
	TLSCertFile  string // STRATIUM_TLS_CERT_FILE, PEM certificate chain
	TLSKeyFile   string // STRATIUM_TLS_KEY_FILE, PEM private key
	GRPCInsecure bool   // STRATIUM_GRPC_INSECURE, serve plaintext (local development only)

	// Principal authentication for root delegations (see principal.go). An
	// OIDC token is required unless PrincipalAuthInsecure is set.
	PrincipalOIDCIssuer   string        // STRATIUM_PRINCIPAL_OIDC_ISSUER
	PrincipalOIDCAudience string        // STRATIUM_PRINCIPAL_OIDC_AUDIENCE
	PrincipalClaim        string        // STRATIUM_PRINCIPAL_CLAIM, the claim naming the person (match the PAP's approver claim)
	PrincipalOIDCTimeout  time.Duration // STRATIUM_PRINCIPAL_OIDC_TIMEOUT, default 5s
	// PrincipalOIDCKeyRefresh is the least time between two fetches of the
	// identity provider's signing keys (principal.KeyFetchClient).
	PrincipalOIDCKeyRefresh time.Duration // STRATIUM_PRINCIPAL_OIDC_KEY_REFRESH_INTERVAL, default 30s
	PrincipalAuthInsecure   bool          // STRATIUM_PRINCIPAL_AUTH_INSECURE, trust the request's subject (local development only)

	// TokenSigningKeyPath is the filesystem path to a PEM-encoded EC private
	// key: the PDP's current delegation-token signing key, which also
	// verifies (STRATIUM_TOKEN_SIGNING_KEY_PATH, required). Spec §4.7.1 K1:
	// the environment holds the path, never the key material, so a leaked
	// environment dump or crash report never leaks a signing key — only
	// internal/token.Load ever reads the file this names.
	TokenSigningKeyPath string
	// TokenPreviousKeyPath is the filesystem path to a PEM-encoded EC key
	// retained for verification only (STRATIUM_TOKEN_PREVIOUS_KEY_PATH,
	// optional). Left empty, no previous key is loaded — the steady-state
	// case outside a rotation window. Set it to the outgoing current key
	// during rotation so a token issued moments before the restart that
	// swaps STRATIUM_TOKEN_SIGNING_KEY_PATH still verifies; see
	// internal/token's own package doc for why a previous key can verify but
	// is structurally unable to sign.
	TokenPreviousKeyPath string

	// ApprovalTTL is how long a freshly created pending approval remains
	// valid before Approval.Verify's expiry check rejects it — the value
	// CreateApproval's expires_at is computed from. Configurable, default
	// 24h, the same "operational tunable with a sensible default" treatment
	// MaxDepth/DBTimeout already get above: how long an organization can
	// reasonably expect a human to respond to an escalation varies by
	// deployment, unlike DatabaseURL/TenantID, where guessing is unsafe at
	// any value.
	ApprovalTTL time.Duration // STRATIUM_APPROVAL_TTL, default 24h
	// MaxPendingApprovals is how many approvals one session, a root
	// delegation and everything delegated under it, may have waiting for an
	// answer at once. A call that would need one more is denied. Zero, which
	// Load never produces, means no maximum.
	MaxPendingApprovals int // STRATIUM_MAX_PENDING_APPROVALS, default 20

	// DPoPFreshnessWindow is how far a DPoP proof's iat may sit from the PDP's
	// own clock, in either direction, before internal/dpop.Verify refuses it as
	// stale (STRATIUM_DPOP_FRESHNESS_WINDOW, required).
	//
	// Required with NO default, unlike ApprovalTTL/MaxDepth/DBTimeout above —
	// spec §4.7.2 K9, and the exception is deliberate. An operator is stating
	// how much clock skew between their agents and this PDP is tolerable, and
	// no single value is right for every deployment: too small denies an
	// honest fleet with ordinary NTP drift, too large widens the window a
	// stolen token and its captured proof stay replayable in. A guessed value
	// is therefore either useless or too permissive, which is exactly the
	// DatabaseURL/TenantID argument (see this package's own doc comment)
	// applied to a duration rather than a string.
	//
	// It joins the same `missing` collection those two use rather than
	// failing on its own, so a fresh deployment learns every gap from one run.
	DPoPFreshnessWindow time.Duration // STRATIUM_DPOP_FRESHNESS_WINDOW (required)

	// SpentProofReapInterval is how often the PDP sweeps its own tenant's
	// expired spent_proofs rows (STRATIUM_SPENT_PROOF_REAP_INTERVAL, default
	// 5m). K8 requires expired rows be reaped on a schedule; this is that
	// schedule's period, and cmd/stratium-pdp's reapSpentProofs is its caller.
	//
	// A default, unlike DPoPFreshnessWindow directly above, and the difference
	// is not an inconsistency: the window is a security parameter whose wrong
	// value is silently unsafe, while this is a throughput/table-size tradeoff
	// whose wrong value is merely a bigger table or a busier database — the
	// same "operational tunable with a sensible default" treatment ApprovalTTL
	// and DBTimeout already get. Rows only become reapable once they are past
	// the freshness window anyway, so a longer interval cannot shorten replay
	// protection, only delay the cleanup of rows that no longer protect
	// anything.
	//
	// # An operator will meet this coverage limit here
	//
	// The sweep is TENANT-SCOPED and cannot be otherwise: store.
	// ReapSpentProofs runs through beginTenantTx because an unscoped DELETE is
	// silently zeroed by FORCE ROW LEVEL SECURITY, and this schema deliberately
	// issues no BYPASSRLS role to any identity (see that method's own doc
	// comment for the full argument). A PDP process serves exactly one tenant,
	// so each process reaping its own covers every tenant that HAS a running
	// PDP — and a tenant whose PDP is scaled to zero keeps its expired rows
	// until one runs again. That is a deployment property, not a defect: those
	// rows deny nothing and cost nothing but space, since a tenant with no PDP
	// is also making no decisions.
	SpentProofReapInterval time.Duration // STRATIUM_SPENT_PROOF_REAP_INTERVAL, default 5m

	// PolicyLanguages is the deployment's enabled set of policy engines —
	// STRATIUM_POLICY_LANGUAGES, a comma-separated list, default every
	// language this build ships (defaultPolicyLanguages below). Unlike
	// DatabaseURL/TenantID above, this has a default: an operator who
	// enables nothing unusual gets every engine for free, the same way
	// leaving STRATIUM_LISTEN_ADDR unset gets ":50051" rather than an error.
	//
	// This package only parses the list; it does not know which names are
	// real. Deliberately: recognizing a name requires an actual engine
	// constructor (cedar.New, rego.New, ...), and this package has no
	// dependency on internal/policy or its engines to name a default with —
	// gaining one just to validate four string literals would be exactly
	// the kind of coupling a "loads config from the environment" package
	// should not need. cmd/stratium-pdp's own buildRegistry (registry.go)
	// is where a name with no matching engine becomes the startup failure
	// the brief asks for: the same fail-fast principle this package applies
	// to DatabaseURL/TenantID, just enforced one step later, by the code
	// that actually owns the answer to "is this a real language."
	PolicyLanguages []string
}

// defaultPolicyLanguages is every policy engine this binary ships today,
// used when STRATIUM_POLICY_LANGUAGES is unset. Plain string literals, not
// each engine's own Language() — see the Config.PolicyLanguages doc comment
// above for why this package does not import them.
var defaultPolicyLanguages = []string{"cedar", "json", "rego", "xacml"}

func Load() (Config, error) {
	c := Config{
		ListenAddr:           envOr("STRATIUM_LISTEN_ADDR", ":50051"),
		MaxDepth:             5,
		DBTimeout:            5 * time.Second,
		DBMaxOpenConns:       20,
		MaxDelegationTTL:     24 * time.Hour,
		PolicyEvalTimeout:    2 * time.Second,
		RequestTimeout:       10 * time.Second,
		MaxRequestBytes:      4 << 20,
		MaxConcurrentStreams: 256,
		MaxConnectionIdle:    5 * time.Minute,
		Limits:               DefaultRequestLimits(),
		// A PEP whose token expired presents it once and re-issues, so real
		// traffic is a few of these per session.
		FailedTokenAuditPerSecond: 5,
		FailedTokenAuditBurst:     20,
		// An agent makes a few tool calls a second at most, each one or two
		// calls here; the burst covers a batch of parallel ones.
		SessionCallsPerSecond:  20,
		SessionCallsBurst:      100,
		ApprovalTTL:            24 * time.Hour,
		SpentProofReapInterval: 5 * time.Minute,
		PolicyLanguages:        defaultPolicyLanguages,
	}
	var err error

	// Every required-with-no-default value is checked before any of them can
	// return: a deployment missing both STRATIUM_DATABASE_URL and
	// STRATIUM_TENANT_ID (say, a fresh environment with none of the PDP's
	// variables set yet) learns both gaps from one run, not one restart per
	// gap. This is the same "collect every missing variable" idiom
	// cmd/stratium-pep/config.go's requiredEnv already uses for the PEP's own
	// required set — applied here so the PDP's required config behaves the
	// same way, not a different, weaker one.
	var missing []string
	c.DatabaseURL = os.Getenv("STRATIUM_DATABASE_URL")
	if c.DatabaseURL == "" {
		missing = append(missing, "STRATIUM_DATABASE_URL")
	}
	// The tenant is configuration, never request input. See the plan's global
	// constraints: the predecessor trusted a client-supplied header and that
	// was a critical authentication bypass.
	c.TenantID = os.Getenv("STRATIUM_TENANT_ID")
	if c.TenantID == "" {
		missing = append(missing, "STRATIUM_TENANT_ID")
	}
	// Presence only, matching DatabaseURL/TenantID's own treatment at this
	// layer: this package validates that a value was configured, not that the
	// file at the path is readable or holds a real EC key — that check needs
	// the filesystem and crypto/ecdsa, which belong to internal/token.Load,
	// same layering registry.go's own buildRegistry already uses for
	// STRATIUM_POLICY_LANGUAGES (syntax here, semantics one level up).
	c.TokenSigningKeyPath = os.Getenv("STRATIUM_TOKEN_SIGNING_KEY_PATH")
	if c.TokenSigningKeyPath == "" {
		missing = append(missing, "STRATIUM_TOKEN_SIGNING_KEY_PATH")
	}
	// Presence is collected here, alongside the other three, so it appears in
	// the same one-run report; the value is PARSED below, after that report,
	// because a malformed duration is a different failure from an absent one
	// and deserves its own message rather than being folded into "missing".
	dpopWindow := os.Getenv("STRATIUM_DPOP_FRESHNESS_WINDOW")
	if dpopWindow == "" {
		missing = append(missing, "STRATIUM_DPOP_FRESHNESS_WINDOW")
	}
	if len(missing) > 0 {
		return c, fmt.Errorf("missing required configuration: %s", strings.Join(missing, ", "))
	}

	if c.DPoPFreshnessWindow, err = time.ParseDuration(dpopWindow); err != nil {
		return c, fmt.Errorf("STRATIUM_DPOP_FRESHNESS_WINDOW: %w", err)
	}
	if c.DPoPFreshnessWindow <= 0 {
		// internal/dpop.Verify refuses a non-positive window itself rather than
		// half-enforcing it (its own doc comment: with window == 0 a proof
		// whose iat lands on the same second still verifies). Catching it here
		// too means the operator learns at startup instead of watching every
		// DPoP-bearing decision deny for a reason that reads like a client bug.
		return c, fmt.Errorf("STRATIUM_DPOP_FRESHNESS_WINDOW must be positive, got %s", c.DPoPFreshnessWindow)
	}

	// No presence check: unset is a valid, deliberate choice (skip migrations),
	// not a missing required value.
	c.MigrationDatabaseURL = os.Getenv("STRATIUM_MIGRATION_DATABASE_URL")
	// No presence check, for the same reason: unset means no previous key is
	// loaded, a deliberate and common choice outside a rotation window, not a
	// missing required value.
	c.TokenPreviousKeyPath = os.Getenv("STRATIUM_TOKEN_PREVIOUS_KEY_PATH")
	if v := os.Getenv("STRATIUM_MAX_CONCURRENT_STREAMS"); v != "" {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil || n < 1 {
			return c, fmt.Errorf("STRATIUM_MAX_CONCURRENT_STREAMS must be an integer of at least 1, got %q", v)
		}
		c.MaxConcurrentStreams = uint32(n)
	}
	if c.MaxConnectionIdle, err = positiveDuration("STRATIUM_MAX_CONNECTION_IDLE", c.MaxConnectionIdle); err != nil {
		return c, err
	}
	if v := os.Getenv("STRATIUM_MAX_REQUEST_BYTES"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return c, fmt.Errorf("STRATIUM_MAX_REQUEST_BYTES must be an integer of at least 1, got %q", v)
		}
		c.MaxRequestBytes = n
	}
	for _, l := range []struct {
		env string
		dst *int
	}{
		{"STRATIUM_MAX_TOOL_BYTES", &c.Limits.ToolBytes},
		{"STRATIUM_MAX_NAME_BYTES", &c.Limits.NameBytes},
		{"STRATIUM_MAX_SUBJECT_BYTES", &c.Limits.SubjectBytes},
		{"STRATIUM_MAX_PATH_BYTES", &c.Limits.PathBytes},
		{"STRATIUM_MAX_URI_BYTES", &c.Limits.URIBytes},
		{"STRATIUM_MAX_PURPOSE_BYTES", &c.Limits.PurposeBytes},
		{"STRATIUM_MAX_CREDENTIAL_BYTES", &c.Limits.CredentialBytes},
		{"STRATIUM_MAX_REQUESTED_TOOLS", &c.Limits.RequestedTools},
		{"STRATIUM_MAX_RESOURCE_ENTRIES", &c.Limits.ResourceEntries},
	} {
		if *l.dst, err = positiveInt(l.env, *l.dst); err != nil {
			return c, err
		}
	}
	if c.MaxPendingApprovals, err = positiveInt("STRATIUM_MAX_PENDING_APPROVALS", 20); err != nil {
		return c, err
	}
	if v := os.Getenv("STRATIUM_DB_MAX_OPEN_CONNS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return c, fmt.Errorf("STRATIUM_DB_MAX_OPEN_CONNS must be an integer of at least 1, got %q", v)
		}
		c.DBMaxOpenConns = n
	}
	if v := os.Getenv("STRATIUM_MAX_DELEGATION_DEPTH"); v != "" {
		if c.MaxDepth, err = strconv.Atoi(v); err != nil {
			return c, fmt.Errorf("STRATIUM_MAX_DELEGATION_DEPTH: %w", err)
		}
	}
	if c.MaxDepth < 1 {
		return c, fmt.Errorf("STRATIUM_MAX_DELEGATION_DEPTH must be at least 1, got %d", c.MaxDepth)
	}
	if v := os.Getenv("STRATIUM_DB_TIMEOUT"); v != "" {
		if c.DBTimeout, err = time.ParseDuration(v); err != nil {
			return c, fmt.Errorf("STRATIUM_DB_TIMEOUT: %w", err)
		}
	}
	if c.MaxDelegationTTL, err = positiveDuration("STRATIUM_MAX_DELEGATION_TTL", c.MaxDelegationTTL); err != nil {
		return c, err
	}
	if c.PolicyEvalTimeout, err = positiveDuration("STRATIUM_POLICY_EVAL_TIMEOUT", c.PolicyEvalTimeout); err != nil {
		return c, err
	}
	if c.RequestTimeout, err = positiveDuration("STRATIUM_REQUEST_TIMEOUT", c.RequestTimeout); err != nil {
		return c, err
	}
	if c.FailedTokenAuditPerSecond, err = positiveFloat(
		"STRATIUM_FAILED_TOKEN_AUDIT_PER_SECOND", c.FailedTokenAuditPerSecond); err != nil {
		return c, err
	}
	if c.SessionCallsPerSecond, err = positiveFloat(
		"STRATIUM_SESSION_CALLS_PER_SECOND", c.SessionCallsPerSecond); err != nil {
		return c, err
	}
	if c.SessionCallsBurst, err = positiveInt("STRATIUM_SESSION_CALLS_BURST", c.SessionCallsBurst); err != nil {
		return c, err
	}
	if v := os.Getenv("STRATIUM_FAILED_TOKEN_AUDIT_BURST"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			return c, fmt.Errorf("STRATIUM_FAILED_TOKEN_AUDIT_BURST must be an integer of at least 1, got %q", v)
		}
		c.FailedTokenAuditBurst = n
	}
	if v := os.Getenv("STRATIUM_APPROVAL_TTL"); v != "" {
		if c.ApprovalTTL, err = time.ParseDuration(v); err != nil {
			return c, fmt.Errorf("STRATIUM_APPROVAL_TTL: %w", err)
		}
	}
	if c.ApprovalTTL <= 0 {
		// Fail fast rather than mint an approval that is already expired the
		// instant it is created (Approval.Verify's expiry check is strict:
		// now must be BEFORE expires_at) — a misconfiguration an operator
		// would otherwise only discover as every single escalation retry
		// mysteriously denying "expired."
		return c, fmt.Errorf("STRATIUM_APPROVAL_TTL must be positive, got %s", c.ApprovalTTL)
	}
	if v := os.Getenv("STRATIUM_SPENT_PROOF_REAP_INTERVAL"); v != "" {
		if c.SpentProofReapInterval, err = time.ParseDuration(v); err != nil {
			return c, fmt.Errorf("STRATIUM_SPENT_PROOF_REAP_INTERVAL: %w", err)
		}
	}
	if c.SpentProofReapInterval <= 0 {
		// A non-positive interval is a time.NewTicker panic, not a "never
		// reap" setting — and an operator who wanted "never reap" is asking
		// for the unbounded table K8 exists to prevent, so there is no value
		// here worth interpreting rather than refusing.
		return c, fmt.Errorf("STRATIUM_SPENT_PROOF_REAP_INTERVAL must be positive, got %s", c.SpentProofReapInterval)
	}
	if v := os.Getenv("STRATIUM_POLICY_LANGUAGES"); v != "" {
		if c.PolicyLanguages, err = splitPolicyLanguages(v); err != nil {
			return c, err
		}
	}
	if err := loadTransport(&c); err != nil {
		return c, err
	}
	if err := loadPrincipalAuth(&c); err != nil {
		return c, err
	}
	return c, nil
}

// splitPolicyLanguages splits a comma-separated STRATIUM_POLICY_LANGUAGES
// value into its entries, trimming surrounding whitespace so
// "cedar, rego" reads the same as "cedar,rego". An empty entry — a leading,
// trailing, or doubled comma — is rejected rather than silently dropped:
// this package cannot tell "typo" from "meant to write something here"
// apart, and dropping it silently would let a config with a stray comma
// deploy with fewer engines than its author believed they listed.
func splitPolicyLanguages(v string) ([]string, error) {
	parts := strings.Split(v, ",")
	langs := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			return nil, fmt.Errorf("STRATIUM_POLICY_LANGUAGES: empty language name in %q (check for a stray comma)", v)
		}
		langs = append(langs, p)
	}
	return langs, nil
}

// RequestLimits is the longest each field of a request to the PDP may be.
// grpc-go bounds a whole message and nothing inside it, so without these one
// field could be as long as the message. In a Config built by hand, a zero
// limit, which Load never produces, means none.
//
// raw_input is not here: it is the tool call itself (a file being written, a
// patch) and is bounded by MaxRequestBytes.
type RequestLimits struct {
	// A tool, and one entry of a delegation's requested tools.
	ToolBytes int // STRATIUM_MAX_TOOL_BYTES, default 8192
	// A harness, an HTTP method, a resource key.
	NameBytes int // STRATIUM_MAX_NAME_BYTES, default 256
	// A principal: an email address, or an identity provider's own id.
	SubjectBytes int // STRATIUM_MAX_SUBJECT_BYTES, default 512
	// A working directory, a resource value.
	PathBytes int // STRATIUM_MAX_PATH_BYTES, default 4096
	// The URI a DPoP proof was made for.
	URIBytes     int // STRATIUM_MAX_URI_BYTES, default 16384
	PurposeBytes int // STRATIUM_MAX_PURPOSE_BYTES, default 1024
	// A delegation token, an identity provider's token, a DPoP proof or key.
	CredentialBytes int // STRATIUM_MAX_CREDENTIAL_BYTES, default 16384

	RequestedTools  int // STRATIUM_MAX_REQUESTED_TOOLS, default 1024
	ResourceEntries int // STRATIUM_MAX_RESOURCE_ENTRIES, default 64
}

// DefaultRequestLimits is what Load uses for a limit that is not set. Each is
// far above anything a real caller sends.
func DefaultRequestLimits() RequestLimits {
	return RequestLimits{
		// Long because the ext_authz PEP's tool is an HTTP request's path and
		// query string, and servers commonly accept those up to 8 KiB.
		ToolBytes:    8 << 10,
		NameBytes:    256,
		SubjectBytes: 512,
		PathBytes:    4096,
		// An origin and a path, where the path alone may be as long as a tool.
		URIBytes:     16 << 10,
		PurposeBytes: 1024,
		// Identity tokens that list many groups are the large ones.
		CredentialBytes: 16 << 10,
		RequestedTools:  1024,
		ResourceEntries: 64,
	}
}

// positiveFloat reads the number setting k, falling back to def when it is
// unset, and refuses a value that is not a finite number above zero.
func positiveFloat(k string, def float64) (float64, error) {
	v := os.Getenv(k)
	if v == "" {
		return def, nil
	}
	r, err := strconv.ParseFloat(v, 64)
	// The comparison is written so NaN fails it too.
	if err != nil || !(r > 0) || math.IsInf(r, 0) {
		return 0, fmt.Errorf("%s must be a number above zero, got %q", k, v)
	}
	return r, nil
}

// positiveInt reads the integer setting k, falling back to def when it is
// unset, and refuses a value that is not an integer of at least 1.
func positiveInt(k string, def int) (int, error) {
	v := os.Getenv(k)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%s must be an integer of at least 1, got %q", k, v)
	}
	return n, nil
}

// positiveDuration reads the duration setting k, falling back to def when it
// is unset, and refuses a value that is not a positive duration.
func positiveDuration(k string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(k)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", k, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive, got %s", k, d)
	}
	return d, nil
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
