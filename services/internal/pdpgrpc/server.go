// Package pdpgrpc is the gRPC transport for the PDP: it adapts wire requests
// into the pure decision in internal/authz and wire responses back out.
//
// Server trusts the request for exactly what proto/pdp/v1/pdp.proto's
// DecideRequest carries and nothing more. In particular the tenant comes
// from cfg (startup configuration) and the principal decision comes from
// evaluating policy here — neither is ever read off the request. See the
// proto's doc comment for why: the predecessor's client-supplied tenant
// header was a critical authentication bypass, and a caller-supplied
// principal verdict would be the same defect aimed at authorization.
package pdpgrpc

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stratiumdata/stratium/internal/authz"
	"github.com/stratiumdata/stratium/internal/config"
	"github.com/stratiumdata/stratium/internal/policy"
	"github.com/stratiumdata/stratium/internal/store"
	"github.com/stratiumdata/stratium/pkg/audit"
	"github.com/stratiumdata/stratium/pkg/classification"
	"github.com/stratiumdata/stratium/pkg/models"
)

// Store is what Decide needs from the tenant-scoped repository. *store.Store
// satisfies it; tests substitute a fake. Defined here, where it is consumed,
// rather than in package store, which has no reason to know about its gRPC
// caller.
type Store interface {
	LoadAgent(ctx context.Context, id uuid.UUID) (authz.AgentInfo, error)
	LoadChain(ctx context.Context, actingDelegationID uuid.UUID) ([]*models.Delegation, error)
	AppendAudit(ctx context.Context, e audit.Entry) error

	// HasAllowDecision backs ReportToolUse (tool_use.go): is there an ALLOW
	// decision on record for this delegation, tool and input digest.
	HasAllowDecision(ctx context.Context, delegationID uuid.UUID, tool string, inputDigest [32]byte) (bool, error)

	// CreateDelegation persists a new delegation, used by CreateDelegation
	// (delegation.go). *store.Store's own doc comment covers ScopeNarrows
	// enforcement and why root_delegation_id/depth are computed server-side
	// rather than trusted from the caller's struct.
	CreateDelegation(ctx context.Context, d *models.Delegation) error

	// CreateApproval and LoadApproval back escalation.go's resolveEscalation
	// — the only two operations the PDP ever performs against approvals
	// (E7: it creates pending records and reads them, never grants one).
	// models.Approval, not a pdpgrpc-local type: see that type's own doc
	// comment for why Task 3 moved it out of package store once this
	// interface needed to name it.
	CreateApproval(ctx context.Context, a *models.Approval) error
	LoadApproval(ctx context.Context, id uuid.UUID) (*models.Approval, error)

	// LoadToolCatalog loads the tenant's per-tool tool_catalog rows (spec
	// §4.4.2 T1/T2), consulted both for the catalog step of DeriveTier's
	// resolution order and for the resource/command extraction Decide
	// performs before deriving a tier. Called fresh on every Decide, the
	// same no-caching-layer choice LoadAgent and LoadChain already make for
	// their own per-tenant data — kept consistent rather than special-cased
	// for this one lookup.
	LoadToolCatalog(ctx context.Context) ([]models.ToolCatalogEntry, error)

	// LoadTierOverrides loads the tenant's tier_overrides rows as the map
	// authz.TierTable.Overrides is keyed by — the FIRST step of §4.4's
	// resolution order, which had no reader on this path until Phase 14 Task
	// 7 despite DeriveTier having consulted it since Phase 2. Called fresh on
	// every Decide, alongside LoadToolCatalog and for the same reason: no
	// caching layer, kept consistent with every other per-tenant read here.
	//
	// What comes back is what is stored, unfiltered. Decide re-validates each
	// row against the live baseline before honoring it — see its own call
	// site, and authz.TierTable.Overrides's doc comment for why that check
	// belongs to the caller that also holds the catalog.
	LoadTierOverrides(ctx context.Context) (map[string]models.ActionTier, error)

	// LoadResourceLabelRules loads the tenant's resource_label_rules rows
	// (spec §3.9.1 R4) — the whole set, unfiltered, because the matching is
	// pkg/classification.Resolve's and a second matcher in SQL would be free
	// to disagree with it (store.LoadResourceLabelRules's own doc comment).
	// Called fresh on every Decide, alongside LoadToolCatalog and
	// LoadTierOverrides and for the same reason: no caching layer, kept
	// consistent with every other per-tenant read here.
	LoadResourceLabelRules(ctx context.Context) ([]classification.Rule, error)

	// LoadDelegation loads one delegation row by id, without walking its
	// parent chain — token.go's IssueToken (re-issuance) is its only
	// caller, and it needs only this row's own liveness (revoked, expired,
	// this tenant via RLS), never the full chain LoadChain assembles for
	// three-leg evaluation. *store.Store's own doc comment on the method
	// covers why this is a deliberately smaller operation than LoadChain,
	// not a redundant one.
	LoadDelegation(ctx context.Context, id uuid.UUID) (*models.Delegation, error)

	// LoadTenantEpoch reads the tenant's current revocation epoch (spec
	// §4.8.1 V3). loadEpochOrDeny (below) is this interface's only caller,
	// and it calls this method first, before any other method on this
	// interface, on every RPC that reads it — see that method's own doc
	// comment for why that ordering is the entire point.
	LoadTenantEpoch(ctx context.Context) (int64, error)

	// SpendProof records a DPoP proof's jti as spent, returning
	// store.ErrProofSpent on a replay (spec §4.7.2 K8). Decide's spendProof
	// (dpop.go) is its only caller and invokes it AFTER LoadTenantEpoch, never
	// beside the local proof checks — it is a write, and V3 admits no store
	// call ahead of the epoch. It is also the LAST credential check, so a
	// proof that fails any cheaper one never burns a jti; see dpop.go's own
	// package doc for both halves of that argument.
	SpendProof(ctx context.Context, jti string, expiresAt time.Time) error
}

// TokenSigner is what this package needs from internal/token to both mint
// and verify a bearer credential naming a delegation. *token.Signer
// satisfies it; tests substitute a fake that can be made to fail on demand,
// the same reason Store above is a local interface rather than *store.Store
// directly — exercising "a signing failure fails the call" (CreateDelegation,
// IssueToken, token.go) or "a verification failure denies" (Decide,
// authenticate.go) needs a seam no real EC key can be made to fail through.
//
// Defined here, where it is consumed, rather than in package token, which
// has no reason to know about its gRPC caller — the same layering Store
// documents for itself just above. Two methods, not one, as of Task 3: Sign
// backs CreateDelegation/IssueToken, Verify backs Decide — one interface
// because both are the same underlying capability (internal/token.Signer
// holding one key pair), not two, so a Server wired with a signer that can
// only do one of these does not typecheck.
type TokenSigner interface {
	Sign(claims jwt.MapClaims) (string, error)

	// Verify parses and validates tokenString, returning its claims.
	// internal/token.Signer's own doc comment covers what "validates" means
	// (signature against the current or previous key, algorithm restricted
	// to ES256, expiry required and checked) — this interface adds nothing
	// beyond naming the method Decide calls.
	Verify(tokenString string) (jwt.MapClaims, error)

	// VerifySignature checks the signature and algorithm only, so an expired
	// token passes. IssueToken's one use for it: authenticating a re-issue
	// request by the token being replaced. Never a basis for a decision.
	VerifySignature(tokenString string) (jwt.MapClaims, error)
}

// eventTypeDecision is the audit_chain event_type recorded for every Decide
// call. Not a documented convention anywhere else in the schema, but it is
// the value pkg/audit, internal/store's, and internal/authz's own tests all
// already use for a decision entry — matched here rather than invented anew.
const eventTypeDecision = store.EventTypeDecision

// auditDeclaredTierAbsent is stored in an audit entry's DeclaredTier when the
// request did not declare one. audit_chain.declared_tier is a plain SMALLINT
// with no CHECK constraint pinning it to the valid ActionTier range (0-4:
// see migrations/000003_audit_chain.up.sql), so -1 can never collide with a
// real declared tier — unlike 0, which is REASONING, a real, declarable
// value. Same absent-vs-zero reasoning as DecideRequest.declared_tier.
const auditDeclaredTierAbsent int16 = -1

// errZeroUUID rejects the zero UUID even when it parses cleanly:
// "00000000-0000-0000-0000-000000000000" is a well-formed string but never a
// legitimate agent or delegation identifier, and proceeding with one would
// mean querying the store for a record that cannot exist.
var errZeroUUID = errors.New("must not be the zero UUID")

// Server implements PDPServiceServer.
type Server struct {
	UnimplementedPDPServiceServer

	store Store

	// policy decides the principal leg for Decide (one action, one
	// evaluation, via Evaluate) and also backs CreateDelegation's grant
	// probes (delegation.go), which need a policy.CompiledPolicySet to
	// probe several times over for one grant request rather than a single
	// per-action verdict — policy.Multi's PrepareAll is what supplies that,
	// so both RPCs are served from this one field. Earlier this was a
	// policy.PrincipalPolicy plus a raw PolicySource/PolicyEngine pair
	// CreateDelegation prepared itself, because policy.Configured (the
	// single-engine predecessor) had no way to hand back a compiled set
	// through the PrincipalPolicy interface it returned. policy.Multi
	// exposes PrepareAll directly, so that pair — and the single-language
	// assumption it carried — is gone rather than fixed twice.
	policy policy.Multi

	cfg config.Config

	// signer mints tokens for CreateDelegation and IssueToken (token.go).
	// The PDP is the sole signing-key holder (spec A4) — signer is the only
	// place that authority enters this package, and internal/authz never
	// sees it at all (that package stays pure: no cryptography, per the
	// phase's global constraints).
	signer TokenSigner

	// principals authenticates a root delegation's principal. nil means the
	// operator opted out (cfg.PrincipalAuthInsecure); see resolvePrincipal
	// (delegation.go), which refuses nil without that opt-out.
	principals PrincipalVerifier
}

// NewServer wires a Server. cfg supplies the tenant and the maximum
// delegation depth; both are startup configuration, never per-request.
// signer is required — every caller of this constructor supplies one,
// matching every other dependency here (store, principalPolicy, cfg) having
// no nil-means-something-sensible default. cmd/stratium-pdp/main.go builds
// its signer via internal/token.Load at startup, before this constructor is
// ever called. There is no signer-optional path left to be safe about, as
// there was before Task 3: Decide now calls signer.Verify on every request
// (spec §4.7.1 K4), not only CreateDelegation/IssueToken's own signer.Sign
// calls, so a nil signer here panics on a test's very first Decide call
// rather than only on a CreateDelegation/IssueToken one — every test in this
// package passes a real signer now.
func NewServer(store Store, principalPolicy policy.Multi, cfg config.Config, signer TokenSigner) *Server {
	return &Server{
		store:  store,
		policy: principalPolicy,
		cfg:    cfg,
		signer: signer,
	}
}

// loadEpochOrDeny reads the tenant's current revocation epoch and is the
// only way any RPC in this package does — Decide, CreateDelegation, and
// IssueToken (server.go, delegation.go, token.go) all call this, and none
// of them call s.store.LoadTenantEpoch directly.
//
// Every one of those three callers invokes this FIRST, before any other
// store method: Decide before LoadAgent, CreateDelegation before LoadAgent,
// IssueToken before LoadDelegation. This is spec §4.8.1 V3, and getting it
// backwards is unsafe in a specific, non-obvious direction:
//
//	read policies at N -> bump to N+1 (a revocation) -> read epoch = N+1
//	   => the decision ignored the revocation but is labelled current. UNSAFE.
//
// Reading first means whatever this call goes on to compute can only ever
// be labelled with an epoch OLDER than or equal to the state it actually
// reflects, never newer — a consumer that later compares this value against
// a fresher one invalidates at least as eagerly as it should, conservative
// in the safe direction. Reading last (or anywhere but first) risks the
// opposite: a response that looks current but was computed against
// already-stale state, which is precisely the class of bug a cache built on
// this value would exist to prevent and would instead reintroduce.
//
// A read failure denies outright — codes.Internal, no response at all, the
// same bare-RPC-error shape LoadAgent/LoadChain failures already take in
// Decide (never denyAndAudit's audited-DENY shape, since by construction
// nothing else has been read yet for an audit row to usefully add beyond
// the status code). There is no fallback value on a failure: an epoch
// reported too LOW would let a consumer accept a decision as current when
// it is not — the dangerous direction — while one reported too HIGH only
// invalidates needlessly, so the only safe move on a read this system
// cannot perform is to report nothing and refuse the call, never to guess
// low by substituting zero or any other default.
func (s *Server) loadEpochOrDeny(ctx context.Context) (int64, error) {
	epoch, err := s.store.LoadTenantEpoch(ctx)
	if err != nil {
		return 0, status.Errorf(codes.Internal, "load tenant epoch: %s", err)
	}
	return epoch, nil
}

// Decide turns req into a decision.
//
// Order: parse and validate the request's shape -> authenticate the token
// (authenticate.go: verify it and read the delegation id it names — spec
// §4.7.1 K4, the PDP's only gate on who is calling) -> check the DPoP proof's
// LOCAL half, if the token is bound (dpop.go's matchProof: signature,
// freshness, thumbprint, htm/htu — no store access, so it belongs with the
// token check) -> read the tenant's revocation epoch (loadEpochOrDeny, spec
// §4.8.1 V3 — the first store CALL of any kind on this path, ahead of the
// spend below as well as the agent, the chain, and the policies, so a
// revocation racing this call can only make the response look older than
// it actually is, never newer; see loadEpochOrDeny's own doc comment for
// why) -> spend the proof's jti (dpop.go's spendProof: the store half, last
// of the credential checks, so nothing cheaper can burn a jti on its way to
// failing) -> load the acting agent -> load the delegation chain that id names
// -> evaluate (tenant from cfg, principal decision from policy, clock from
// time.Now — the one boundary where the ambient clock is allowed, so
// internal/authz itself stays pure)
// -> resolve an escalation, if any (escalation.go: create a pending
// approval, or verify one offered on a retry — the one place approval
// verification happens, since it needs the store and internal/authz must
// not) -> append the audit entry -> respond. A failed audit append returns
// an error and no response: spec D3 says a failed audit write denies the
// action, and the only way that holds for an ALLOW is for this method to
// never hand one back once the append has failed.
//
// Authentication buys nothing past "which delegation" (K3). A token that
// verifies is not trusted for anything about that delegation's own current
// state — the load and all three legs below run exactly as they would have
// from a bare id, so a revoked or expired delegation still denies there, at
// the delegation leg, never at the token check above it. The same holds for
// the proof: it proves possession of the bound key for this one request, and
// buys nothing about the delegation either.
//
// Neither the token check nor the proof check is a fourth leg, and this task
// did not make one. The compound decision is still principal ∧ agent ∧
// delegation, folded by authz.FoldVerdicts — untouched here, and the single
// place deny-overrides-with-default-deny lives. A credential that fails
// verification denies through denyAndAudit before authz.Decide is ever
// called, so there is nothing for the fold to see.
func (s *Server) Decide(ctx context.Context, req *DecideRequest) (*DecideResponse, error) {
	agentID, err := parseNonNilUUID(req.GetAgentId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "agent_id: %s", err)
	}
	if req.GetSubject() == "" {
		return nil, status.Error(codes.InvalidArgument, "subject is required")
	}
	var declaredTier *models.ActionTier
	if req.DeclaredTier != nil {
		tier, err := models.ParseActionTier(int(*req.DeclaredTier))
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "declared_tier: %s", err)
		}
		declaredTier = &tier
	}
	// approvalID is present only on a retry after a prior call returned
	// EFFECT_ESCALATE (DecideRequest.approval_id's own doc comment).
	// Malformed shape is rejected here, alongside every other caller-
	// supplied UUID, because it is a request-shape defect (InvalidArgument,
	// no store call, no decision) — not a verification failure, which fails
	// closed to a named, audited DENY instead (resolveEscalation, below).
	var approvalID *uuid.UUID
	if req.ApprovalId != nil {
		id, err := parseNonNilUUID(req.GetApprovalId())
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "approval_id: %s", err)
		}
		approvalID = &id
	}

	now := time.Now()
	// Verb and NormalizedInput start unset, deliberately: DecideRequest no
	// longer carries either (spec §4.4.2 T3 retired both from the wire
	// alongside the PEP's per-tool tables that used to compute them). Both
	// are populated below, per tool, only when the tenant's own catalog
	// names this one — authz.ApplyExtraction — never from a caller's claim.
	// Built here, ahead of authentication, so a token failure below still
	// has a Tool/RawInput to audit — an operator reading a row denied for a
	// bad token still wants to know what the caller was trying to do.
	action := authz.Action{
		Tool:         req.GetTool(),
		RawInput:     req.GetRawInput(),
		DeclaredTier: declaredTier,
	}

	// Authenticate before anything else touches the store (spec §4.7.1 K4):
	// a token is now the ONLY thing that identifies which delegation this
	// call presents (authenticate.go's own doc comment covers the K3
	// boundary this does not cross — authentication, never authorization).
	// Checking this first means an invalid token costs one audit write,
	// never an agent lookup or a chain load — the same cheapest-check-first
	// discipline the InvalidArgument checks above already follow. Unlike
	// those, a bad token still produces an audited DENY, not a bare RPC
	// error: it is a fact about a presented credential, not a malformed
	// request shape, and the audit trail is exactly where "someone tried
	// and failed to authenticate" belongs. denyAndAudit is the same
	// pre-decision-denial helper a catalog load failure and a DeriveTier
	// failure already share below — see its own doc comment for why a
	// third caller here does not risk the three drifting apart.
	delegationID, jkt, err := s.authenticateToken(req.GetToken())
	if err != nil {
		// No epoch to report: loadEpochOrDeny has not run yet on this path,
		// and there is no legitimate value to substitute for "never read" —
		// see toResponse's own doc comment on why nil, not zero, is what a
		// genuinely-never-read epoch must produce on the wire.
		return s.denyAndAudit(ctx, agentID, uuid.Nil, nil, action, req.GetSubject(), now, err, nil)
	}

	// Every LOCAL half of the proof-of-possession check (spec §4.7.2 K7),
	// here beside authenticateToken for the same reason that check sits ahead
	// of every store call: parse, signature, freshness, thumbprint-versus-
	// cnf.jkt and htm/htu are pure computation over bytes already in hand.
	// The one part that is NOT local — spending the jti, which is a store
	// write — deliberately does not run here; it runs after the epoch read
	// below. dpop.go's package doc carries both reasons for that split.
	//
	// matched is nil with a nil error for an unbound (bearer) token, which
	// still decides normally: K5 puts that refusal at the two network
	// surfaces, not here, because refusing it here would deny every local-
	// surface caller (hook, mcp). Reported on the response instead, below.
	matched, err := s.matchProof(req, jkt, now)
	if err != nil {
		// Same shape and same nil epoch as the token failure just above: a
		// proof that does not verify is a fact about a presented credential,
		// audited like one, and loadEpochOrDeny still has not run.
		//
		// delegationID, NOT uuid.Nil, unlike that failure: the token verified
		// here, so the id is known and correct, and an operator reading this
		// row needs to know WHICH delegation's token was presented with a bad
		// proof. Only chain is still nil — nothing has loaded it yet.
		return s.denyAndAudit(ctx, agentID, delegationID, nil, action, req.GetSubject(), now, err, nil)
	}

	epoch, err := s.loadEpochOrDeny(ctx)
	if err != nil {
		return nil, err
	}

	// The store half of the credential check, and the FIRST store write on
	// this path — after the epoch read (V3: the epoch must be the first store
	// call of any kind) and after every cheaper check has already passed, so
	// a malformed or stolen proof can never burn a jti an honest client might
	// legitimately retry with. See dpop.go's package doc: two independent
	// arguments, one placement.
	if matched != nil {
		if err := s.spendProof(ctx, *matched); err != nil {
			// delegationID again, for the reason above and more sharply: a
			// replay denial that recorded no delegation would leave an
			// operator watching a replay storm unable to say which
			// credential is being replayed — in the one feature built to
			// make replay visible.
			return s.denyAndAudit(ctx, agentID, delegationID, nil, action, req.GetSubject(), now, err, &epoch)
		}
	}

	agent, err := s.store.LoadAgent(ctx, agentID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "agent %s: %s", agentID, err)
		}
		return nil, status.Errorf(codes.Internal, "load agent: %s", err)
	}

	// delegationID is what the token named, above — never a bare wire field
	// (K4). A token naming a delegation that belongs to another tenant, or
	// none at all, is NotFound here via RLS (store.go's own package doc),
	// exactly like every other lookup in this service — not a verification
	// failure, and not a special case: LoadChain does not know or care
	// whether delegationID came from a token or, as it always did before
	// this task, a bare field.
	chain, err := s.store.LoadChain(ctx, delegationID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "delegation %s: %s", delegationID, err)
		}
		return nil, status.Errorf(codes.Internal, "load chain: %s", err)
	}

	principal := authz.Principal{Subject: req.GetSubject()}
	resource := req.GetResource()

	// The tenant's own tool_catalog rows (spec §4.4.2 T1/T2), loaded fresh
	// for this decision. A load failure fails closed rather than proceeding
	// as though the tenant had none: a row that exists but could not be read
	// might be the one row that would have raised this tool's tier, and
	// silently falling back to DefaultCatalog() in that case would be
	// exactly the "skipped row" the phase brief rules out. Routed through
	// denyAndAudit — the same deny-and-audit shape a DeriveTier failure uses
	// below — rather than a bare codes.Internal, so this failure is audited
	// identically to any other pre-decision denial instead of only ever
	// surfacing as an RPC error with no row in the audit chain.
	catalogEntries, err := s.store.LoadToolCatalog(ctx)
	if err != nil {
		return s.denyAndAudit(ctx, agentID, delegationID, chain, action, req.GetSubject(), now,
			fmt.Errorf("load tool catalog: %w", err), &epoch)
	}

	// Extraction happens before tiers is even built, and touches only
	// action.Verb, action.NormalizedInput, and resource — never
	// action.RawInput (see authz.ApplyExtraction's own doc comment).
	// DeriveTier below re-scans RawInput for destructive-or-external
	// evidence unconditionally (tier.go's destructiveEvidence), so the order
	// extraction runs in relative to that scan cannot matter: nothing on
	// this path can narrow what the evidence check sees.
	//
	// A harness hook's own name for a tool is renamed to the canonical one
	// first (authz.ResolveAlias), so the catalog, the tier table, the tool
	// lists and the policies below all see one vocabulary. Only a caller
	// that names its harness gets this; see DecideRequest.harness.
	action, alias := authz.ResolveAlias(req.GetHarness(), catalogEntries, action)
	var extracted authz.ExtractedInput
	if alias != nil {
		extracted = authz.ExtractAliased(catalogEntries, action, *alias)
	} else {
		extracted = authz.ExtractFromCatalog(catalogEntries, action)
	}
	action, resource = authz.ApplyExtraction(extracted, action, resource)

	// The tenant's own resource_label_rules (spec §3.9.1 R4), loaded fresh
	// for this decision and failing closed exactly as the catalog above does
	// — same argument, one table over: a row that exists but could not be
	// read might be the one row that labels this resource, and proceeding as
	// though the tenant had none would deny it under R2 with nothing in the
	// audit trail saying the rules were never read. Routed through
	// denyAndAudit for the same reason too.
	//
	// After the epoch (V3 admits no store call ahead of it —
	// TestDecide_EpochIsTheFirstStoreRead is the guard) and after
	// ApplyExtraction, which is what produces the resource identity there is
	// anything to resolve. Before the tier table is built, so the label is on
	// the resource map every downstream consumer sees: the policy provider's
	// EvaluationInput, and the delegation leg's own ResourceConstraints and
	// CheckCap.
	labelRules, err := s.store.LoadResourceLabelRules(ctx)
	if err != nil {
		return s.denyAndAudit(ctx, agentID, delegationID, chain, action, req.GetSubject(), now,
			fmt.Errorf("load resource label rules: %w", err), &epoch)
	}
	// extracted.ResourceID, never resource["id"]: the label may only ever be
	// resolved against an identity this PDP derived itself, from raw_input,
	// through the tenant's own catalog row. See labelResource's own doc
	// comment for why reading it back out of the map instead let a caller
	// choose which rule labelled it.
	//
	// A command-field tool (Bash) yields no single resource id, so its command
	// text contributes every path it names and labelResource folds them to the
	// strictest — closing J1, where any configured cap denied every shell call
	// permanently. ShellResourceIDs interprets a value, so it lives beside the
	// tier classifier in internal/authz and never in extract.go, which may look
	// up which field holds a value and never what the value means.
	//
	// extracted.ResourceID is included only when non-empty. labelResource's own
	// fold already treats "" as "not an id" and skips it (label.go:130), but
	// checkResourceConstraints' satisfiesIDPrefix (internal/authz/constraints.go)
	// does not -- it reads a non-empty ids slice as "this call resolved to a
	// checkable identity" and fails "" against any non-empty prefix. Appending
	// the empty string unconditionally would deny every in-scope shell call
	// under an id_prefix constraint, on an id nothing ever claimed.
	var resourceIDs []string
	if extracted.ResourceID != "" {
		resourceIDs = append(resourceIDs, extracted.ResourceID)
	}
	if extracted.Command != "" {
		resourceIDs = append(resourceIDs, authz.ShellResourceIDs(extracted.Command)...)
	}
	// An aliased call the PDP can name no resource for is refused. The alias
	// makes it the canonical tool for every rule below, and those rules were
	// written for calls that say which resource they touch.
	// ponytail: refuses every aliased tool with no resource (today only
	// Codex's apply_patch, whose paths are inside the patch text). Read the
	// paths, or mark resource-less aliases as such, when one needs to pass.
	if alias != nil && len(resourceIDs) == 0 {
		return s.denyAndAudit(ctx, agentID, delegationID, chain, action, req.GetSubject(), now,
			fmt.Errorf("%w: %q names no resource the PDP can read", errAliasedNoResource, action.WireTool), &epoch)
	}
	resource = labelResource(labelRules, resource, resourceIDs)

	// The catalog step of §4.4's resolution order (override, catalog,
	// built-in): the tenant's own rows override DefaultCatalog() per tool,
	// and a tenant with none yet resolves through an unchanged
	// DefaultCatalog() — see BuildTierCatalog's own doc comment for why that
	// is the regression guard that makes shipping this table safe.
	tiers := authz.TierTable{Catalog: authz.BuildTierCatalog(catalogEntries, authz.DefaultCatalog())}

	// The override step, the one above it. A load failure fails closed for
	// the identical reason the catalog load above does, and it is worth
	// stating separately because the direction is the same but the argument
	// is not: an override exists only to RAISE a tier, so proceeding as
	// though the tenant had none would under-rate precisely the actions it
	// took the trouble to mark as more sensitive.
	storedOverrides, err := s.store.LoadTierOverrides(ctx)
	if err != nil {
		return s.denyAndAudit(ctx, agentID, delegationID, chain, action, req.GetSubject(), now,
			fmt.Errorf("load tier overrides: %w", err), &epoch)
	}
	tiers.Overrides = honoredOverrides(storedOverrides, tiers.Catalog, catalogEntries)

	// Derived ahead of authz.Decide so the policy engine can see it (spec Y3):
	// DeriveTier is pure, and Decide (below) derives it again, independently,
	// from these same inputs — that second derivation stays authoritative for
	// the actual decision, so this one cannot itself widen anything.
	//
	// On error, this does NOT return codes.Internal directly: Decide's own
	// re-derivation (same tiers, same action) would hit this identical error
	// and deny-and-audit via authz.DeriveTierDenial — bailing out here first,
	// before principal verdicts are even evaluated, would bypass the audit
	// trail on exactly the same error Decide always audits. Building that
	// same Result here, through the same shared function, keeps both call
	// sites deny-and-audit rather than two paths that could report the
	// identical failure differently.
	derivedTier, err := authz.DeriveTier(tiers, action)
	if err != nil {
		return s.denyAndAudit(ctx, agentID, delegationID, chain, action, req.GetSubject(), now, err, &epoch)
	}

	// acting is the delegation the agent is presenting — the last hop.
	// LoadChain guarantees chain is non-empty on a nil error (see
	// appendAudit below, which makes the same assumption).
	acting := chain[len(chain)-1]

	// The policy provider returns every verdict it consulted for the
	// principal leg; authz.Decide folds them with deny-overrides via
	// authz.FoldVerdicts. It now sees the agent and delegation dimensions
	// too, so a tenant can condition on them, but it still only decides the
	// principal leg — the agent and delegation legs below are independent
	// AND terms, so nothing returned here can widen what they allow.
	principalVerdicts := s.policy.Evaluate(ctx, policy.EvaluationInput{
		Principal:   principal,
		Action:      action,
		DerivedTier: derivedTier,
		Resource:    resource,
		Agent:       agent,
		Delegation: policy.DelegationContext{
			Depth:              acting.Depth,
			MaxActionTier:      acting.MaxActionTier,
			ClassificationCaps: acting.ClassificationCaps,
			Purpose:            acting.Purpose,
		},
	})
	result := authz.Decide(authz.Request{
		TenantID:  s.cfg.TenantID, // config only. Never req — see package doc.
		Principal: principal,
		Agent:     agent,
		Chain:     chain,
		Action:    action,
		Resource:  resource,
		// The same identities labelResource above already resolved for this
		// call — not recomputed, so the label and the delegation leg's
		// id_prefix check can never disagree about what this call touched.
		ResourceIDs:       resourceIDs,
		Now:               now,
		PrincipalVerdicts: principalVerdicts,
	}, authz.Config{
		Tiers:    tiers,
		Trust:    authz.DefaultTrustTable(),
		MaxDepth: s.cfg.MaxDepth,
	})

	// Escalation only ever reaches here through the compound decision every
	// other outcome does too — authz.Decide has already run all three legs
	// fresh, on this exact call, and its own deny-check loop runs before its
	// escalate-check loop (compound.go), so a leg that denies (a revoked
	// delegation, a policy that now forbids) has already won by the time
	// Effect could read EFFECT_ESCALATE. An approval is therefore never
	// consulted for a request the three legs would have denied anyway —
	// see resolveEscalation's own doc comment (escalation.go) for why that
	// holds by construction rather than by a check repeated here, and why
	// this is also what keeps a decision above max_action_tier from ever
	// creating an approval row: that case denies before it ever escalates.
	var newApprovalID string
	if result.Effect == authz.EffectEscalate {
		result, newApprovalID, err = s.resolveEscalation(
			ctx, approvalID, req.GetSubject(), agentID, delegationID, chain, action, result, now)
		if err != nil {
			return nil, err
		}
	}

	if err := s.appendAudit(ctx, agentID, delegationID, chain, action, req.GetSubject(), result, now); err != nil {
		return nil, err
	}

	// ApprovalId is not part of authz.Result — it is a wire-only fact
	// (which row, if any, this call just created), not a decision fact — so
	// it is attached here rather than threaded through toResponse. It is
	// only ever non-empty on the fresh-escalation branch above: a verified
	// retry converts result.Effect to ALLOW or DENY, never leaves it
	// ESCALATE, so newApprovalID stays "" on every other path, matching
	// approval_id's own doc comment in the proto (populated only when
	// effect is EFFECT_ESCALATE).
	resp := toResponse(result, &epoch)
	resp.ApprovalId = newApprovalID
	// A wire-only fact, attached here exactly like ApprovalId above and for
	// the same reason: it is not a decision fact, so authz.Result has nothing
	// to name it with, and toResponse has no business knowing what a proof is.
	// matched is non-nil only when a bound token's proof passed every check
	// AND its jti was spent — both above — so this can never read true for a
	// token that was merely bound. See the proto's own doc comment for why the
	// PDP reports this rather than refusing (K5 belongs at the surfaces).
	//
	// This is Decide's TAIL, which every three-leg outcome reaches — allow,
	// deny at a leg, and escalate alike. So a bound token with a valid proof
	// that is then denied at the principal leg reports TRUE: the field
	// describes what the caller presented, and that does not depend on the
	// verdict. Only the six denyAndAudit early returns bypass this line, and
	// they leave it false meaning "not established", never "bearer token".
	// The proto's own comment states that rule; TestDecide_SenderConstrained
	// IsSetOnALegDenialButNotOnAPreDecisionDenial holds the two halves of it
	// apart, because this comment has already been wrong once.
	resp.SenderConstrained = matched != nil
	return resp, nil
}

// honoredOverrides is the read-time half of §4.4's raise-only rule (T5): it
// returns the subset of stored that this decision may honor, each row
// re-checked against the resolution beneath it in the tenant's LIVE catalog
// — authz.OverrideBaseline, the same function the PAP's write path computes
// its baseline with, and authz.ValidateOverride, the same comparison. Both
// ends call the identical pair; neither reimplements the other.
//
// Re-checking here is not belt-and-braces over the write-time call. Three
// things it catches that nothing else can:
//
//   - A direct INSERT as a database superuser never passes through the PAP.
//     The schema's own tier_overrides_raise_only CHECK does not stop it
//     either: that CHECK compares action_tier against the builtin_tier
//     COLUMN, which such a write supplies for itself.
//   - The stored builtin_tier is a snapshot. A tenant that catalogs a tool
//     as DESTRUCTIVE after writing a WRITE override on it has left a row
//     that was valid when written and is a lowering now. This is why the
//     check recomputes rather than reading that column — reading it would
//     re-validate against exactly the stale value that caused the problem.
//   - An override on a key whose baseline moved for any other reason at all.
//
// A failing row is DROPPED, not fatal, and the distinction is deliberate:
// dropping falls through to the tier beneath the override, which is by
// construction HIGHER than what the row claimed — the safe direction —
// whereas failing the decision would let one bad row deny an entire tenant
// every action, turning a misconfiguration into an outage. Fail closed, not
// catastrophically.
//
// Dropped is not silent. An operator whose override is being ignored has to
// be able to find out why, and a row that fails this check is either a
// configuration mistake or a write that bypassed the control plane — both
// are things somebody needs to see. A log line, not a metric: this codebase
// has no metrics surface at all (no Prometheus, no OpenTelemetry, in any
// binary), so a metric would mean introducing one for a single counter,
// while slog is already the PDP's logging (cmd/stratium-pdp/main.go, which
// calls slog.SetDefault so these lines land in the same handler and stream
// as every other line that binary emits). A counter alone would also answer
// "how many" without answering "which one", which is the only question an
// operator actually has here.
//
// What is logged is the key, the tier claimed, and the baseline it failed
// against — enough to fix the row, and nothing else. Not the tenant (this
// process serves exactly one, named at startup), not created_by (the
// decision path does not even select that column — store.LoadTierOverrides's
// own doc comment), and nothing about the request that happened to observe
// the bad row.
func honoredOverrides(
	stored, catalog map[string]models.ActionTier, entries []models.ToolCatalogEntry,
) map[string]models.ActionTier {
	honored, dropped := authz.HonoredOverrides(
		authz.TierTable{Catalog: catalog, Overrides: stored}, entries)
	for _, d := range dropped {
		slog.Warn("tier override dropped: it would lower the tier resolved beneath it",
			"tool_or_verb", d.Key, "override_tier", d.Override.String(), "baseline_tier", d.Baseline.String())
	}
	return honored
}

// appendAudit builds the audit entry for one decision and appends it.
//
// chain is empty on the three of Decide's SIX pre-decision denials that
// happen before LoadChain runs: a token that failed authentication, a DPoP
// proof that failed verification, and a jti that could not be spent (Decide's
// own call sites; denyAndAudit's doc comment below enumerates all six and
// covers why they route through this same function rather than each inlining
// its own copy). Every other caller reaches this only after LoadChain has
// already succeeded — Decide's success/escalation path, plus a tool-catalog
// load failure, a tier-override load failure, and a DeriveTier failure — so
// for them chain is non-empty and delegationID is always
// chain[len(chain)-1].ID by construction; LoadChain guarantees as much on a
// nil error.
//
// delegationID and chain are therefore NOT the same question, and this
// function treats them separately. Only ONE of the six pre-decision paths
// has no delegation id at all: an authentication failure, where the token
// never yielded one. On the other five the token verified — the id is known
// and correct — and on the two DPoP paths the chain simply was not loaded
// yet. Writing NULL there
// would lose the single most useful fact about a replay: WHICH delegation's
// token is being replayed. An operator investigating a replay storm would
// see the agent and the actor and nothing to connect them to a credential,
// in the one feature built to make replay visible. So DelegationID is
// populated whenever it is non-nil, and the chain-derived fields
// (RootDelegationID, ChainDepth) stay gated on chain, which is the only
// thing that can supply them.
//
// PolicySource/PolicyID are populated from result.Deciding, guarded against
// nil exactly as toResponse guards it: left at their zero value ("") for the
// default-deny-with-no-verdict case, which audit.Entry's own doc comment
// already documents as the meaning of "empty" there.
//
// UnevaluatedPolicyIDs is copied unconditionally, not guarded by
// result.Deciding: it is authz.Decide's own aggregate across every verdict
// it saw (internal/authz/compound.go), independent of which single verdict
// Deciding names — that independence is the entire point (see
// authz.Result.UnevaluatedPolicyIDs' own doc comment), so gating it on
// Deciding here would reintroduce exactly the loses-the-fold defect the
// aggregate exists to avoid.
func (s *Server) appendAudit(
	ctx context.Context,
	agentID, delegationID uuid.UUID,
	chain []*models.Delegation,
	action authz.Action,
	actor string,
	result authz.Result,
	now time.Time,
) error {
	declaredTier := auditDeclaredTierAbsent
	if action.DeclaredTier != nil {
		declaredTier = int16(*action.DeclaredTier) //nolint:gosec // G115: ActionTier is range-checked to 0-4 by models.ParseActionTier before it ever reaches here
	}

	// Raw tool input is never stored, only its digest — see pkg/audit's
	// package doc.
	digest := sha256.Sum256([]byte(action.RawInput))

	entry := audit.Entry{
		TenantID:             s.cfg.TenantID,
		OccurredAt:           now,
		EventType:            eventTypeDecision,
		Actor:                actor,
		AgentID:              &agentID,
		ToolName:             action.RecordedTool(),
		Action:               action.Verb,
		DeclaredTier:         declaredTier,
		DerivedTier:          int16(result.DerivedTier), //nolint:gosec // G115: models.ActionTier is a 0-4 enum
		Decision:             result.Effect.String(),
		DeniedLeg:            result.DeniedLeg,
		DeniedAtDepth:        int16(result.DeniedAtDepth), //nolint:gosec // G115: -1 sentinel or a chain depth bounded well under int16's range (see ChainDepth above)
		Reason:               result.Reason,
		UnevaluatedPolicyIDs: result.UnevaluatedPolicyIDs,
		InputDigest:          digest,
	}

	// The row names the tool as the caller sent it. When an alias applied,
	// say which tool it was decided as: without that, a reader sees
	// "apply_patch" allowed by a rule that only mentions "Edit".
	if action.WireTool != "" {
		entry.Reason = strings.TrimSpace(fmt.Sprintf("%s [%s decided as %s]", entry.Reason, action.WireTool, action.Tool))
	}

	// DelegationID is gated on delegationID itself, NOT on chain: the two
	// answer different questions (this function's own doc comment above). A
	// proof or spend failure knows exactly which delegation the verified
	// token named and has simply not loaded the chain yet, and dropping that
	// id would blind an operator to which credential is being replayed.
	//
	// nil rather than a pointer to the zero UUID when it genuinely is not
	// known — an authentication failure — so that row stays honest: this
	// decision never identified a delegation at all, which is a different
	// fact than "identified the zero UUID". DelegationID and
	// RootDelegationID are nullable columns for exactly this reason
	// (migrations/000003_audit_chain).
	if delegationID != uuid.Nil {
		entry.DelegationID = &delegationID
	}
	// RootDelegationID/ChainDepth stay gated on chain, which is the only
	// thing that can supply either: the root is chain[0] and the depth is the
	// acting hop's, neither of which a bare id yields.
	if len(chain) > 0 {
		acting := chain[len(chain)-1]
		root := chain[0]
		entry.RootDelegationID = &root.ID
		entry.ChainDepth = int16(acting.Depth) //nolint:gosec // G115: store.maxChainWalk bounds any chain walk to 64 hops, far under int16's range
	}

	if d := result.Deciding; d != nil {
		entry.PolicySource = d.Source
		entry.PolicyID = d.PolicyID
	}

	if err := s.store.AppendAudit(ctx, entry); err != nil {
		if errors.Is(err, store.ErrConcurrentAppend) {
			return status.Errorf(codes.Aborted, "audit append: %s", err)
		}
		return status.Errorf(codes.Internal, "audit append: %s", err)
	}
	return nil
}

// denyAndAudit builds the DeriveTierDenial-shaped Result for err, appends
// the audit entry, and returns the wire response. SIX failures on Decide's
// pre-decision path resolve through this one function rather than each
// inlining its own copy of "build the denial, audit it, respond," so they are
// audited identically and cannot independently drift the way six hand-written
// copies of the same lines eventually would:
//
//  1. a token that failed authentication
//  2. a DPoP proof that failed verification
//  3. a jti that could not be spent
//  4. a tool catalog that could not be loaded
//  5. tier overrides that could not be loaded
//  6. a DeriveTier failure
//
// The list is numbered because it has now been wrong twice, in both
// directions: it said "three" while there were four (the tier-override
// failure was missing from the day it was added), and then "five" while there
// were six, because the count was re-derived by adding the two new DPoP paths
// to a list that was already short. Count the call sites, do not extend the
// sentence.
//
// DeriveTierDenial attributes every one of these to the "delegation" leg,
// including a token failure, which is not really about the delegation's own
// state at all: "delegation" is the only bucket audit_chain's denied_leg
// CHECK constraint offers a structural, pre-leg denial (migrations/000003;
// denyForApproval, escalation.go, makes the identical choice for the same
// reason, spelled out in its own doc comment). What tells a token failure
// apart from an actually-revoked delegation, for an operator reading the
// audit trail, is Reason's text, not DeniedLeg — see authenticateToken's
// own errors (authenticate.go) and
// TestDecide_TokenNamingRevokedDelegation_DeniesAtTheDelegationLeg
// (authenticate_test.go), which exists specifically to prove the two stay
// distinguishable and that a revoked delegation is denied by DelegationLeg's
// own re-evaluation, never by this function standing in for it.
//
// delegationID is uuid.Nil on exactly one caller's path — a token that
// failed authentication, which never yielded an id. The proof and spend
// failures pass the real, token-verified id even though chain is still nil,
// and appendAudit (above) is written to treat those two as the separate
// questions they are; see its own doc comment for why writing NULL there
// would lose the most useful fact about a replay.
//
// chain is nil on three paths — those two plus the authentication failure —
// since none of them has reached LoadChain.
//
// epoch is nil on the two that run BEFORE loadEpochOrDeny (authentication
// and the proof check; Decide's own call sites pass nil for exactly that
// reason) and non-nil on the other four, all of which run after a successful
// epoch read — including the spend failure, which is why a replay denial can
// honestly report an epoch where a bad-proof denial cannot. Forwarded
// straight to toResponse rather than re-decided here — this function has no
// opinion of its own on whether an epoch is available, only on how to audit
// and respond once that has already been decided by the caller.
func (s *Server) denyAndAudit(
	ctx context.Context,
	agentID, delegationID uuid.UUID,
	chain []*models.Delegation,
	action authz.Action,
	subject string,
	now time.Time,
	err error,
	epoch *int64,
) (*DecideResponse, error) {
	result := authz.DeriveTierDenial(err)
	if auditErr := s.appendAudit(ctx, agentID, delegationID, chain, action, subject, result, now); auditErr != nil {
		return nil, auditErr
	}
	return toResponse(result, epoch), nil
}

// errAliasedNoResource is Decide's refusal of an aliased call that carries
// no resource identity.
var errAliasedNoResource = errors.New("aliased tool call refused")

// parseNonNilUUID parses s as a UUID and rejects the zero value.
func parseNonNilUUID(s string) (uuid.UUID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil, err
	}
	if id == uuid.Nil {
		return uuid.Nil, errZeroUUID
	}
	return id, nil
}

// toResponse converts a decision into the wire response. Every field is
// populated explicitly, including the three per-leg pairs — leaving any of
// them at its zero value would silently read back as EFFECT_DENY with no
// reason, indistinguishable from a leg that was actually evaluated and
// denied for no stated reason.
//
// DecidedSource/DecidedPolicyId are the exception: they are left unset
// (nil), not zeroed, when result.Deciding is nil. That case is real — a
// default-deny with no verdict at all, from a nil/empty PrincipalVerdicts —
// and collapsing it into empty strings would make it indistinguishable from
// a verdict that did decide the outcome and whose Source/PolicyID happen to
// be empty. Both fields are proto3 optional for exactly that reason, the
// same presence-vs-zero-value pattern DecideRequest.declared_tier uses.
//
// epoch gets the identical presence-vs-zero-value treatment for the
// identical reason: nil means "never read" (Decide's one path that denies
// during authentication, before loadEpochOrDeny ever runs), which must stay
// distinguishable from a genuinely read value — including a real epoch that
// happens to equal some sentinel a lazier design might have reached for
// instead. result carries no epoch of its own (internal/authz stays pure —
// no store access, no ambient revocation state — so Result has nothing to
// name here); the caller reads it separately, via loadEpochOrDeny, and
// passes it in exactly as it already assembles everything else in resp
// from values authz.Decide alone could not have produced (DerivedTier's own
// int32 cast just below is the same shape: authz's value, converted at this
// one boundary).
func toResponse(result authz.Result, epoch *int64) *DecideResponse {
	resp := &DecideResponse{
		Effect:           toProtoEffect(result.Effect),
		DerivedTier:      int32(result.DerivedTier), //nolint:gosec // G115: models.ActionTier is a 0-4 enum
		PrincipalEffect:  toProtoEffect(result.Principal.Effect),
		PrincipalReason:  result.Principal.Reason,
		AgentEffect:      toProtoEffect(result.Agent.Effect),
		AgentReason:      result.Agent.Reason,
		DelegationEffect: toProtoEffect(result.Delegation.Effect),
		DelegationReason: result.Delegation.Reason,
		DeniedLeg:        result.DeniedLeg,
		DeniedAtDepth:    int32(result.DeniedAtDepth), //nolint:gosec // G115: -1 sentinel or a chain depth bounded well under int32's range
		Reason:           result.Reason,
		Epoch:            epoch,
	}

	if d := result.Deciding; d != nil {
		source, policyID := d.Source, d.PolicyID
		resp.DecidedSource = &source
		resp.DecidedPolicyId = &policyID
	}

	return resp
}

// toProtoEffect maps authz.Effect onto the wire enum explicitly rather than
// by numeric cast: the two are independently defined types that happen to
// share an ordering today, and a cast would keep compiling silently if that
// ever stopped being true.
func toProtoEffect(e authz.Effect) Effect {
	switch e {
	case authz.EffectAllow:
		return Effect_EFFECT_ALLOW
	case authz.EffectEscalate:
		return Effect_EFFECT_ESCALATE
	default:
		return Effect_EFFECT_DENY
	}
}
