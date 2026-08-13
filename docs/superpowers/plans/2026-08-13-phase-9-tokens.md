# Phase 9 — Token issuance and verification

Implements spec §3.2 **A4** and §4.7.1 **K1**–**K4**. Unblocks `proxy` and
`extauthz` per **A10**. Five tasks.

**Why now.** Two of four enforcement surfaces ship. The remaining two are
network intermediaries: the request reaches them *from the agent being policed*,
so a delegation reference can only arrive in a header that same agent controls.
An agent choosing its own delegation id is an agent choosing its own authority —
spec defect **D1** relocated, and worse, because a delegation id is a bearer
reference to a scope someone else was granted. A4's tokens are the answer the
spec already had; A10 recorded that they are a prerequisite rather than a later
nicety.

**The one thing that makes this worth building, restated.** **K4**: the bare
`delegation_id` path is removed. If `Decide` keeps accepting a bare id, a token
adds no security at all against that attacker — they omit the token and send the
id. The PDP cannot tell a trusted local `hook` from a hostile network client,
because under **A1** and **E7** it authenticates no callers. Two mechanisms, one
of them unauthenticated, is exactly as strong as the unauthenticated one.

So this phase changes `hook` and `mcp` too. That is not scope creep; it is the
difference between a token that means something and a token that decorates.

## Global constraints

- Go 1.25, module path `stratium`, module root `services/`.
- **`internal/authz` stays pure** — no database, no network, no ambient clock,
  and now no cryptography either. Signing and verification live beside the
  store and the server; `authz` never sees a token.
- **A token is an authenticated reference, never a capability** (K3). It names a
  delegation; the PDP still loads that delegation and all three legs still
  evaluate. A token whose delegation was revoked is denied *by the delegation
  leg*. Nothing in this phase may let a token's contents substitute for a
  loaded delegation.
- **Fail closed.** An absent, malformed, expired, wrongly-signed, or
  unparseable token denies. There is no path on which a token problem produces
  an allow, and none on which a token's absence falls back to a bare id.
- **The PDP is the sole signing-key holder** (A4). No other component signs, and
  the private key never leaves the process that loaded it.
- **Never log a token, a key, or a key path's contents.** A token names live
  authority; the existing rules about `raw_input` and approval ids apply with
  more force.
- Strict root `.golangci.yml`. Clean before each commit, from `services/`:
  `go build ./...`, `go vet ./...`, `go vet -tags integration ./...`,
  `go test -race ./...`, `golangci-lint run ./...`. Plus `make conformance` and
  `make integration` from the repo root.
- Conventional commits, no attribution trailers — check each message.
- Scratch work goes in the session scratchpad, never the repository.

---

## Task 1 — The signer, and key loading

**Files:** `services/internal/token/` (new), `services/internal/config/`, tests.

ES256 signing over a key loaded from a PEM file whose **path** comes from an
environment variable (K1). The env never holds the key material.

**Two keys, asymmetric roles.** A current key signs and verifies; an optional
previous key **verifies only**. Rotation then means mounting a new file and
restarting, without invalidating tokens issued seconds earlier. A previous key
that could sign would double the window in which a compromised old key still
mints authority — so make signing structurally impossible for it, not merely
unused.

**Required config has no defaults**, matching every other component. A missing
or unreadable key file is a **startup failure**, not a lazy error on the first
request: a PDP that starts without a signing key and fails every decision looks
like a policy problem, not a deployment one.

Reference, not to be copied blind: `~/Development/stratium/go/pkg/security/tokensign`
(270 lines) — it predates this design and takes PEM *contents* rather than a
path, which K1 deliberately changes.

**Tests:** a valid EC key loads and round-trips a sign/verify; a missing file,
an unreadable file, a non-PEM file, and an RSA key where EC is required each
fail at startup naming the problem; a previous key verifies but **cannot sign**
— assert that structurally, not by convention.

**Mutation-test and report survivors:** let the previous key sign; make a
missing key file a lazy error; accept a key of the wrong type.

---

## Task 2 — Issuance

**Files:** `proto/pdp/v1/pdp.proto`, `services/internal/pdpgrpc/`, tests.

`CreateDelegation` returns a token alongside the delegation id — the caller
already has a round trip, and a delegation without a way to use it is not
useful. Add `IssueToken(delegation_id)` for re-issuance when a token expires and
its delegation has not.

**Claims: the minimum that identifies, and nothing more.** The delegation id,
the tenant, an issued-at, an expiry, and a token id. **Do not put the scope in
the token** — not the tier ceiling, not the tool list, not the caps. K3 says a
token is a reference, and scope in a token is scope that can go stale against
the row it names, which is how a revoked delegation keeps working.

**Token lifetime is independent of, and never longer than, the delegation's.**
An expiry beyond the delegation's would be a credential outliving the authority
it names. Clamp it and record that you did.

**Re-issuance re-checks.** `IssueToken` loads the delegation and refuses if it
is expired, revoked, or belongs to another tenant. A re-issuance path that
trusts the id it was handed is a way to resurrect a dead delegation.

**Tests:** a created delegation returns a verifiable token naming it; a token's
expiry never exceeds its delegation's; `IssueToken` on an expired delegation
fails; on a revoked one fails; across tenants is `NotFound` via RLS; and the
token carries no scope fields — assert that explicitly, since it is the property
K3 rests on.

**Mutation-test and report survivors:** put the tier ceiling in the claims; let
a token outlive its delegation; let `IssueToken` skip the delegation load.

---

## Task 3 — Verification, and removing the bare-id path

**Files:** `proto/pdp/v1/pdp.proto`, `services/internal/pdpgrpc/`, tests.

`DecideRequest` carries a token instead of a delegation id. **Remove the
delegation id field.** This is **K4** and it is the point of the phase.

Verify: signature against the current or previous key; not expired; well-formed;
names a delegation that exists in this tenant. Then **load that delegation and
evaluate all three legs as today** — the token has bought authentication, not
authorization.

**Each failure denies with a distinguishable reason.** "Your token expired" and
"your delegation was revoked" send an operator to different places, and the
audit row must tell them apart.

**A token for another tenant's delegation is `NotFound` via RLS**, not a
verification failure — the tenant boundary is RLS's job everywhere else and
this is not an exception.

**Tests:** a valid token decides normally; an expired one denies; one signed by
an unknown key denies; a malformed one denies; one naming a revoked delegation
denies **at the delegation leg**, proving the token did not substitute for it;
one naming another tenant's delegation is `NotFound`; and a request with **no**
token denies rather than falling back to anything.

**Mutation-test and report survivors:** accept an unsigned token; skip the
expiry check; let a valid token bypass the delegation load; restore a bare-id
fallback.

---

## Task 4 — The PEPs carry tokens

**Files:** `services/cmd/stratium-pep/`, both modes, docs, tests.

`session-start` stores the **token** in the session file instead of the
delegation id. `hook` and `mcp` send it. The session file is read fresh on every
call, so a revocation still takes effect on the very next one — preserve that.

**Re-issue on expiry, deny on failure.** A long session outlives a short token.
The PEP may call `IssueToken` when its token has expired, and **must deny if
re-issuance fails** — a PEP that retries forever is an agent hung
indistinguishably from a broken tool call, which is the reasoning C22's timeout
already rests on.

**The session file now holds a credential, not an identifier.** It was already
`0600`; say plainly in `docs/pep.md` that its contents are now bearer authority
and what that means for where it may be written.

**Tests:** `session-start` writes a token; both modes send it; an expired token
triggers exactly one re-issue attempt; a failed re-issue denies; a missing
session file denies; and the file is written `0600`.

---

## Task 5 — Prove it, and re-check what this does not fix

**Files:** the integration suite, and a scratch real-agent run.

**Integration proofs, against a live stack:**

1. End to end with tokens: `session-start` → `hook` → allow, and a denied call
   still denies for the same reason it did before tokens.
2. A token naming a **revoked** delegation is denied at the **delegation leg** —
   K3's property, proving the token is a reference and not a capability.
3. A token signed by a **previous** key still verifies; one signed by an unknown
   key does not.
4. A request with **no** token is denied, with **no** bare-id fallback anywhere.
   This is K4 and it is the proof the phase exists for.
5. Cross-tenant: a token for another tenant's delegation is `NotFound`.

**Then a real-agent run**, same safety constraints as the previous three:
scratch directory only, never a settings file outside it, never install into the
session doing the work, tear everything down and verify no `stratium`
containers remain.

Confirm the agent works unchanged through a token-carrying `hook` and `mcp`, and
report what it does when a token expires mid-session — that is the new failure
mode this phase introduces and nobody has seen it yet.

**Re-check, and expect all three to be unchanged:**

- **C24** still requires the PEP decision cache, which does not exist. Confirm
  its skip reason is still accurate and correct it if not.
- **C25** still requires DPoP, deferred. Same.
- **Phase 7 Finding A** — resource constraints scope to one exact identity,
  never a subdirectory. Unrelated to tokens; confirm unchanged and not masked.
