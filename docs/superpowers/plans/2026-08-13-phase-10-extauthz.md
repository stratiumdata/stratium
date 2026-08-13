# Phase 10 — The Envoy ext-authz enforcement surface

Implements spec §3.2 **A2**/**A6** for the `extauthz` mode and §3.4 **E5**.
Unblocks conformance property **C23**. Four tasks.

**Why this surface now.** Three of the four surfaces A2 requires now ship
(`hook`, `mcp`, and — after Phase 9 — both on tokens). `extauthz` was blocked on
sender-constrained identity per **A10**, and Phase 9 removed that block. It is
also the **first surface where a token genuinely arrives from the party being
policed**, which makes it the real test of everything Phase 9 built: until now
the token has only ever travelled from a session file the agent never wrote.

**Dead code waiting for it.** `pdpgrpc.DegradeEscalateToDeny` was written in
Phase 5 Task 5 for a non-blocking surface that did not exist and has been used
by nothing since. This phase either makes it live or proves it was the wrong
shape — both are useful answers.

## The mechanics this plan fixes

**M1 — the tool identity is the request path.** Envoy passes `:method` and
`:path`; for gRPC over Envoy the path is `/package.Service/Method`. That is the
natural analogue of a tool name, and it is **catalogable**: a tenant adds a row
for `/inventory.Inventory/DeleteItem` at `DESTRUCTIVE` exactly as it adds one
for `write_file`. Phase 8's per-tenant catalog is what makes this surface
workable at all.

**M2 — the token arrives in `authorization: Bearer`.** Standard, and Envoy
forwards it without special configuration. No token is a denial; there is no
alternative credential and no fallback (spec **K4**).

**M3 — `raw_input` is the request metadata as JSON, with the credential
stripped.** Method, path, and selected headers, serialized. This is structural
serialization, not classification — the same category as the hook forwarding
`tool_input`.

**The `authorization` header must never reach `raw_input`.** `raw_input` is
hashed into the audit chain and reaches the PDP's classifier; a bearer token
sitting in an audit record is live authority written into a log that is designed
to be kept and read. Strip it, and any other credential-bearing header, before
serializing. **Test that it is absent, structurally.**

**M4 — escalate degrades to deny plus a pending record (E5).** Envoy's
ext_authz timeouts are measured in milliseconds and cannot wait for a human. The
denial must carry enough for an operator to find the pending approval, so a
retry after approval succeeds.

## Global constraints

- Go 1.25, module path `stratium`, module root `services/`.
- **The PEP classifies nothing, decides nothing, and extracts nothing.** It
  serializes the request and forwards a token. Any local allowlist, path
  pattern-matching for sensitivity, or "health checks are fine" shortcut is
  spec defect **D1**.
- **Fail closed, always.** No token, an invalid token, an unreachable PDP, a
  malformed `CheckRequest`, an ambiguous response — every one denies. On this
  surface a fail-open is an open proxy.
- **A token is an authenticated reference, never a capability** (**K3**). The
  PDP loads the delegation and evaluates all three legs; nothing here changes
  that.
- **Never log a token, key material, request bodies, or headers.** Envoy passes
  entire request metadata; this surface has more to leak than any before it.
- `internal/authz` stays pure and is not touched by this phase.
- Strict root `.golangci.yml`. Clean before each commit, from `services/`:
  `go build ./...`, `go vet ./...`, `go vet -tags integration ./...`,
  `go test -race ./...`, `golangci-lint run ./...`. Plus `make conformance` and
  `make integration` from the repo root.
- Conventional commits, no attribution trailers — check each message.
- Scratch work goes in the session scratchpad, never the repository.

---

## Task 1 — The ext_authz server

**Files:** `services/cmd/stratium-pep/extauthz.go`, config, and tests.

Add `extauthz` as a mode alongside `hook`, `mcp`, and `session-start`. It serves
`envoy.service.auth.v3.Authorization/Check` over gRPC.

Add `github.com/envoyproxy/go-control-plane` and record the version. It is the
canonical, versioned source of the ext_authz contract, maintained alongside
Envoy itself — which is why it is worth the dependency tree on a project that
has otherwise been sparing. Note in the package doc that a hand-rolled copy was
rejected because Envoy owns this contract and we only answer it; unlike the MCP
proxy, there is no id-fidelity argument for owning the framing.

**Configuration:** a listen address, plus the PDP address, agent id, subject,
and connect timeout the other modes already require. **Required values have no
defaults.** There is **no session file** — the token arrives per request, which
is the whole difference between this surface and the local ones. Say so in the
config's doc comment, because a reader who knows `hook` will look for one.

**Fail closed at startup**: a missing config value stops the process, naming
every missing key at once, as every other component does.

**Tests:** the server starts and answers `Check`; a missing required value fails
startup naming all of them; and the mode is reachable from the binary's
dispatch.

---

## Task 2 — Map a `CheckRequest` to a `DecideRequest`

**Files:** `services/cmd/stratium-pep/extauthz.go` and tests.

Extract, per **M1**–**M3**: the tool identity from the request path; the token
from `authorization: Bearer`; and `raw_input` as the request metadata
serialized to JSON.

**The credential-stripping rule is the load-bearing one.** `authorization` — and
any other credential-bearing header — must not appear in `raw_input`.
`raw_input` is hashed into the append-only audit chain, so a token that leaks
there is bearer authority written permanently into a record designed to be
retained and read. **Assert its absence structurally, not by inspection**, and
test that a header whose name differs only in case is stripped too — HTTP
headers are case-insensitive and a case-sensitive strip is a strip that fails.

**Do not send `declared_tier`** — the field exists for clients that have one,
and a guess only creates an opportunity to be wrong. Assert its absence.

**A request with no `authorization` header denies** without contacting the PDP.
There is no fallback credential (**K4**).

**Tests:** the path becomes the tool; a `Bearer` token is extracted; a missing
or malformed `authorization` denies; `raw_input` carries method and path;
`raw_input` **never** carries `authorization` in any casing; no `declared_tier`
is sent.

**Mutation-test and report survivors:** leave `authorization` in `raw_input`;
strip case-sensitively; send `declared_tier`; treat a missing token as an empty
one and call the PDP anyway.

---

## Task 3 — Map the decision to a `CheckResponse`, and degrade escalation

**Files:** `services/cmd/stratium-pep/extauthz.go`,
`services/internal/pdpgrpc/nonblocking.go`, and tests.

ALLOW returns an OK `CheckResponse`. DENY returns `PERMISSION_DENIED` with a
denied-response carrying the PDP's reason.

**ESCALATE degrades to deny plus a pending approval record (E5).** Use
`pdpgrpc.DegradeEscalateToDeny`, which Phase 5 wrote for exactly this and which
nothing has used since. **If it turns out to be the wrong shape, say so and fix
it** — a helper written speculatively for an absent caller is exactly the kind
of thing that is wrong in a way only its first real caller discovers.

**The denial must let an operator find the pending approval.** A retry after
approval has to succeed, so the approval id must reach the caller — in a
response header, in the body, or both. Decide which and justify it; a pending
record nobody can locate is a record that helps nobody.

**Distinguishable reasons.** "Your token expired", "your delegation was
revoked", and "this needs approval, which is pending" send an operator to three
different places. A single generic denial would make this surface worse than the
`hook`, which already distinguishes them.

**Tests:** allow returns OK; deny returns `PERMISSION_DENIED` with the reason;
escalate returns a denial **and** the approval id; an unreachable PDP denies; a
PDP error denies; an unset effect denies (the proto's `Effect` zero value is
`EFFECT_DENY` deliberately — assert it rather than assuming the wire holds the
invariant).

**Mutation-test and report survivors:** return OK on ESCALATE; drop the approval
id; make an unreachable PDP allow; collapse all reasons into one string.

---

## Task 4 — Behind a real Envoy, and C23

**Files:** `deploy/docker/`, the integration suite, and a scratch run.

**Put a real Envoy in front of it.** Add an Envoy service to compose, configured
with the ext_authz filter pointing at `stratium-pep extauthz`, in front of a
trivial upstream. Every previous surface was proven against the real thing it
was built for — `hook` and `mcp` against a real `claude` session — and this one
is no different: a hand-driven `Check` call proves the mapping, not the
integration.

**Prove, against that stack:**

1. A request with a valid token for a permitted action **reaches the upstream**.
2. A request with a valid token for a denied action **does not**, and Envoy
   returns the PDP's reason.
3. A request with **no** token is denied — no fallback anywhere (**K4**).
4. A request whose token names a **revoked** delegation is denied at the
   **delegation leg** (**K3**).
5. An escalating request is denied **and** a pending approval row exists,
   findable from the response; approving it out of band (as the control plane,
   since the PDP has no `UPDATE` grant) makes a retry succeed. That is **E5**
   end to end.
6. The `authorization` header does **not** appear in the audit row's input
   digest source — the credential-stripping rule, proven against a real request
   rather than a constructed one.

**Then assess C23** — "on a non-blocking surface, escalate returns deny plus a
pending record." Read what it actually asserts before converting it. If proof 5
establishes it, unskip it and report the new tally. If it asserts something
still missing, leave it skipped with a **corrected reason**, exactly as C19,
C21, C22, and C24 were handled. **Do not force a pass.**

**Also re-check, expecting no change:** C19 still requires all four surfaces
*and* the decision cache — after this phase three of four exist, so its reason
may need correcting even though it stays skipped. C25 still requires DPoP.

Tear everything down; verify no stray containers.
