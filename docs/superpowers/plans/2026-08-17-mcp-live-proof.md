# The `mcp` surface, proven live

Closes the last enforcement surface that has never been run against a real PDP.
Two tasks.

**The gap, stated precisely.** §3.2 **A2** claims four enforcement surfaces
ship, and three have been proven against the real thing they were built for:
`hook` through the cache end-to-end suite, `extauthz` behind a real Envoy,
`proxy` in front of a real gRPC service. **No integration test has ever invoked
the `mcp` subcommand.** It is proven at unit level and at `Decide`, against a
fake PDP client, and nowhere else.

**Why that matters here specifically.** Every live proof in this project has
found something no constructed test had: real Envoy passes `:method` and
`:path` as literal header entries and injects `x-forwarded-proto`; `GetPath()`
carries the query inline while `GetQuery()` is empty; a real IdP's token
endpoint sits on a different origin than its issuer, which broke a CSP. Three
surfaces, three assumptions the fixtures had encoded backwards.

**What is *not* the gap, so this task does not chase it.** `mcp` is a stdio
proxy: the harness writes JSON-RPC frames to its stdin, and that **is** the
interface. There is no negotiation a "real" client would perform differently —
the proxy does not participate in `initialize`, it relays it. Hand-written
frames on stdin are therefore not a fixture standing in for reality, unlike a
hand-built `CheckRequest` for Envoy. **The client side is already real.** What
is not real today is the PDP, and the upstream the proxy launches as a child
whose lifecycle it must manage.

**No spec amendment.** These are test-strategy decisions, not design rulings —
the same call Phase 15 Task 7's decisions took. The surface's behaviour is
unchanged by this work; only what is proven about it changes.

## Global constraints

- Go 1.25, module path `stratium`, module root `services/`.
- **The behaviour of `cmd/stratium-pep/mcp.go` and `mcp_authorize.go` does not
  change.** If a proof fails, that is a finding to report, not a licence to
  adjust the surface until it passes. Phase 15 modified zero lines of
  `mcp_authorize.go`; this plan should too, unless a proof surfaces a real
  defect — in which case stop and say so.
- **The PEP classifies nothing and decides nothing.** `mcp` gates `tools/call`
  and relays everything else, including `tools/list`, unfiltered. That
  non-filtering is a considered ruling (`mcp.go`'s own package doc: filtering
  would be **D1** in a UX coat of paint, or one `Decide` per listed tool). Pin
  it; do not improve it.
- **Assert on the upstream's own record, never on what the caller observed.**
  A denied call must be shown not to have *arrived*, which the caller's error
  cannot establish. This is the discipline `grpc-target`'s call counter set for
  `proxy` and `echo-upstream`'s for Envoy.
- **The trust model is that the harness starts the proxy, not the agent** —
  which is why the session file `mcp_authorize.go` reads is not something the
  agent supplied. Any proof that writes a session file must respect that
  asymmetry rather than routing a token through the frames.
- Never log a token, a session file's contents, or frame payloads.
- **`internal/authz` is not touched**, except for `conformance_test.go`'s own
  pointer bookkeeping in Task 2 if a pointer genuinely changes. No production
  file in that package changes. (Phase 15's plan needed the identical carve-out
  and omitted it; the pre-flight scan caught it there too.)
- Strict root `.golangci.yml`. Clean before each commit, from the repo root:
  `make build`, `make vet`, `make test`, `make lint`, `make conformance`,
  `make integration`.
- **Commit before running any mutation.** Before believing any mutant's result,
  confirm `git diff --numstat` is non-empty for the patched file **and**
  `go vet ./...` is clean — a no-op patch and a survivor are indistinguishable,
  and so are a non-compiling mutant and a survivor.
- Conventional commits, no attribution trailers.
- Scratch work goes in the session scratchpad, never the repository.

---

## Task 1 — A purpose-built MCP upstream

**Files:** a new upstream server and its tests. **Where it lives is yours to
decide** — see below; do not treat this line as having answered it.

A minimal MCP server over stdio, in the same spirit as `deploy/docker/echo-upstream`
for Envoy and `services/cmd/grpc-target` for the proxy: it exists to be relayed
to, and to report what reached it.

**It must speak enough MCP to be relayed to honestly** — `initialize`,
`tools/list` advertising at least two tools, and `tools/call` returning a
result. Enough that the proxy's relay is exercised against something that
answers like a server, not a script that echoes bytes.

**It records every call it receives to a file, out of band.** The test reads
that file directly. **Do not expose the record through a tool call**: that would
be a `tools/call`, which the proxy gates, so the observation would depend on the
thing being observed — the defect class this project has found nine times.

**Decide where it lives and justify it.** `grpc-target` sits inside the module
because it imports generated types the test also imports; `echo-upstream` sits
outside deliberately because it shares nothing. Work out which this is. If the
test needs to agree with it on a frame shape, that is an argument for inside.

**It is built by the test, not by compose.** `mcp` is stdio and is spawned by
the test process, so the upstream binary must exist on the test host — build it
into a temp directory in `TestMain` rather than requiring a manual step.

**Tests:** it answers `initialize`; it lists its tools; a `tools/call` returns a
result and appends exactly one record; a malformed frame does not crash it; the
record file is readable while it runs.

**Mutation-test and report survivors:** make it record calls it did not receive;
make it record nothing; have it answer `tools/call` without recording.

---

## Task 2 — The live proofs

**Files:** `deploy/docker/docker-compose.yml`, the integration suite.

**A dedicated PDP service and its own `STRATIUM_TENANT_ID`**, as `pdp-epoch` and
`pdp-cache` already have. These proofs seed delegations and policies, and a
shared tenant risks exactly the interference those services exist to prevent.

**This makes it the eighth dedicated PDP service, and that is accumulating
debt** — the integration suite now carries one per phase that touches
control-plane state. Record it; do not solve it here. A plan that economises by
sharing a tenant would be trading a known cost for an intermittent one.

**Drive the real binary through the existing harness.** `runPEPSubcommand`
(`internal/store/cache_e2e_integration_test.go`) already takes an arbitrary
subcommand and feeds it stdin against the compose stack — it serves `hook` and
`session-start` today. `mcp` is a third caller, not a new mechanism. If it needs
reshaping for a long-lived process rather than a one-shot, say what and why;
that is a finding about the seam.

**Prove, against a live stack:**

1. A permitted `tools/call` reaches the upstream and its result returns to the
   caller — the full loop through a real PDP for the first time.
2. A denied `tools/call` **does not reach the upstream**, asserted against the
   upstream's own record. Not the caller's error.
3. `tools/list` relays **unfiltered**, including a tool that would be denied if
   called. Prove the listing is unchanged, then prove calling that same tool is
   denied — one proof, two frames, so the ruling is pinned at both ends.
4. The request `id` survives the relay unchanged in both directions, for a
   denial as well as an allow — a denial is synthesized by the proxy rather than
   relayed, so it is the case where correlation is easiest to lose.
5. The proxy **launches and reaps its child**: the upstream process exists while
   the session runs and is gone afterwards.
6. An upstream that dies mid-session **fails closed** — no frame is invented, no
   call is allowed through, and the proxy exits rather than hanging.
7. The token comes from the **session file**, not from the frames: a session
   file naming a revoked delegation denies, proving the credential path is the
   one the trust model claims.

**Then re-check the conformance suite.** Nothing here is expected to convert —
this proves an existing surface rather than building a property. **Read the
pointers that name `cmd/stratium-pep` tests before assuming that**: if any
property's proven-elsewhere pointer becomes stronger or weaker for having a live
`mcp` proof, say so. Do not force a conversion; C17 remains the only `notBuilt`
and this plan does not touch it.

**Known flaky, and not this plan's:** `TestIntegration_Cache_E2E_NoEntry_PDPStopped_Denies`
races Docker's socket teardown. Re-run once and note it rather than chasing it.

Tear the stack down; verify no stray containers. **A supabase stack for an
unrelated project runs on this host — do not stop, remove, or prune it. If
Docker fills, `docker builder prune -af` only.**
