# Phase 6 — The MCP enforcement surface

Implements spec §3.2 **A2**/**A6** for the `mcp` mode, on the trust model
§4.1.1 **A10** permits. Four tasks.

**Why this surface, and why now.** A2 requires four enforcement surfaces; only
`hook` exists. A10 splits the remaining three: `mcp` is locally invoked and can
read a delegation reference out-of-band exactly as `hook` does, while `proxy`
and `extauthz` are network intermediaries whose caller identity must be
sender-constrained — so those two are blocked on token issuance and this one is
not.

**The second implementation is the point.** `stratium-pep` has had exactly one
mode since Phase 3a. Everything shared — `awaitApproval`, `pollApproval`,
`loadSessionFile`, `normalize`, the config loader — has only ever served
`hook`, so none of it has been tested as an abstraction. Phase 4 learned this
the hard way about `policytest.EngineContract`, which turned out to describe
Cedar rather than constrain engines, and only a second implementation revealed
it. Expect the same here: **if a shared helper needs reshaping to serve `mcp`,
that is a finding about the seam, not a failure of this phase.** Report it.

## What the mode is

`stratium-pep mcp` is an **MCP proxy over stdio**: the agent's harness launches
it in place of a real MCP server, and it launches the upstream server it wraps.
Requests flow agent → PEP → upstream; responses flow back. It authorizes each
`tools/call` against the PDP before forwarding.

Stdio, not HTTP, because that is how a harness launches a local MCP server and
it is what makes A10's trust model hold: the process is started by the harness
alongside the agent, so the session file it reads is not something the agent
supplied.

## Global constraints

- Go 1.25, module path `stratium`, module root `services/`.
- **The PEP classifies nothing and decides nothing.** It forwards `tool`, a
  `verb` derived from the tool name only, `raw_input`, and a best-effort
  `normalized_input`; the PDP derives the tier. Any local tier logic,
  allowlist, or "obviously safe" shortcut is spec defect **D1**, the hole that
  made every enforcement path in the predecessor bypassable.
- **Fail closed, always.** PDP unreachable, missing or malformed session file,
  a delegation that no longer exists, a malformed MCP frame, an ambiguous
  response — every one denies. A PEP that fails open is worse than no PEP,
  because it looks like enforcement.
- **`ESCALATE` blocks** (spec §4.6, `mcp` is a blocking surface). Reuse
  `awaitApproval` from `cmd/stratium-pep/escalation.go`; do not write a second
  poll loop. A timeout denies.
- **Never log `raw_input`, tool arguments, the session file's contents, or an
  approval id.** They reach the PDP because server-side derivation requires it
  and land in the audit chain as a digest; a second, unprotected copy on a
  developer's disk is strictly worse than none.
- Strict root `.golangci.yml`. Clean before each commit, from `services/`:
  `go build ./...`, `go vet ./...`, `go vet -tags integration ./...`,
  `go test -race ./...`, `golangci-lint run ./...`. Plus `make conformance` and
  `make integration` from the repo root.
- Conventional commits, no attribution trailers — check each message; an
  earlier phase had to rewrite six commits for this.
- Scratch work goes in the session scratchpad, never the repository.

---

## Task 1 — The stdio proxy skeleton

**Files:** `services/cmd/stratium-pep/mcp.go` and tests.

Wire `mcp` as a mode alongside `hook` and `session-start`. It reads JSON-RPC
frames from stdin, writes to stdout, and relays to and from a child process it
launches — the upstream MCP server, named by configuration.

**Relay faithfully and enforce narrowly.** Every method except `tools/call`
passes through untouched, including notifications, `initialize`, and anything
the PEP does not recognise. A proxy that drops a method it has never heard of
breaks the server it wraps for no security benefit; a proxy that *interprets*
methods it was not asked to police has started making decisions.

**Two properties that are easy to get wrong and must be tested:**

- **JSON-RPC ids must round-trip exactly.** An id may be a string, a number, or
  null; re-encoding a number as a string, or renumbering, breaks correlation
  silently and the failure looks like the upstream server misbehaving.
- **Concurrency.** MCP allows multiple in-flight requests, and an authorization
  call takes milliseconds. Do not serialize the whole stream behind one pending
  decision unless you can show that is required — and if you do serialize, say
  so and justify it, because it is a throughput property somebody will later
  change without knowing why it was chosen.

**Fail closed on transport faults**: a malformed frame, a child that exits, a
closed pipe. Each denies or terminates cleanly; none silently forwards.

**Tests:** a `tools/list` round-trips unchanged; an unknown method round-trips
unchanged; ids of each JSON type round-trip exactly; a malformed frame does not
reach the upstream; the child exiting is handled without hanging.

---

## Task 2 — Authorize `tools/call`

**Files:** `services/cmd/stratium-pep/mcp.go`, and tests.

Intercept `tools/call`: build a `DecideRequest` from the tool name and its
arguments, call the PDP, and forward on ALLOW or return an MCP error on DENY.

**Reuse, do not reimplement:** `loadSessionFile` for the delegation reference
(read fresh per call, so a revocation takes effect on the very next tool call —
that is why the hook re-reads rather than caching), `normalize` for the
best-effort extraction, and `awaitApproval` for `ESCALATE`.

**Do not send `declared_tier`.** The field exists for clients that have one,
and sending a guess only creates an opportunity to be wrong; the PDP re-derives
regardless. Assert its absence in a test, as the hook's tests do.

**The denial must be a well-formed MCP error the agent can act on** — a JSON-RPC
error with the PDP's reason, not a transport failure and not a fabricated
"success" carrying an error string. An agent that cannot tell "you may not do
this" from "the server broke" will retry the wrong thing.

**`tools/list` is deliberately NOT filtered.** Enforcement happens at call time.
Filtering the advertised list would mean the PEP deciding locally which tools
are permitted — D1 — or issuing one `Decide` per tool per listing, which is
worse. Record the decision and its reasoning in the package doc, because the
UX argument for filtering is obvious and someone will raise it.

**Tests:** an allowed call forwards and its response returns; a denied call
never reaches the upstream and yields a JSON-RPC error carrying the PDP's
reason; an escalated call blocks and then forwards on approval; an escalation
timeout denies; the request carries `raw_input` and no `declared_tier`; a
missing session file denies; an unreachable PDP denies.

**Mutation-test and report survivors:** forward on DENY; send a `declared_tier`;
cache the session file across calls; treat an escalation timeout as allow.

---

## Task 3 — Configuration, and the shared-seam report

**Files:** `services/cmd/stratium-pep/config.go`, docs, and tests.

Configuration for the mode: the upstream server command and its arguments, plus
the PDP address, agent id, subject, session file, connect timeout, and the
escalation poll interval and timeout the hook already requires. **Required
values have no defaults**, the same rule every other component follows.

**Then answer the question this phase exists to ask, in your report:** did the
shared helpers — `awaitApproval`, `pollApproval`, `loadSessionFile`,
`normalize`, the config loader — serve a second mode without modification? For
each one you had to change, say what and why. That is a finding about the seam,
and it is the same question Phase 4 asked of `policytest.EngineContract`, where
the answer turned out to be that it described one implementation rather than
constraining any.

**Install docs** covering how a harness launches the proxy in place of the
upstream server, the environment it needs, and a plain statement that every
tool call is denied until a session is started and a policy permits it.

---

## Task 4 — Against a real agent

This is the task the phase exists for, and it is the same shape as Phase 3a
Task 4, which found defects no mocked test could.

In a scratch directory outside the repository: bring up the stack, seed a
tenant, agent, policy, and delegation, configure a real MCP server behind the
proxy, and run a real agent session that makes tool calls — some the policy
permits, at least one it does not, and at least one that escalates.

**Do not install the proxy into the session running this work.** Fail-closed
plus any PDP problem would wedge it.

**Report:** what the agent tried, what was allowed, denied, and escalated, what
the agent did when denied, the audit rows produced, and the reason strings a
real user would see. If the reason strings are unhelpful, that is a finding
worth more than a passing test — Phase 3b exists because Phase 3a's real-agent
run reported one.

**If a real MCP-capable agent is unavailable, say so plainly** rather than
simulating one, and fall back to driving the proxy with recorded JSON-RPC
frames — labelling the result a contract test, not a real-agent test. The
distinction matters: one proves the proxy works, the other proves it works with
the thing it was built for.

Then clean up the scratch directory, containers, and volumes.
