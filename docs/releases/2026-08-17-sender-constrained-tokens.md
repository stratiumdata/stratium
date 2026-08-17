# Release note — sender-constrained tokens (DPoP)

Delegation tokens can now be **bound to a key the caller holds**, and the two
network enforcement surfaces require it. A stolen token is no longer usable on
its own: the holder must also prove possession of the key it names, per
RFC 9449.

**This release does not upgrade cleanly with existing configuration.** Four
required values have no defaults, and any process missing one refuses to start.
Read "Before you upgrade" first.

---

## Before you upgrade

### 1. Set four configuration values

Each is **required and has no default**. A process missing one exits at startup
naming every missing key at once, so you will not discover them one restart at a
time.

| Variable | Process | Value |
|---|---|---|
| `STRATIUM_DPOP_FRESHNESS_WINDOW` | `stratium-pdp` | Go duration, must be positive. How far a proof's timestamp may be from the PDP's clock in either direction. `30s` is a reasonable start. |
| `STRATIUM_SPENT_PROOF_REAP_INTERVAL` | `stratium-pdp` | Go duration, must be positive. How often spent-proof records are deleted. `5m` is a reasonable start. |
| `STRATIUM_PEP_EXTAUTHZ_ALLOWED_HOSTS` | `stratium-pep extauthz` | Comma-separated list of the public authorities this gateway serves, e.g. `api.example.com,api.eu.example.com`. No empty entries. |
| `STRATIUM_PEP_PROXY_PUBLIC_URI` | `stratium-pep proxy` | Scheme and authority only — `https://proxy.example:9292`. Scheme must be `http` or `https`; no userinfo, no path, no query, no fragment. |

**Choosing the freshness window.** Too short and legitimate calls fail on
ordinary clock drift between an agent and the PDP; too long and a captured proof
stays replayable for longer against the same method and URI. It bounds only the
window, not the number of uses — a proof is single-use regardless.

**Why the two address values exist.** A proof is bound to the URI the *client*
addressed. The surface must establish that value itself rather than trusting
what the caller asserts, or the binding proves nothing about where the request
was aimed. `ALLOWED_HOSTS` is a list because one gateway may legitimately serve
several public names; `PROXY_PUBLIC_URI` is single because a proxy has one
identity.

Note both are the **public** address a client dials and signs — not the listen
address. Behind a load balancer these differ, and the listen address is usually
`:9292`-shaped with no hostname at all.

### 2. Run migration `000018`

Adds `spent_proofs`, which records each proof as it is used so a replay
collides at the database. `stratium_app` receives `INSERT`, `SELECT`, and
`DELETE` on that table and nothing more.

### 3. Re-issue tokens for `proxy` and `extauthz` callers

**Every caller of those two surfaces must present a bound token.** An unbound
token is refused there after this release, whatever the policy would have said.

To mint one, pass the caller's **public** JWK to `IssueToken`; the token comes
back carrying a `cnf.jkt` claim. The caller then sends a DPoP proof on each
request — in the `DPoP` header for `extauthz`, in `dpop` metadata for `proxy`.

`hook` and `mcp` callers need no change. See "What is unaffected".

---

## Breaking changes

**Unbound tokens are refused on `proxy` and `extauthz`.** This is the point of
the release. Plan the re-issue in step 3 before upgrading those surfaces.

**A proof is single-use.** Replaying one is denied, distinctly from a policy
denial. A client that caches and resends a proof will break.

**A proof is bound to the method and URI it was made for.** Presenting it for a
different method or a different address is denied, even with a valid token.

**`proxy` no longer holds a call open across a human approval.** An escalating
call now returns a denial carrying the approval id, and the caller retries with
a **fresh** proof once approved. This is not a preference: a proof is single-use
and short-lived, a human approval is neither, and the proxy cannot mint a
replacement because the client holds the key. `extauthz` already behaved this
way. Callers that relied on the call blocking must handle the denial-and-retry
shape instead.

**An escalating call from an unbound token is refused immediately** rather than
waiting, since its outcome would be refused anyway.

---

## What is unaffected

**`hook` and `mcp` are unchanged.** They keep working with ordinary bearer
tokens, and binding is not required there — on those surfaces the caller
already holds the session file containing a real token, so a key adds nothing.
No configuration change, no re-issue.

**Existing bearer tokens remain valid** everywhere except the two network
surfaces.

**No policy, delegation, agent, or approval semantics changed.** A bound token
is still an authenticated *reference*: the PDP loads the delegation and
evaluates all three legs exactly as before. Proof verification is a fourth
condition, never a bypass.

---

## Verifying the upgrade

A correctly configured deployment shows all of:

- every process starts (a missing value is loud, not silent)
- a bound token with a valid proof reaches the upstream through both surfaces
- the same token with **no** proof is denied
- an **unbound** token is denied on both surfaces
- resending an identical proof is denied for replay, not for policy
- `hook` and `mcp` still work with your existing unbound tokens

If a process refuses to start, the error names every missing or malformed key
together. If calls are denied after upgrading, check the denial reason before
the policy: "not bound to a key", "proof already spent", and an `htu` mismatch
are all distinct messages and each points somewhere different.

---

## Known limitations

**A proof binds the request line, not the body.** On `proxy` this is the gRPC
method; on `extauthz`, the method and URI. Message contents are not covered.

**A stream is authorized once, at open.** One decision, one proof, for the
stream's whole life. Per-message binding is not available without target
schemas.

**An escalation that is refused still leaves a pending approval.** The PDP
creates the row before either surface can see whether the token was bound, so
approving it achieves nothing — nothing will retry against it. This was equally
true of the previous blocking behaviour when an escalation timed out. If you see
an orphaned approval queue, this is why.

**The audit chain is not encrypted**, so crypto-shredding is unavailable. That
subsystem is not built.

**`mcp` is proven at unit level and against the decision path, not against a
live stack.** No live harness exists for it and none existed before this
release; it was not modified.
