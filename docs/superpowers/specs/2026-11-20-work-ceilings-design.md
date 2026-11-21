# Ceilings on requested work — design

Status: approved 2026-11-20 · built

Outcome notes: the PAP answers 413 when the request declares a length over
the limit; a body with no declared length is cut off at the limit and the
handler reports it as a bad request (400). The evaluation deadline covers
evaluating the prepared policies, not loading and compiling them. The PAP's
policy test endpoint evaluates a candidate policy too, so it runs under the
same 2s deadline, fixed.

## Intent

Several inputs to the PDP and PAP have no upper bound: how long a delegation
may live, how large a PAP request body may be, how long a policy evaluation
may run, how many calls one connection may have in flight. Each gets a bound,
with a default that an ordinary deployment never notices.

## Goals

- A delegation cannot be created with a lifetime above a configured maximum.
- A TTL of any size cannot overflow the arithmetic that turns it into a time.
- A PAP request body above 1 MiB is refused; a slow or idle PAP connection is
  closed.
- A policy evaluation that runs past a configured time ends and denies.
- One PDP connection cannot hold an unbounded number of calls in flight.

## Non-goals

- Rate limiting, per caller or global.
- Changing what `Decide` audits. A call with a bad token still writes one
  audit row; that was a deliberate choice ("someone tried and failed to
  authenticate" belongs in the trail) and bounding it is rate limiting.
- A PDP message size setting: grpc-go already refuses messages above 4 MiB.

## Anti-goal

A limit that a normal deployment trips over. Every default sits well above
what the quickstart, the tests and the docs use.

## Approaches

1. **Fixed constants.** Smallest change, but a deployment that legitimately
   wants a week-long delegation has to rebuild.
2. **Settings with defaults (chosen)** for the two limits a deployment may
   reasonably need to move (maximum delegation lifetime, policy evaluation
   time); constants for the rest (body size, HTTP timeouts, calls per
   connection).
3. **Everything configurable.** Five more settings nobody will change.

## Design

**Delegation lifetime.** New PDP setting `STRATIUM_MAX_DELEGATION_TTL`
(a duration, default `24h`). `CreateDelegation` refuses a `ttl_seconds`
above it with `InvalidArgument`, naming the maximum. Refusing rather than
shortening silently: the caller asked for something it will not get, and
should hear so. A child is already limited by its parent's expiry.

**Token lifetime.** `IssueToken` already shortens a token to the
delegation's expiry and says so in the response, and the PEP relies on that
by asking for ten years. So it keeps accepting any positive value, and the
requested value is capped at the maximum delegation lifetime before it is
turned into a duration, which removes the overflow.

**Policy evaluation.** New PDP setting `STRATIUM_POLICY_EVAL_TIMEOUT`
(default `2s`). The evaluation of the prepared policy set runs under that
deadline. Rego stops when the deadline passes and its error already becomes
a DENY that names the policy; the other three languages cannot loop.

**PDP connections.** `grpc.MaxConcurrentStreams(256)`.

**PAP.** `decodeJSON` reads through `http.MaxBytesReader` at 1 MiB and
answers 413 above it. The server gains `ReadTimeout` (30s) and `IdleTimeout`
(120s) beside the existing `ReadHeaderTimeout`.

**Docs.** The two settings in the configuration reference; a line in the
user guide where delegations are created.

## Calls made by the author (not decided by the maintainer)

- Defaults: 24h, 2s, 1 MiB, 256, 30s/120s.
- Refuse an over-long delegation rather than shorten it.
- Bad-token audit rows are left alone (see non-goals).
- No `WriteTimeout` on the PAP unless every handler is confirmed short.

## Verification

- Go tests: TTL at the maximum is accepted, one second above is refused; a
  huge `ttl_seconds` to `IssueToken` yields a token ending at the
  delegation's expiry; a Rego policy that loops is denied within the
  deadline; a 2 MiB PAP body gets 413; bad setting values fail startup.
- `make integration`.

## Left to the builder

Identifier names, error wording, where the deadline is applied in the
policy package.
