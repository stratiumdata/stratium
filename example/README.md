# example

Three runnable programs, one shared agent, each demonstrating a different
Stratium enforcement surface (hook, mcp, extauthz/proxy) end to end against a
small local model. `stratium/example` is its own Go module (see `go.work`)
so it can stay dependency-light and never bleeds into `services`' build.

`agent/` holds the parts every surface shares:

- `transport.go` — `Transport`, the interface each surface implements to
  advertise tools and place calls, decoupled from how the call actually
  travels.
- `report.go` — `Report`, which turns a list of expected ALLOW/DENY outcomes
  and the calls actually observed into a pass/fail verdict. A model turn
  that calls no tool is recorded separately as inconclusive: that is a small
  model's limitation, not evidence the enforcement is broken, and must never
  fail the run.
- `precheck.go` — `Precheck`, which fails fast with the exact fix (not a
  Stratium-shaped denial) when a prerequisite like Ollama or LiteLLM isn't
  reachable yet.

The model loop and the three surfaces themselves are later work; this module
currently only holds their shared foundation.
