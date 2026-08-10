# Phase 3b — Normalized tool input

Fixes the defect the first real-agent run found. Two tasks.

**The defect, measured.** Claude Code sends `tool_input` as JSON. The
classifier's read-only pattern is anchored — `^\s*(cat|ls|pwd|…)` — so it never
matches, and every read-only operation falls through to the `INTERNAL_MODIFY`
default:

```
{"command":"ls -la"}          -> INTERNAL_MODIFY     (should be READ_ONLY)
{"command":"cat /etc/hosts"}  -> INTERNAL_MODIFY     (should be READ_ONLY)
{"file_path":"/tmp/x.txt"}    -> INTERNAL_MODIFY     (should be READ_ONLY)
{"command":"rm -rf /"}        -> DESTRUCTIVE         (correct)
ls -la                        -> READ_ONLY           (what the tests assumed)
```

**It fails safe, and the failure is narrower than it looks.** `reDestructive`
and `reExternal` are unanchored substring matches, so they still fire on raw
JSON. What is broken is the *distinction* between reading and writing, not the
detection of danger. Practically: a delegation capped at `READ_ONLY` denies
everything including reads, and nearly all traffic lands at tier 2 regardless
of what it does.

Every integration test fed **bare command strings**, because that is the shape
the plan author imagined. The real agent sends JSON. Eleven packages of passing
tests did not see it.

## The decision (spec-level, record it)

**The PEP sends both the raw `tool_input` and a normalized extraction; the PDP
classifies each and takes the more severe result.**

The PEP knows its agent framework's schema and the PDP deliberately does not,
so extraction belongs at the edge. But extraction is interpretation, and D1
exists to keep interpretation out of the component being policed — so the raw
input travels too. A PEP that extracts wrongly, or lies, can only ever
under-report the *extracted* field; the raw JSON is still scanned by the
unanchored destructive patterns, so `rm -rf /` cannot be hidden by a bad
extraction.

This is the same raw-or-normalized pattern `matches()` already applies to
`normalizeCommand`, one layer further out.

## Global constraints

- Go 1.25, module path `stratium`, module root `services/`.
- **The PEP still classifies nothing.** Extracting a named field from a JSON
  object is a structural lookup, not a judgement about sensitivity — the same
  category as deriving `verb` from the tool name. No tier logic, no allowlist,
  no severity reasoning may enter the PEP.
- **Take the more severe.** Never the extracted value alone, never the first
  match. If raw and normalized disagree, the worse one wins.
- Strict root `.golangci.yml`. `go test -race ./...`, `golangci-lint run ./...`,
  `go vet -tags integration ./...` clean before each commit.

---

## Task 1 — Carry normalized input on the wire and classify both

**Files:** `proto/pdp/v1/pdp.proto`, `services/internal/authz/tier.go`,
`services/internal/pdpgrpc/server.go`, and their tests.

Add `normalized_input` to `DecideRequest`, documented as a best-effort
extraction that never replaces `raw_input` and never lowers a tier.

`Action` gains a `NormalizedInput` field. `BuiltinTier` classifies **both**
`RawInput` and `NormalizedInput` and returns the more severe result. Do not
restructure the existing raw/normalized `matches()` logic — this is a second
axis over the same idea, and both must compose.

**Tests.** For each of the measured cases above: the JSON form alone still
classifies as it does today; the JSON form plus a correct extraction classifies
correctly; **an extraction that under-reports does not lower the tier** —
`raw = {"command":"rm -rf /"}` with `normalized = "ls"` must still be
`DESTRUCTIVE`, which is the property that makes the design safe against a bad
PEP; and an empty normalized input changes nothing.

**Mutation-test and report survivors:** take the normalized result instead of
the more severe; take the raw result only; make an empty normalized input
suppress raw classification.

---

## Task 2 — Extract in the PEP, and re-run the real agent

**Files:** `services/cmd/stratium-pep/`, the integration suite, and tests.

The hook extracts a normalized string from `tool_input` by **field name only**:
`.command` for shell tools, `.file_path` or `.path` for file tools, `.pattern`
for search tools. A tool it does not recognise sends an empty normalized input
and relies on raw classification — which is the current behaviour and remains
correct, just coarse.

**Keep the extraction table small and dumb.** It is a schema map, not a
policy. If it starts growing conditionals about what a tool *means*, that is
classification and it belongs in the PDP.

**Then re-run the real-agent test from Phase 3a Task 4**, with the same safety
constraints: scratch directory only, never touch a settings file outside it,
never install the hook into the running session.

Report the derived tier for every tool call this time, and confirm that a
delegation capped at `READ_ONLY` now permits reads and denies writes — the case
that is broken today. That is the proof this phase exists for; a passing unit
test is not.

Also report whether the reason strings improved, and whether the agent behaves
differently when the tier is correct.
