# Quickstart — `deploy/stratium`

How to get from a fresh clone to a coding agent whose tool calls are actually
being authorized, and back out again.

**Every command below was run against a live stack while writing this. The
output under each step is what was observed, not what the code suggests should
happen.** Ids, ports and timings will differ on your run; everything else should
match.

`deploy/stratium` is a single Python 3 file with no third-party dependencies. It
drives the product but is not part of it — you can delete it and the system still
works, you just have to do all of this by hand.

---

## 0. Before you start

You need Docker (with `docker compose`, v2 — not the old `docker-compose`), a Go
toolchain, and Python 3. The script checks all three before doing anything else
and names what is missing. On a fresh clone it also builds the admin UI, which
the stack's images embed, and that needs Node.js (`npm`).

```bash
git clone https://github.com/stratiumdata/stratium.git && cd stratium
```

Everything below runs from the repository root.

---

## 1. Bring it up

```bash
deploy/stratium up --harness claude
```

**The harness flag is required and has no default.** The two harnesses write
different files, and a hook installed on the one you are *not* running is
silently no enforcement at all — so the script makes you say which. Use
`--harness codex`, or `--harness both`.

**Observed** (about 80 seconds warm; the first run is longer because it builds
images):

```
[1] Preflight
    ok   docker, docker compose and go are present

[2] Stack up (this is the slow one -- it builds images)
    ok   compose project: docker
    ok   pap=localhost:51465  pdp=localhost:51458  kc=localhost:64634
         resolved now, never stored -- they change on every compose up

[3] Build the PEP
    ok   /Users/you/stratium/bin/stratium-pep

[4] Policy so the principal may delegate
    ok   already present (subject agent-tester@example.com)

[5] Seed the tool catalog
    ok   tool_catalog rows: 26 -> 26

[6] Agent row
    ok   reused: quickstart-46384b (0f8f833a-ef4c-4e7e-bbb5-00d259cf5c19)

[7] Classification caps
    ok   already present (catch-all, so every other probe stays UNCLASSIFIED)
    ok   already present ("/secret-*" -> SECRET)
    ok   created ("/tmp/secret-*" -> SECRET)
    ok   created ("/private/tmp/secret-*" -> SECRET)
    ok   quickstart-46384b capped at {'nato': 'CONFIDENTIAL'}
         verify's classification case needs this; state['caps'] is how it knows

[8] Delegation
    ok   1f9a667e-1e50-426d-a2c9-f9e9b0321cdb  grants Read,Grep,Glob  tier 3

[9] Wire the hooks
    ...

[10] Verify -- onboarding is not done until a denial is observed
```

**PASS if** step 10 ends with four `PASS` lines and `Enforcement proven`. See §3.

> The run above is a **warm** one — `already present`, `reused`, `26 -> 26`. On a
> genuinely first run those read `created`, `created`, and `0 -> 26`, and the
> whole thing takes minutes rather than 80 seconds because it builds the images.
> Every step is idempotent, so re-running `up` is safe and is the fastest way to
> repair a half-configured stack.

### What those ten steps actually did

Steps 4 and 5 are the two that look like boilerplate and are not. Without the
policy in step 4, `session-start` fails with *"none of the requested tools are
held by this principal"* — the delegation cannot be issued at all. Without the
catalog in step 5 the PDP has no way to know which argument of a tool call names
the resource, so nothing can be classified.

> The local stack's PDPs run with principal verification off, so `session-start`
> works with a bare subject. A production PDP also needs the person's OIDC token,
> passed with `STRATIUM_PEP_PRINCIPAL_TOKEN_FILE`: see the
> [user guide](user-guide.md#31-stratium-pdp--the-decision-service), §3.1
> "Principal authentication".

Step 7 registers two label rules and caps the agent. The catch-all (`""` prefix →
`nato UNCLASSIFIED`) matters more than it looks: **once any cap is set, a resource
whose label cannot be resolved is denied.** Without a catch-all, capping an agent
denies essentially everything. The script refuses to set a cap without one — see
§7.

Step 8 issues a root delegation granting a deliberately narrow `Read,Grep,Glob`.
That narrowness is what makes step 10 able to prove anything.

### Open the console

Step 2 above printed a `pap=host:port` line — `up` and `status` both do, and
neither ever writes it to disk (ports are ephemeral; §3 covers why the tool
persists identity and never addresses). Open `http://<that address>/` in a
browser and sign in with one of the seeded Keycloak accounts, e.g. `pap-admin`
/ `pap_admin_local_dev_only` (`docs/user-guide.md` §2.2 lists all three). The
label rules and the classification cap step 7 just registered are editable
there too, alongside policies, agents, the tool catalog, and approvals —
`docs/user-guide.md` §5 is the full reference.

---

## 2. Finish the wiring

If you ran `up` from an ordinary terminal, step 9 wired the hooks and you can
skip to §3.

If you ran it **from inside a Claude Code or Codex session**, step 9 stopped:

```
[9] Wire the hooks
         SKIPPED -- this is running inside a claude session.
         Installing now would deny every tool call in it, including the ones
         you would need to recover: the session picks the hook up live, but it
         was not launched with the environment the hook reads.

         Finish from a plain terminal:
             deploy/stratium install --claude --bin /Users/you/stratium/bin/stratium-pep
             deploy/stratium run claude

         Or re-run with --wire-anyway if you meant to disable this session.
```

This is deliberate, and it is the trap most worth understanding. A `PreToolUse`
hook with `matcher: "*"` takes effect in an already-running session **immediately**.
That session was not launched with the ten environment variables the hook
reads, so every tool call in it starts denying — including the ones you would use
to undo it. Run the two commands from a plain terminal instead.

```bash
deploy/stratium install --claude --bin "$PWD/bin/stratium-pep"
```

**Observed:**

```
installed SessionStart + PreToolUse + PostToolUse + PostToolUseFailure (matcher '*', command '/Users/you/stratium/bin/stratium-pep') in /Users/you/stratium/.claude/settings.json

NEXT — start the agent with `deploy/stratium run claude`. It resolves the stack's ports and sets the 10 variables the hooks read. Starting `claude` any other way leaves every tool call denied.
```

`SessionStart` starts the session, `PreToolUse` decides each call, and the two
`PostToolUse` hooks tell the PDP which calls ran.

> **This gags every agent session already open in this project — including one
> you may be reading this guide with.** Installation takes effect live, and a
> session started any other way lacks the environment the hook reads, so its next
> tool call denies with `missing required configuration`. That is the hook working
> correctly, not a fault.
>
> Restart those sessions through `deploy/stratium run claude` (§3), or back the
> hooks out with `deploy/stratium --claude uninstall` — removal takes effect live
> too, and the session recovers on its next call.

---

## 3. Launch an agent

**Always start the agent through the launcher:**

```bash
deploy/stratium run claude
```

Anything you would pass to `claude` goes after it: `deploy/stratium run claude --resume`.

The launcher resolves the Docker ports and the agent id fresh, exports the ten
`STRATIUM_PEP_*` variables, and `exec`s the real binary. **Starting `claude`
directly leaves it denying every tool call** for want of configuration.

### Why a launcher and not a config file

Two of the eleven values cannot be stored:

- `STRATIUM_PEP_PDP_ADDR` is a Docker **ephemeral port**. It changed three times
  in one afternoon while this guide was being written — `64645`, then `60087`,
  then `51458`. Anything written to a file is wrong after the next
  `compose up`.
- Operator tokens expire after **five minutes** (Keycloak's default; the realm
  sets no `accessTokenLifespan`). The script mints them per request rather than
  holding one.

So the rule the whole tool is built around: **persist identity, never
addresses.** `.stratium-quickstart.json` holds the agent id and file paths.
Ports and tokens are never written to disk.

---

## 4. See it enforce

`up` registered three prefixes at `nato SECRET` — `/secret-`, `/tmp/secret-` and
`/private/tmp/secret-` — so any path starting one of those ways is above the
agent's `CONFIDENTIAL` ceiling. Use a `/tmp` one: macOS seals the root volume, so
`mkdir /secret-demo` fails with `Read-only file system`.

Make the file first — see the warning below — then ask for it in the launched
session:

```bash
mkdir -p /tmp/secret-demo && echo 'classified' > /tmp/secret-demo/plans.txt
```

```
use your Read tool on /tmp/secret-demo/plans.txt
```

The tool call is denied before it runs, and the agent is told why:

```
resource classification SECRET exceeds delegation cap CONFIDENTIAL in hierarchy "nato" (depth 0)
```

Reading anything else — `/tmp/notes.txt` — succeeds, because the catch-all rule
labels it `UNCLASSIFIED`, which is under the cap.

> **Why both `/tmp` and `/private/tmp` are registered.** The label match is on
> the literal path string the tool call carries, and macOS resolves `/tmp` to
> `/private/tmp`. Whichever spelling the agent happens to send has to hit a rule,
> or the path falls through to the catch-all and is allowed — a silent
> non-enforcement that looks exactly like a broken cap. Observed: both spellings
> deny, `exit=2`.

> **Ask for a tool, not an outcome, and make the file real.** This is the step
> most likely to look like a failure when nothing is wrong. Point a capable model
> at a path that does not exist and it lists the directory instead; point it at an
> empty file and it may `cat` it through `Bash`. Either way `Read` never fires,
> the hook is never consulted, and you have proven nothing. Name the tool
> explicitly, give the file content, or skip the model entirely and use `verify`
> (§5).
>
> Note that `Bash(cat /secret-demo/plans.txt)` is a *different* check, not an
> absent one. `Bash` is catalogued with a command field and no resource field, so
> its tier is derived from the command text — and, since 2026-08-28, its resource
> identity is too: every path the command names is extracted and the **strictest**
> label of the set decides. So the shell route denies here as well, and a benign
> path prepended to the secret one does not help. A command naming no path at all
> still has nothing to label, and still denies under any cap.

---

## 5. `verify` — proof, on demand

```bash
deploy/stratium verify
```

**Observed:**

```
delegation grants Read,Grep,Glob

  PASS  Read               exit=0 (want 0)  granted -- must be allowed
  PASS  LS                 exit=2 (want 2)  catalogued, held tool not in the grant -- must be denied
        tool "LS" not in delegation approved_tools at depth 0
  PASS  Frobnicate05946b8f exit=2 (want 2)  not even catalogued -- must be denied
        tool "Frobnicate05946b8f" not in delegation approved_tools at depth 0
  PASS  classification     exit=2 (want 2)  SECRET over a CONFIDENTIAL cap
        resource classification SECRET exceeds delegation cap CONFIDENTIAL in hierarchy "nato" (depth 0)

Enforcement proven: a held tool allowed, an unheld tool denied.
```

Exit `0` if every case passes, `1` otherwise. It feeds decisions straight to the
real binary — no model, no guessing what a tool call will look like.

Each case asserts on the **reason text**, not just the exit code. That matters
because this system has four independent ways to deny — action tier, tool
holding, classification, missing configuration — and all four exit `2`. A case
that checked only the exit code would stay green while silently testing something
else. That happened during development: a `Write` probe labelled "not in the
grant" was actually denying on action tier, because of a stale `tier_overrides`
row left on the shared tenant by an unrelated test suite.

Each run uses a fresh uuid-tagged resource path.

---

## 6. `doctor` — when something is wrong

```bash
deploy/stratium doctor
```

**Observed**, with the hooks installed, run from a shell that is not the
launcher:

```
  OK  toolchain    docker, docker compose, go
  OK  stack        24 services running
  OK  ports        pap=localhost:49415 pdp=localhost:49399
  OK  state        quickstart-cf50a3 (b51ce46a-f4de-4493-932b-81fb8afcf5ea)
  OK  binary       /Users/you/stratium/bin/stratium-pep
  OK  hooks        claude project       SessionStart /Users/you/stratium/bin/stratium-pep session-start
!!  hooks        claude project       hook entry writable by you: /Users/you/stratium/.claude/settings.json
!!  hooks        claude project       binary writable by you: /Users/you/stratium/bin/stratium-pep
  OK  hooks        claude project       PreToolUse   /Users/you/stratium/bin/stratium-pep hook
  OK  hooks        claude project       PostToolUse  /Users/you/stratium/bin/stratium-pep report
  OK  hooks        claude project       PostToolUseFailure /Users/you/stratium/bin/stratium-pep report
     note: the agent runs as you, so it can change this and stop being governed; `sudo -E deploy/stratium --claude install --system` puts it out of reach
  XX  environment  10 of 11 missing in this shell
     -> you are outside the launcher -- use: deploy/stratium run claude
  OK  delegation   a114c0c4-8e31-470e-b53b-7f92474e7f1b grants Read,Grep,Glob
  OK  caps         {"nato": "CONFIDENTIAL"} -- classification enforcement is on
```

It walks the layers in dependency order and names the fix for whatever is broken.
Exit `1` if anything is wrong.

The `!!` lines are a warning, not a fault: a per-project install leaves the hook
entry and the binary where the agent can change them. That is fine for trying
Stratium out; see [What the install protects](pep/hook.md#what-the-install-protects).

The `environment XX` above is not a fault — it is `doctor` correctly reporting
that *this* shell is not the launcher. That line is green only inside
`deploy/stratium run`.

**`hooks` is checked across every scope both harnesses merge** — project
`settings.json`, project `settings.local.json`, user `settings.json`, and
`~/.codex/hooks.json` — and prints the source of each. A hook hiding in a scope
you did not check denies every tool call in every project, while the one file you
did check reports clean.

---

## 7. Reading the refusals

The script refuses four things. Each refusal is a real hazard, not fussiness.

**No harness.**

```
stratium: error: pick a harness: --claude or --codex
```

**A binary that does not resolve.**

```
stratium: 'stratium-pep' is not runnable (not on PATH). A PreToolUse hook that
cannot run exits 127, which Claude Code treats as a non-blocking error — the tool
call proceeds unchecked. Pass --bin with a real path, or --force if you are
writing settings for another machine.
```

This is the important one. A missing hook binary is not a broken enforcement
point, it is **no enforcement point** — the transcript shows a hook error and
every tool call proceeds. `--force` exists for writing settings destined for
another machine.

**A cap with no catch-all rule** — `409`, from the API rather than the script.
With any cap set, an unresolvable label denies, so a cap without a catch-all
denies nearly everything. Register a `""`-prefix rule first, or pass
`?allow_uncovered=true` if a deny-by-default posture is what you want.

**A teardown of the wrong compose project.**

```
stratium: this would tear down compose project 'docker' with -v (volumes and
all), but `up` created 'stratium-throwaway'. Refusing.
```

Docker derives the project name from the compose file's parent directory —
`docker` here, which is not distinctive. Two checkouts resolve to the same
project, so `up` records what it created and `down` refuses anything else.

---

## 8. Tear it down

```bash
deploy/stratium down
```

**Order matters, and the script enforces it: hooks come off first, then the
stack.** Reverse that and every tool call in an open agent session denies against
a PDP that is no longer listening.

`down` removes the hooks from every scope, stops the stack with `-v`, and deletes
the state file, the built binary and the session file. Volumes go with it, so
agents, delegations and label rules do not survive.

To keep the stack and only unwire the agent:

```bash
deploy/stratium --claude uninstall
```

---

## 9. Command reference

| Command | What it does |
|---|---|
| `up --harness {claude,codex,both}` | Everything, ending on an observed denial. `--wire-anyway` overrides the in-session guard. |
| `run {claude,codex} [args...]` | Resolves ports and env, then `exec`s the agent. |
| `verify` | Four decisions through the real binary. Exit 0 on all pass. |
| `doctor` | Layer-by-layer diagnosis across every hook scope. Exit 0 when healthy. |
| `down [--force]` | Hooks, then stack, then local files. Refuses a foreign compose project. |
| `install` / `uninstall` / `status` | Hook wiring only. Requires `--claude` or `--codex`. |
| `selftest` | The script's own assertions. No stack required. |

Shared flags work on **either side** of the subcommand — `--claude install` and
`install --claude` are the same. Useful ones: `--bin PATH`, `--matcher Read` (start
narrow), `--only PreToolUse`, `--user`, `-n/--dry-run`.

### `--only PreToolUse`

`up` installs both hooks: `SessionStart` issues a delegation per session,
`PreToolUse` authorizes each call. If you are working through the manual test
plan, install **only** `PreToolUse` — a `SessionStart` hook re-issues a fresh
delegation on every session start, discarding one you built by hand.

---

## 10. Things that will bite you

- **`up` stops with `container docker-postgres-1 exited (1)`.** The cause is in
  the container's log, which `up` prints below the error. `No space left on
  device` means Docker's own disk is full: `docker system df` shows what is
  using it, and `docker builder prune` frees the build cache.
- **Keycloak needs port 8080 on your machine.** Every other port is chosen by
  Docker, but the sign-in page's address is fixed in the realm. If something
  else is listening on 8080, `up` fails with `port is already allocated`; stop
  the other program first.
- **A hook installed inside a running session takes effect immediately.** So does
  a removal. Do not install `matcher: "*"` from a session you are using.
- **`session-start`'s eight variables are not `hook`'s seven.** They overlap in
  five. Export only the first set and every tool call denies with `missing
  required configuration` — a denial that reads exactly like a policy denial
  until you open the reason. The launcher sets all ten.
- **Every tool call is denied until a session is started and a policy permits
  it.** Seeing everything denied after installing a hook is usually correct.
- **Five tools can never satisfy a cap.** `Glob`, `Grep`, `WebFetch`, `WebSearch`
  and `TodoWrite` declare no resource field, so they produce nothing to label and
  deny under any cap. The caps API lists them in its response.
- **Integration suites leave rows on the shared tenant** — `tier_overrides` in
  particular — and do not clean up. If a decision denies for a reason you did not
  expect, check that table before suspecting your code.

---

## See also

- `docs/architecture.md` — how the PEP, PDP and PAP fit together.
- `docs/pep.md` — the operator reference for the enforcement point: every
  configuration value, and how to read a denial.
- `docs/testing/2026-08-20-agent-integration-test.md` — the manual walkthrough
  this script automates, for when you want to see the moving parts.
