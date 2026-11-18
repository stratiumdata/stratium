# Your first governed agent

**You are** a developer or platform engineer trying Stratium for the first time.
**You want** Claude Code or Codex running with every tool call checked, and to
watch Stratium block one.

**You'll need** Docker with Compose v2, a Go toolchain, and Python 3. About ten
minutes.

## 1. Bring up the stack

```bash
git clone https://github.com/stratiumdata/stratium.git && cd stratium
deploy/stratium up --harness claude      # or --harness codex, or both
```

One command starts Postgres, Keycloak, the decision service (PDP) and the admin
plane (PAP), then sets up a working tenant:

- registers an agent,
- writes a policy that lets you delegate to it,
- loads the Claude Code tool catalog, so Stratium knows which argument of each
  tool names a file,
- labels everything `UNCLASSIFIED` and anything under `/tmp/secret-` as `SECRET`,
- caps the agent at `CONFIDENTIAL`,
- starts a session granting `Read`, `Grep`, and `Glob`.

!!! note "A production PDP also needs the person's OIDC token"
    The local stack's PDPs run with principal verification off, so a bare
    subject starts a session. A production PDP verifies who the session is for:
    give `session-start` the person's OIDC token with
    `STRATIUM_PEP_PRINCIPAL_TOKEN_FILE`. See the
    [user guide](../user-guide.md#31-stratium-pdp--the-decision-service), §3.1
    "Principal authentication".

!!! warning "Run it from a plain terminal"
    If you run `up` from inside an agent session, it skips installing the hook,
    because the hook would take effect in that session immediately and deny
    every tool call in it. Finish from a normal terminal, as the output tells you.

## 2. Launch the agent through Stratium

```bash
deploy/stratium run claude
```

The launcher starts the agent with the settings the hook needs. Every tool call
now goes to the PDP before it runs.

## 3. Watch it enforce

Create a file the agent is not cleared to read:

```bash
mkdir -p /tmp/secret-demo && echo 'classified' > /tmp/secret-demo/plans.txt
```

Then ask the agent:

```
use your Read tool on /tmp/secret-demo/plans.txt
```

The call is refused before it runs, and the agent is told why:

```
resource classification SECRET exceeds delegation cap CONFIDENTIAL in hierarchy "nato" (depth 0)
```

Reading an ordinary file such as `/tmp/notes.txt` succeeds, because it is
labelled `UNCLASSIFIED`, which is under the cap. This session doesn't grant
`Bash` at all, so the shell route is refused outright. Even in a session that
did grant it, `cat /tmp/secret-demo/plans.txt` would be refused, because
Stratium labels every path a shell command names.

!!! tip "Name the tool, and make the file real"
    If the file doesn't exist, a capable agent lists the directory instead of
    reading it, the read never happens, and nothing is proven. To check without
    a model in the loop, run `deploy/stratium verify`.

## 4. Look around

Open the admin console at the `pap=` address `up` printed, and sign in as
`pap-admin` / `pap_admin_local_dev_only`. You will find the agent, policy, label
rules, cap, and live delegation that `up` created.

## When you're done

```bash
deploy/stratium down                     # stops the stack and removes its data
deploy/stratium --claude uninstall       # removes the hook from this project
```

!!! danger "Don't leave the hook installed against a stopped stack"
    With no PDP to ask, the hook denies every tool call. That's the safe
    failure, and it will look like a broken agent.

## Next

- [Understand a denial](understand-a-denial.md): read any refusal you hit.
- [A default posture](../default-posture.md): sensible settings for a real agent.
- [Quickstart](../quickstart.md): the full transcript of every step above.
