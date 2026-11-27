# Try the hosted demo

[demo.stratium.dev](https://demo.stratium.dev) is a running Stratium tenant you
can point an agent at without starting anything yourself. In about ten minutes
you sign in to the admin console, open a session for an agent, and watch that
session's tool calls be allowed and denied, first by hand and then from a real
Claude Code session.

**Every command below was run against the live demo while writing this, and
the output under each step is what came back.** Ids differ on your run.

The enforcement point runs on your machine, because that is where your agent's
tool calls happen. Everything it asks is decided by the hosted service.

| | |
|---|---|
| Console | <https://demo.stratium.dev> |
| Login | `demo` / `00b4b1e3f4d4719a` |
| Decision service | `demo.stratium.dev:443` |
| Agent id | `7d1f3c52-9a4e-4b0e-8c1d-5e2a6f0b9d31` |

!!! warning "This is a shared sandbox"
    Every visitor uses the same login and the same tenant, so other people can
    see and change what you create. Do not put anything real in it. It is reset
    to the state described here from time to time.

## 1. Look around the console

Open <https://demo.stratium.dev> and sign in with the login above. Three
screens hold what the rest of this page relies on:

- **Agents** has one row, `demo-agent`. Your session will act as it.
- **Policies** has `demo-grant`, the policy that lets the demo login hold
  tools at all. Without a policy naming the person, no session can be opened.
- **Label rules** has three rows. Paths starting `/tmp/secret-` or
  `/private/tmp/secret-` are `SECRET`; everything else is `UNCLASSIFIED`. The
  agent is capped at `CONFIDENTIAL`, so it may not touch the first kind.

## 2. Build the enforcement point

You need Git and Go 1.26 or newer.

```bash
git clone https://github.com/stratiumdata/stratium.git && cd stratium
(cd services && go build -o ../bin/stratium-pep ./cmd/stratium-pep)
```

Everything below runs from the repository root.

## 3. Prove who you are

The decision service does not take your word for whose authority an agent acts
under. It wants a token from the identity provider, and reads the person from
that.

```bash
umask 077
curl -s https://demo.stratium.dev/realms/stratium/protocol/openid-connect/token \
  -d grant_type=password -d client_id=stratium-pdp \
  -d username=demo -d password=00b4b1e3f4d4719a -d 'scope=openid email' |
  python3 -c 'import sys, json; print(json.load(sys.stdin)["access_token"])' > principal.jwt
```

The token lasts five minutes and is only needed to open a session, so run
step 4 straight away. Come back here for a fresh one whenever you open another.

## 4. Open a session

```bash
export STRATIUM_PEP_PDP_ADDR=demo.stratium.dev:443
export STRATIUM_PEP_AGENT_ID=7d1f3c52-9a4e-4b0e-8c1d-5e2a6f0b9d31
export STRATIUM_PEP_SUBJECT=demo@example.com
export STRATIUM_PEP_SESSION_FILE="$PWD/demo-session.json"
export STRATIUM_PEP_PRINCIPAL_TOKEN_FILE="$PWD/principal.jwt"
export STRATIUM_PEP_CONNECT_TIMEOUT=5s
export STRATIUM_PEP_APPROVAL_POLL_INTERVAL=2s
export STRATIUM_PEP_APPROVAL_TIMEOUT=120s
export STRATIUM_PEP_REQUESTED_TOOLS=Read,Grep,Glob
export STRATIUM_PEP_REQUESTED_TIER=3
export STRATIUM_PEP_TTL_SECONDS=3600
export STRATIUM_PEP_PURPOSE="trying the demo"

bin/stratium-pep session-start
```

It prints nothing and exits `0`. `demo-session.json` now holds what was granted:

```json
{"delegation_id": "59cd941c-297e-49d6-8753-8d83361da1fa",
 "granted_scope": {"max_action_tier": 3, "tools": ["Read", "Grep", "Glob"]},
 "token": "eyJhbGciOiJFUzI1NiIs…"}
```

That is a delegation: the demo login handing `demo-agent` three tools, up to
action tier 3, for an hour. The grant is deliberately narrow so the next step
has something to refuse. Open **Delegations** in the console and it is there.

## 5. Ask for decisions

`stratium-pep hook` is what an agent harness calls before each tool call. It
reads the call on standard input, asks the decision service, and exits `0` to
allow or `2` to deny. You can feed it calls by hand:

```bash
ask() { printf '%s' "$1" | bin/stratium-pep hook; echo "exit=$?"; }
```

**A tool the session holds, on an ordinary file.** Allowed.

```bash
ask '{"tool_name":"Read","tool_input":{"file_path":"/tmp/notes.txt"}}'
```

```
exit=0
```

**A tool the session was never given.**

```bash
ask '{"tool_name":"Write","tool_input":{"file_path":"/tmp/notes.txt","content":"x"}}'
```

```
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"tool \"Write\" not in delegation approved_tools at depth 0"}}
exit=2
```

**A held tool, on a file above the agent's ceiling.**

```bash
ask '{"tool_name":"Read","tool_input":{"file_path":"/tmp/secret-demo/plans.txt"}}'
```

```
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"resource classification SECRET exceeds delegation cap CONFIDENTIAL in hierarchy \"nato\" (depth 0)"}}
exit=2
```

**A shell command more dangerous than the session's tier.**

```bash
ask '{"tool_name":"Bash","tool_input":{"command":"rm -rf /tmp/x"}}'
```

```
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"action tier DESTRUCTIVE exceeds delegation max_action_tier EXTERNAL_COMMS at depth 0"}}
exit=2
```

Three denials, three different reasons: the tool, the data, and the action.
None of these calls ran anything; the decision comes before the tool.

## 6. Try to cheat

The enforcement point is on your machine, so you control what it says. The
decision service is built so that lying to it does not get a better answer.

**Claim the session belongs to someone else.**

```bash
STRATIUM_PEP_SUBJECT=someone@example.com \
  ask '{"tool_name":"Read","tool_input":{"file_path":"/tmp/notes.txt"}}'
```

```
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"delegation chain is not well-formed: request subject is not the principal root delegation 15fccdc5-5411-4356-a51b-a547c06bfd1f was issued for"}}
exit=2
```

**Open a session in someone else's name with your own token.**

```bash
STRATIUM_PEP_SUBJECT=someone@example.com STRATIUM_PEP_SESSION_FILE="$PWD/other.json" \
  bin/stratium-pep session-start
```

```
stratium-pep: could not create delegation: rpc error: code = PermissionDenied desc = subject is not the principal that principal_token identifies
```

(If this one says the token is expired instead, repeat step 3 first.)

## 7. Ask for more

A session gets what it asks for only up to what the person holds. Get a fresh
token (step 3), then ask for `Write` as well:

```bash
STRATIUM_PEP_REQUESTED_TOOLS=Read,Grep,Glob,Write bin/stratium-pep session-start
ask '{"tool_name":"Write","tool_input":{"file_path":"/tmp/notes.txt","content":"x"}}'
```

```
exit=0
```

The same call that was denied in step 5 is allowed, because this session was
granted the tool. The `SECRET` file is still out of reach: the ceiling belongs
to the agent, not to the session.

## 8. Put it in front of a real agent

So far you have played the agent yourself. To have Claude Code make the calls,
install the hook in an empty project. Use a scratch directory, not a project
you are working in: the hook governs every tool call in the project it is
installed in.

```bash
mkdir -p /tmp/stratium-demo-project && echo "hello from the demo" > /tmp/stratium-demo-project/notes.txt
mkdir -p /tmp/secret-demo && echo "classified" > /tmp/secret-demo/plans.txt

deploy/stratium --claude --only PreToolUse \
  --settings /tmp/stratium-demo-project/.claude/settings.json \
  --bin "$PWD/bin/stratium-pep" install
```

The installer prints a block of `export` lines for the local stack. Ignore it:
the variables you exported in step 4 are the ones the hook reads, and they
already point at the demo. Start Claude Code from the same shell, so it
inherits them:

```bash
cd /tmp/stratium-demo-project && claude
```

Then ask it:

```
Use your Read tool on notes.txt, then on /tmp/secret-demo/plans.txt.
```

The first read succeeds. The second is stopped before it runs, and the agent
is told why:

```
PreToolUse:Read hook error: resource classification SECRET exceeds delegation cap CONFIDENTIAL in hierarchy "nato" (depth 0)
```

Name the tool when you ask. Given only a goal, a capable model may reach for a
different tool, and then you are watching a different rule.

## 9. Clean up

From the repository root:

```bash
deploy/stratium --claude --settings /tmp/stratium-demo-project/.claude/settings.json uninstall
rm -rf /tmp/stratium-demo-project /tmp/secret-demo principal.jwt demo-session.json other.json
```

Sessions expire on their own after the hour you asked for.

## Where to go next

- The [quickstart](quickstart.md) runs the whole system on your own machine,
  where you are the administrator and can change the policies, ceilings and
  approvals the demo keeps fixed.
- [Understand a denial](journeys/understand-a-denial.md) explains each of the
  reasons you saw above.
- [The concepts](concepts.md) covers what a delegation is and why the chain of
  them is what gets checked.
