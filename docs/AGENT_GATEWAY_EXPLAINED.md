# How the Stratium Agent Gateway Works

**A Non-Technical Guide**

---

## The Problem: AI Agents Acting on Your Behalf

When you ask an AI assistant like Claude or ChatGPT to do something — read a financial report, write code, send an email — the AI is acting *on your behalf*. It's using your access, your permissions, your authority.

Today, most systems treat this as if *you* did the action. If you can read a confidential document, so can the AI. If you can delete a database, so can the AI. There's no way to say:

- "The AI can read my spreadsheets, but not my emails."
- "The AI can help for the next 30 minutes, then its access expires."
- "If something goes wrong, I want to instantly cut off the AI's access."

This is like giving someone a copy of your house key with no way to change the locks. The Stratium Agent Gateway solves this.

---

## The Solution: A Permission Slip for AI

Think of the Agent Gateway like a **permission slip system at a school**:

1. **The parent (you)** writes a permission slip: "My child (the AI) can go on the field trip (read financial reports) until 3pm (token expires)."
2. **The teacher (Agent Gateway)** checks the slip before every activity: "Does this slip allow the museum visit? Yes. Does it allow skydiving? No."
3. **If the parent calls the school** and says "cancel the trip," the teacher immediately stops all activities — no matter where the child is.

The AI agent can't forge the permission slip, can't extend its own deadline, and can't add activities that weren't on the original slip.

---

## How It Works: Three Checkpoints

Every time an AI agent tries to do something, the Agent Gateway checks three things:

### Checkpoint 1: Is the User Allowed?

Just because you asked the AI to do something doesn't mean *you're* allowed to do it. The Gateway first checks your own permissions.

**Example:** You're a financial analyst with INTERNAL clearance. You ask Claude to read a board-level strategic plan classified as CONFIDENTIAL. The Gateway says: "The user doesn't have CONFIDENTIAL clearance. Denied." The AI never sees the document.

### Checkpoint 2: Is the AI Agent Trusted Enough?

AI agents have their own trust levels, separate from yours. A brand-new, unverified agent has fewer permissions than a certified, battle-tested agent.

| Trust Level | What It Can Do | Real-World Analogy |
|-------------|---------------|-------------------|
| Unverified | Read public information only | A visitor with a guest badge |
| Registered | Read + limited changes | A regular employee |
| Certified | Full access within its scope | A department manager |
| Platform-Trusted | System-level actions | A security administrator |

Even if you're the CEO, an Unverified AI agent working on your behalf can only read public data.

### Checkpoint 3: Does the Permission Slip Allow This?

The permission slip (called a "delegation token") lists exactly what the AI can do:

- **Which tools:** "Can read files and search, but cannot write or delete."
- **How sensitive:** "Can access INTERNAL data, but not CONFIDENTIAL or RESTRICTED."
- **How long:** "Valid for 30 minutes."

If the AI tries to do anything not on the slip, it's denied.

**All three checkpoints must say "yes" for the action to proceed.** If any one says "no," the action is blocked.

---

## Sub-Agents: Delegation Chains

Sometimes an AI agent needs to delegate work to another AI agent — like a manager assigning tasks to team members.

The Agent Gateway supports this with a simple rule: **a sub-agent can receive the same permissions as its parent, or fewer — but never more.**

This means:
- A parent agent can pass its **full scope** to a sub-agent (same tools, same clearance, same time limit).
- A parent agent can **choose to narrow** the scope if the sub-agent doesn't need everything.
- A parent agent **cannot give a sub-agent more** than it has itself.

**Example — Same scope (common case):**

1. You give Claude permission to "analyze financial data" (read + write, INTERNAL clearance).
2. Claude creates a sub-agent with the same permissions (read + write, INTERNAL clearance).
3. The sub-agent can do everything Claude can — no loss of functionality.

**Example — Narrowed scope (when appropriate):**

1. You give Claude permission to "analyze financial data" (read + write, INTERNAL clearance).
2. Claude creates a sub-agent specifically for summarizing reports — only needs read access.
3. Claude gives the sub-agent narrower permissions (read only, INTERNAL clearance).

The narrowing is a **choice**, not a requirement. The security guarantee is that no sub-agent can escalate beyond what the original user authorized.

If you revoke Claude's permission at the top, *all* sub-agents lose access instantly — like pulling out the top card in a house of cards.

---

## Real-Time Revocation

One of the most important features: you can cut off an AI agent's access at any time, and it takes effect immediately.

**How it works:**

1. You're watching an AI agent work on your financial analysis.
2. You notice it's heading in an unexpected direction.
3. You revoke the delegation.
4. The very next action the AI tries is denied. Not the next session — the next action, within seconds.

If the agent had created sub-agents, they're all revoked too. No stragglers, no orphaned permissions.

---

## The Audit Trail: Proof of What Happened

Every single action — whether it was allowed or denied — is recorded:

```
TIME                 AGENT              ACTION      DECISION   REASON
2026-04-11 14:23:01  claude-analyst     read file   ALLOW      within scope
2026-04-11 14:23:05  claude-analyst     read file   DENY       CONFIDENTIAL > cap INTERNAL
2026-04-11 14:23:08  claude-analyst     write file  DENY       tier 3 > max tier 2
```

This gives you:
- **Who** asked the AI to do what
- **Which AI** tried to do it
- **What** the AI tried to do
- **Whether** it was allowed or denied
- **Why** it was allowed or denied

For regulated industries (banking, healthcare, government), this audit trail is the difference between "we trust the AI" and "we can prove exactly what the AI did."

---

## Multi-Provider: Works with Any AI

The Agent Gateway doesn't care which AI provider you use. The same authorization system works for:

- **Anthropic Claude** (Claude Code, Claude Desktop)
- **OpenAI** (Codex, ChatGPT Desktop)
- **Custom agents** (your own AI applications)

You can even have a Claude agent delegate to a Codex sub-agent, and the entire permission chain is tracked across both providers.

---

## Why This Matters

### For Security Teams

"We can prove the AI stayed within its authorized scope. Here's the cryptographic proof and audit trail."

### For Compliance Officers

"Every AI action is logged with the full authorization chain. We can show auditors exactly what happened and why it was allowed."

### For Developers

"I can give AI agents the access they need to be useful, without worrying about them accessing things they shouldn't."

### For Executives

"We can adopt AI across the organization while maintaining the same security and compliance standards we have for human users."

---

## Summary

The Stratium Agent Gateway is a security layer between AI agents and your data. It:

1. **Checks three things** before every action: user permissions, agent trust level, and the specific permission slip.
2. **Enforces scope limits** — the AI can only do what's on the permission slip, nothing more.
3. **Supports delegation chains** — sub-agents get narrower permissions, never broader.
4. **Enables real-time revocation** — cut off an AI's access instantly.
5. **Records everything** — full audit trail of every action, allowed or denied.
6. **Works with any AI provider** — Claude, ChatGPT, Codex, or custom agents.

It's the difference between trusting AI on faith and trusting AI with proof.
