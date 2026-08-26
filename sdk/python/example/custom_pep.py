#!/usr/bin/env python3
"""A custom PEP, in about sixty lines.

Mints a delegation for Read only, then checks two calls: one it should be
allowed to make and one it should not. Exits non-zero if either differs, and
asserts on the PDP's own reason strings rather than on exit codes -- a denial
for the wrong reason is a failure, not a pass.

    python3 custom_pep.py --pdp localhost:56378 --agent <uuid> --subject you@example.com
"""

import argparse
import sys

from stratium import Client, Session


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pdp", required=True, help="host:port of the PDP")
    ap.add_argument("--agent", required=True, help="an agent id in the PDP's tenant")
    ap.add_argument("--subject", required=True)
    args = ap.parse_args()

    with Client(args.pdp) as client:
        session = Session(
            client, subject=args.subject, agent_id=args.agent,
            tools=["Read"], max_action_tier=1,
            purpose="stratium python sdk example", ttl_seconds=300,
        )
        print(f"delegation {session.grant.delegation_id}")
        print(f"  granted tools: {list(session.grant.granted_scope.tools)}")
        print(f"  granted tier:  {session.grant.granted_scope.max_action_tier}")
        print()

        expectations = [
            ("Read", {"file_path": "/tmp/notes.txt"}, True, None),
            ("Bash", {"command": "rm -rf /tmp/x"}, False, "approved_tools"),
        ]

        failures = 0
        for tool, raw_input, want_allowed, want_reason in expectations:
            d = session.check(tool=tool, raw_input=raw_input)
            verdict = "ALLOW" if d else "DENY "
            print(f"  {verdict} {tool:6} {d.reason}")

            if bool(d) != want_allowed:
                print(f"    MISMATCH: expected {'ALLOW' if want_allowed else 'DENY'}")
                failures += 1
            elif want_reason and want_reason not in d.reason:
                # A denial for the wrong cause is not a pass.
                print(f"    MISMATCH: expected the reason to mention {want_reason!r}")
                failures += 1

        print()
        print(f"enforcement: {len(expectations) - failures}/{len(expectations)} as expected")
        return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
