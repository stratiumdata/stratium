#!/usr/bin/env python3
"""A custom PEP, in about sixty lines.

Mints a delegation for Read only, then checks three calls: one it should be
allowed to make, and two it should not -- denied for two DIFFERENT reasons,
because DelegationLeg checks the tier ceiling before the tool-name check, so
a call over tier is refused before its tool is ever looked up. Exits
non-zero if any differs, and asserts on the PDP's own reason strings rather
than on exit codes -- a denial for the wrong reason is a failure, not a pass.

    python3 custom_pep.py --pdp localhost:56378 --agent <uuid> --subject you@example.com --insecure
"""

import argparse
import sys

from stratium import Client, Session


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pdp", required=True, help="host:port of the PDP")
    ap.add_argument("--agent", required=True, help="an agent id in the PDP's tenant")
    ap.add_argument("--subject", required=True)
    ap.add_argument("--ca-file", help="PEM CA bundle for the PDP's certificate (default: system roots)")
    ap.add_argument("--insecure", action="store_true", help="plaintext, for the local Docker stack only")
    args = ap.parse_args()

    with Client(args.pdp, insecure=args.insecure, ca_file=args.ca_file) as client:
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
            # Granted, and within the tier ceiling.
            ("Read", {"file_path": "/tmp/notes.txt"}, True, None),

            # Catalogued READ_ONLY, so the tier gate passes -- and the
            # delegation simply does not hold this tool.
            ("Grep", {"pattern": "TODO", "path": "/tmp"}, False, "approved_tools"),

            # Refused EARLIER than the tool check: DelegationLeg tests the tier
            # ceiling first, and Bash's tier is derived from its command, which
            # makes `rm -rf` DESTRUCTIVE against a READ_ONLY ceiling. The tool
            # name never gets examined.
            ("Bash", {"command": "rm -rf /tmp/x"}, False, "max_action_tier"),
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
