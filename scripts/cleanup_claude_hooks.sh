#!/usr/bin/env bash
#
# cleanup_claude_hooks.sh — Remove all state left behind by Stratium Claude Code
# hook testing. Pairs with scripts/test_claude_hooks.sh and the procedure
# documented in docs/TESTING_CLAUDE_HOOKS.md.
#
# Usage:
#   ./scripts/cleanup_claude_hooks.sh           # perform cleanup
#   ./scripts/cleanup_claude_hooks.sh --dry-run # show what would be removed
#   ./scripts/cleanup_claude_hooks.sh --yes     # skip confirmation prompt
#
# Safe to re-run: every step tolerates missing files.

set -euo pipefail

DRY_RUN=0
ASSUME_YES=0
for arg in "$@"; do
  case "$arg" in
    --dry-run) DRY_RUN=1 ;;
    --yes|-y)  ASSUME_YES=1 ;;
    -h|--help)
      sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "Unknown argument: $arg" >&2
      exit 2
      ;;
  esac
done

run() {
  if [[ $DRY_RUN -eq 1 ]]; then
    echo "DRY-RUN: $*"
  else
    echo "+ $*"
    eval "$@"
  fi
}

confirm() {
  [[ $ASSUME_YES -eq 1 || $DRY_RUN -eq 1 ]] && return 0
  read -r -p "Proceed with cleanup? [y/N] " reply
  [[ "$reply" =~ ^[Yy]$ ]]
}

echo "Stratium Claude hook cleanup"
echo "============================"
echo "Mode: $([[ $DRY_RUN -eq 1 ]] && echo dry-run || echo execute)"
echo

if ! confirm; then
  echo "Aborted."
  exit 1
fi

echo
echo "[1/5] Test session and project files in /tmp"
run "rm -f /tmp/stratium-test-session.json"
run "rm -f /tmp/stratium-session-*.json"
run "rm -rf /tmp/stratium-test-project /tmp/CLAUDE.md /tmp/mcp-test-claude.md"

echo
echo "[2/5] Machine config in ~/.claude"
run "rm -f \"$HOME/.claude/stratium.json\""
run "rm -f \"$HOME/.claude/stratium-agent.json\""
run "rm -f \"$HOME/.claude/stratium-tokens.json\""

echo
echo "[3/5] Bash hook delegation cache"
run "rm -f \"$HOME/.stratium/delegation.json\""

echo
echo "[4/5] Keychain entries (Phase 2 secure token storage)"
case "$(uname -s)" in
  Darwin)
    run "security delete-generic-password -s 'stratium-claude-hooks' >/dev/null 2>&1 || true"
    ;;
  Linux)
    if command -v secret-tool >/dev/null 2>&1; then
      run "secret-tool clear service stratium-claude-hooks 2>/dev/null || true"
    else
      echo "  secret-tool not installed; skipping Linux keyring cleanup"
    fi
    ;;
  *)
    echo "  Unknown OS $(uname -s); skipping keychain cleanup"
    ;;
esac

echo
echo "[5/5] Stratium hook entries in Claude Code settings"
if command -v stratium-hooks >/dev/null 2>&1; then
  run "stratium-hooks configure --gateway localhost:50054"
else
  echo "  stratium-hooks CLI not on PATH."
  echo "  Manually edit ~/.claude/settings.json to remove any 'stratium' hook entries."
fi

echo
echo "Done."
