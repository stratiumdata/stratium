package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"

	"github.com/stratiumdata/stratium/example/agent"
	"github.com/stratiumdata/stratium/internal/pdpgrpc"
)

// writeSessionFile writes path in the exact shape stratium-pep's own
// session-start does (services/cmd/stratium-pep/session_file.go's
// writeSessionFile): resp's raw JSON, indented, plus a trailing newline —
// identical to example/agent.ChainLink.WriteSessionFile's own encoding, but
// that method needs a Chain this program never builds (there is no second
// depth here, only one root delegation), so this is the same three lines
// written directly against the *pdpgrpc.CreateDelegationResponse
// agent.CreateDelegation already returns.
func writeSessionFile(resp *pdpgrpc.CreateDelegationResponse, path string) error {
	data, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		return fmt.Errorf("encode session file: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write session file %s: %w", path, err)
	}
	return nil
}

// pepHookEnv is the child environment for one `stratium-pep hook`
// invocation — the seven decision variables hook.go's own
// loadHookConfigFromEnv requires, plus the cache staleness window
// loadCacheConfigFromEnv requires alongside it, matching
// example/depth/hook's own hookEnv exactly (docs/pep/hook.md's own env
// table). ApprovalTimeout is short: no ESCALATE path is exercised by this
// example, so a surprise one fails fast rather than hanging.
func pepHookEnv(pdpAddr, agentID, sessionFile string) []string {
	return append(os.Environ(),
		"STRATIUM_PEP_PDP_ADDR="+pdpAddr,
		"STRATIUM_PEP_AGENT_ID="+agentID,
		"STRATIUM_PEP_SUBJECT="+subject,
		"STRATIUM_PEP_SESSION_FILE="+sessionFile,
		"STRATIUM_PEP_CONNECT_TIMEOUT=5s",
		"STRATIUM_PEP_APPROVAL_POLL_INTERVAL=2s",
		"STRATIUM_PEP_APPROVAL_TIMEOUT=10s",
		"STRATIUM_PEP_CACHE_STALENESS_WINDOW=5s",
	)
}

// hookStdin is the subset of Claude Code's own PreToolUse payload this
// program feeds on stdin, matching services/cmd/stratium-pep/hook.go's own
// hookStdin exactly, and example/depth/hook's own identical type.
type hookStdin struct {
	ToolName  string         `json:"tool_name"`
	ToolInput map[string]any `json:"tool_input"`
}

// hookDenyOutput decodes the JSON `stratium-pep hook` writes to stdout on an
// exit-2 deny, matching hook.go's own hookOutput/hookSpecificOutput wire
// shape, and example/depth/hook's own identical type.
type hookDenyOutput struct {
	HookSpecificOutput struct {
		PermissionDecision       string `json:"permissionDecision"`
		PermissionDecisionReason string `json:"permissionDecisionReason"`
	} `json:"hookSpecificOutput"`
}

// runHookProbe execs the real `stratium-pep hook` binary, feeds it stdin
// exactly as Claude Code's PreToolUse hook would, and turns its exit code
// into an agent.Result — or a Go error if the exit code is neither 0 (allow)
// nor 2 (deny), or the deny JSON does not parse. Duplicated from
// example/depth/hook/main.go's own runHookProbe rather than shared — see
// that file's own ensureAgent doc comment for why every runnable example in
// this suite keeps its own PAP/PEP plumbing local.
func runHookProbe(pepBin string, env []string, toolName string, toolInput map[string]any) (agent.Result, error) {
	stdin, err := json.Marshal(hookStdin{ToolName: toolName, ToolInput: toolInput})
	if err != nil {
		return agent.Result{}, fmt.Errorf("encode hook stdin: %w", err)
	}

	cmd := exec.Command(pepBin, "hook") //nolint:gosec // G204: pepBin is this example's own fixed configuration, never request data.
	cmd.Env = env
	cmd.Stdin = bytes.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	if runErr == nil {
		return agent.Result{Allowed: true}, nil
	}

	var exitErr *exec.ExitError
	if !errors.As(runErr, &exitErr) {
		// The process never even ran to completion (binary missing,
		// permission denied, killed) — unambiguously this example being
		// broken, not the PDP answering. agent.Precheck's own
		// binaryExecutableProbe (below) exists to catch the "missing"
		// case before this is ever reached.
		return agent.Result{}, fmt.Errorf("running stratium-pep hook: %w (stderr: %s)", runErr, stderr.String())
	}
	if exitErr.ExitCode() != 2 {
		return agent.Result{}, fmt.Errorf("stratium-pep hook exited %d, want 0 (allow) or 2 (deny) (stderr: %s)",
			exitErr.ExitCode(), stderr.String())
	}

	var out hookDenyOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		return agent.Result{}, fmt.Errorf("decode hook deny JSON: %w (stdout: %s)", err, stdout.String())
	}
	return agent.Result{Allowed: false, Reason: out.HookSpecificOutput.PermissionDecisionReason}, nil
}

// printDecision matches agent.Run's own ALLOW/DENY line format (agent/agent.go)
// and example/depth/hook's own printDecision exactly, so this program's
// transcript reads the same way every other example's does.
func printDecision(out io.Writer, name string, args map[string]any, res agent.Result) {
	argsJSON, _ := json.Marshal(args)
	if res.Allowed {
		fmt.Fprintf(out, "  ALLOW  %-18s %s\n", name, argsJSON)
	} else {
		fmt.Fprintf(out, "  DENY   %-18s %s\n         %s\n", name, argsJSON, res.Reason)
	}
}

// binaryExecutableProbe is a Precheck probe confirming pepBin exists and is
// executable before this program ever tries to exec it, matching
// example/depth/hook's own identical probe.
func binaryExecutableProbe(pepBin string) func() error {
	return func() error {
		info, err := os.Stat(pepBin)
		if err != nil {
			return err
		}
		if info.IsDir() {
			return fmt.Errorf("%s is a directory, not a binary", pepBin)
		}
		if info.Mode()&0o111 == 0 {
			return fmt.Errorf("%s is not executable", pepBin)
		}
		return nil
	}
}
