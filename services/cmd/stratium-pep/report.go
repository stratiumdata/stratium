// report.go implements `stratium-pep report`: the PostToolUse half of the
// hook surface. `hook` asks the PDP before a tool call; `report` tells the
// PDP after one that it ran, so the PDP can notice a tool call it was never
// asked about (pdpgrpc's tool_use.go has the other half).
//
// It can change nothing: the tool call is over. So it never blocks, never
// writes to stdout, and always exits 0 -- a failure to report is one line on
// stderr. The opposite of `hook`, which denies on every failure.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stratiumdata/stratium/internal/pdpgrpc"
)

// reportConfig is what `report` needs: where the PDP is, and where the
// session's token is. It names no agent or subject; the token does that.
type reportConfig struct {
	PDPAddr         string
	SessionFilePath string
	ConnectTimeout  time.Duration
}

func loadReportConfigFromEnv() (reportConfig, error) {
	var missing []string
	cfg := reportConfig{
		PDPAddr:         requiredEnv("STRATIUM_PEP_PDP_ADDR", &missing),
		SessionFilePath: requiredEnv("STRATIUM_PEP_SESSION_FILE", &missing),
	}
	timeoutRaw := requiredEnv("STRATIUM_PEP_CONNECT_TIMEOUT", &missing)
	if len(missing) > 0 {
		return reportConfig{}, missingConfigError(missing)
	}
	timeout, err := requiredDuration("STRATIUM_PEP_CONNECT_TIMEOUT", timeoutRaw)
	if err != nil {
		return reportConfig{}, err
	}
	cfg.ConnectTimeout = timeout
	return cfg, nil
}

// reportClient is the part of the PDP client `report` uses.
type reportClient interface {
	ReportToolUse(ctx context.Context, in *pdpgrpc.ReportToolUseRequest, opts ...grpc.CallOption) (*pdpgrpc.ReportToolUseResponse, error)
	IssueToken(ctx context.Context, in *pdpgrpc.IssueTokenRequest, opts ...grpc.CallOption) (*pdpgrpc.IssueTokenResponse, error)
}

// args may name the harness (`--harness copilot`), for one whose after-the-
// call payload is not Claude Code's. The report must be read exactly as the
// decision was, or the two would not match.
func runReportCmd(args []string, stdin io.Reader, stderr io.Writer) int {
	stdin, err := harnessStdin(args, stdin)
	if err == nil {
		err = dialAndReport(stdin)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "stratium-pep report: %s\n", err)
	}
	return 0
}

func dialAndReport(stdin io.Reader) error {
	cfg, err := loadReportConfigFromEnv()
	if err != nil {
		return err
	}
	conn, err := dialPDP(cfg.PDPAddr)
	if err != nil {
		return fmt.Errorf("could not create PDP client: %w", err)
	}
	defer func() { _ = conn.Close() }()
	return reportToolUse(stdin, pdpgrpc.NewPDPServiceClient(conn), cfg)
}

// reportToolUse forwards one PostToolUse payload. tool_input goes on the wire
// as the exact bytes the harness sent, as it does in `hook`: the PDP matches
// on a digest of them.
func reportToolUse(stdin io.Reader, client reportClient, cfg reportConfig) error {
	body, err := io.ReadAll(stdin)
	if err != nil {
		return fmt.Errorf("could not read stdin: %w", err)
	}
	var in hookStdin
	if err := json.Unmarshal(body, &in); err != nil {
		return fmt.Errorf("malformed stdin: %w", err)
	}
	if in.ToolName == "" {
		return fmt.Errorf("malformed stdin: tool_name is required")
	}
	// Cursor runs its tool-failure hook for a call that was denied as well as
	// for one that ran and failed. A denied call did not run, so it is not
	// reported; no other harness sends this field.
	var failure struct {
		Type string `json:"failure_type"`
	}
	if _ = json.Unmarshal(body, &failure); failure.Type == "permission_denied" {
		return nil
	}
	sess, err := loadSessionFile(cfg.SessionFilePath)
	if err != nil {
		return err
	}
	req := &pdpgrpc.ReportToolUseRequest{
		Token:    sess.GetToken(),
		Tool:     in.ToolName,
		RawInput: string(in.ToolInput),
	}

	err = sendReport(client, cfg.ConnectTimeout, req)
	if status.Code(err) != codes.Unauthenticated {
		return err
	}
	// The token may simply have expired while the tool ran. One re-issue and
	// one retry, as `hook` does for a denied Decide (reissue.go).
	ctx, cancel := context.WithTimeout(context.Background(), cfg.ConnectTimeout)
	defer cancel()
	issued, issueErr := client.IssueToken(ctx, &pdpgrpc.IssueTokenRequest{
		DelegationId: sess.GetDelegationId(),
		TtlSeconds:   reissueTTLSeconds,
		Token:        req.GetToken(),
	})
	if issueErr != nil {
		return fmt.Errorf("re-issue token: %s", describeRPCError(issueErr, agentOrDelegationUnknownMsg))
	}
	req.Token = issued.GetToken()
	return sendReport(client, cfg.ConnectTimeout, req)
}

func sendReport(client reportClient, timeout time.Duration, req *pdpgrpc.ReportToolUseRequest) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_, err := client.ReportToolUse(ctx, req)
	return err
}
