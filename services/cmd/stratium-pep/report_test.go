package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stratiumdata/stratium/internal/pdpgrpc"
)

type fakeReportClient struct {
	reports   []*pdpgrpc.ReportToolUseRequest
	rejectOld bool // refuse any token but the re-issued one
	issueErr  error
	issued    int
}

func (c *fakeReportClient) ReportToolUse(_ context.Context, in *pdpgrpc.ReportToolUseRequest, _ ...grpc.CallOption) (*pdpgrpc.ReportToolUseResponse, error) {
	c.reports = append(c.reports, &pdpgrpc.ReportToolUseRequest{Token: in.GetToken(), Tool: in.GetTool(), RawInput: in.GetRawInput()})
	if c.rejectOld && in.GetToken() != "fresh" {
		return nil, status.Error(codes.Unauthenticated, "token: expired")
	}
	return &pdpgrpc.ReportToolUseResponse{Matched: true}, nil
}

func (c *fakeReportClient) IssueToken(_ context.Context, _ *pdpgrpc.IssueTokenRequest, _ ...grpc.CallOption) (*pdpgrpc.IssueTokenResponse, error) {
	c.issued++
	if c.issueErr != nil {
		return nil, c.issueErr
	}
	return &pdpgrpc.IssueTokenResponse{Token: "fresh"}, nil
}

func reportTestConfig(t *testing.T) reportConfig {
	t.Helper()
	path := filepath.Join(t.TempDir(), "session.json")
	writeTestSessionFile(t, path, "11111111-1111-1111-1111-111111111111", "stale")
	return reportConfig{SessionFilePath: path, ConnectTimeout: time.Second}
}

func TestReportToolUse_ForwardsToolAndRawInputBytes(t *testing.T) {
	client := &fakeReportClient{}
	raw := `{"command":"echo \"héllo\"",  "n":1}`
	if err := reportToolUse(stdinBody("Bash", raw), client, reportTestConfig(t)); err != nil {
		t.Fatal(err)
	}
	if len(client.reports) != 1 {
		t.Fatalf("sent %d reports, want 1", len(client.reports))
	}
	got := client.reports[0]
	if got.GetTool() != "Bash" || got.GetRawInput() != raw || got.GetToken() != "stale" {
		t.Errorf("report = %+v, want the tool, the session token and tool_input byte for byte", got)
	}
}

func TestReportToolUse_ReissuesAnExpiredTokenOnce(t *testing.T) {
	client := &fakeReportClient{rejectOld: true}
	if err := reportToolUse(stdinBody("Bash", `{}`), client, reportTestConfig(t)); err != nil {
		t.Fatal(err)
	}
	if client.issued != 1 || len(client.reports) != 2 || client.reports[1].GetToken() != "fresh" {
		t.Errorf("issued=%d reports=%d, want one re-issue and a retry with the new token", client.issued, len(client.reports))
	}
}

func TestReportToolUse_Errors(t *testing.T) {
	cfg := reportTestConfig(t)
	if err := reportToolUse(strings.NewReader("not json"), &fakeReportClient{}, cfg); err == nil {
		t.Error("malformed stdin: want an error")
	}
	if err := reportToolUse(strings.NewReader(`{"tool_input":{}}`), &fakeReportClient{}, cfg); err == nil {
		t.Error("no tool_name: want an error")
	}
	noSession := reportConfig{SessionFilePath: filepath.Join(t.TempDir(), "absent"), ConnectTimeout: time.Second}
	if err := reportToolUse(stdinBody("Bash", `{}`), &fakeReportClient{}, noSession); err == nil {
		t.Error("no session file: want an error")
	}
	failing := &fakeReportClient{rejectOld: true, issueErr: status.Error(codes.PermissionDenied, "revoked")}
	if err := reportToolUse(stdinBody("Bash", `{}`), failing, cfg); err == nil {
		t.Error("re-issue refused: want an error")
	}
}

// The tool call is over by the time `report` runs: nothing it does may look
// like a decision, so it exits 0 and keeps stdout empty even when it cannot
// report at all.
func TestDispatch_Report_ExitsZeroAndSilentOnFailure(t *testing.T) {
	t.Setenv("STRATIUM_PEP_PDP_ADDR", "")
	var stdout, stderr bytes.Buffer
	code := dispatch([]string{"report"}, stdinBody("Bash", `{}`), &stdout, &stderr)
	if code != 0 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "stratium-pep report:") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

// Cursor's failure hook also fires for a call that was denied. That call did
// not run, so reporting it would flag every refusal as an undecided call.
func TestReportToolUse_SkipsACallCursorSaysWasDenied(t *testing.T) {
	client := &fakeReportClient{}
	denied := `{"tool_name":"Shell","tool_input":{"command":"ls"},"failure_type":"permission_denied"}`
	if err := reportToolUse(strings.NewReader(denied), client, reportTestConfig(t)); err != nil {
		t.Fatalf("reportToolUse() error = %v", err)
	}
	failed := `{"tool_name":"Shell","tool_input":{"command":"ls"},"failure_type":"error"}`
	if err := reportToolUse(strings.NewReader(failed), client, reportTestConfig(t)); err != nil {
		t.Fatalf("reportToolUse() error = %v", err)
	}
	if len(client.reports) != 1 {
		t.Errorf("reports sent = %d, want 1: the failed call only", len(client.reports))
	}
}
