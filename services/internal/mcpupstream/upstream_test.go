package mcpupstream

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// --- helpers -------------------------------------------------------------

// runServe runs Serve over a fixed list of frames and returns the reply lines
// and the record file's path. Every test that does not need the server to still
// be running while it looks at something uses this.
func runServe(t *testing.T, frames ...string) (replies []string, recordPath string) {
	t.Helper()
	recordPath = filepath.Join(t.TempDir(), "records.jsonl")
	var out strings.Builder
	in := strings.NewReader(strings.Join(frames, "\n") + "\n")
	if err := Serve(in, &out, recordPath); err != nil {
		t.Fatalf("Serve() = %v, want nil", err)
	}
	if out.Len() == 0 {
		return nil, recordPath
	}
	return strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n"), recordPath
}

// decodeResult decodes one reply's result field into v, failing the test if the
// reply carried an error instead.
func decodeResult(t *testing.T, reply string, v any) {
	t.Helper()
	var resp struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   *rpcError       `json:"error"`
	}
	if err := json.Unmarshal([]byte(reply), &resp); err != nil {
		t.Fatalf("decode reply %q: %v", reply, err)
	}
	if resp.Error != nil {
		t.Fatalf("reply carried error %+v, want a result", resp.Error)
	}
	if resp.JSONRPC != "2.0" {
		t.Errorf("reply jsonrpc = %q, want \"2.0\"", resp.JSONRPC)
	}
	if err := json.Unmarshal(resp.Result, v); err != nil {
		t.Fatalf("decode result %q: %v", resp.Result, err)
	}
}

func mustReadRecords(t *testing.T, path string) []Record {
	t.Helper()
	records, err := ReadRecords(path)
	if err != nil {
		t.Fatalf("ReadRecords(%q) = %v", path, err)
	}
	return records
}

// --- the protocol subset -------------------------------------------------

func TestServe_Initialize_AnswersWithProtocolVersionAndServerInfo(t *testing.T) {
	replies, recordPath := runServe(t, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}`)

	if len(replies) != 1 {
		t.Fatalf("got %d replies, want 1: %v", len(replies), replies)
	}
	var result struct {
		ProtocolVersion string `json:"protocolVersion"`
		ServerInfo      struct {
			Name string `json:"name"`
		} `json:"serverInfo"`
		Capabilities map[string]json.RawMessage `json:"capabilities"`
	}
	decodeResult(t, replies[0], &result)

	// The server's OWN version, not the client's -- an upstream that echoed
	// whatever was asked for would agree with a client asking for a revision
	// nobody implements.
	if result.ProtocolVersion != protocolVersion {
		t.Errorf("protocolVersion = %q, want %q", result.ProtocolVersion, protocolVersion)
	}
	if result.ServerInfo.Name != serverName {
		t.Errorf("serverInfo.name = %q, want %q", result.ServerInfo.Name, serverName)
	}
	if _, ok := result.Capabilities["tools"]; !ok {
		t.Errorf("capabilities = %v, want a tools capability", result.Capabilities)
	}
	if got := mustReadRecords(t, recordPath); len(got) != 1 || got[0].Method != "initialize" {
		t.Errorf("records = %+v, want exactly one initialize", got)
	}
}

func TestServe_ToolsList_AdvertisesFetchAndPurge(t *testing.T) {
	replies, _ := runServe(t, `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)

	if len(replies) != 1 {
		t.Fatalf("got %d replies, want 1: %v", len(replies), replies)
	}
	var result struct {
		Tools []struct {
			Name        string          `json:"name"`
			Description string          `json:"description"`
			InputSchema json.RawMessage `json:"inputSchema"`
		} `json:"tools"`
	}
	decodeResult(t, replies[0], &result)

	// Two tools, not one: the live proof needs one tool it can seed as
	// permitted and one it can seed as denied, so that tools/list can be shown
	// to relay UNFILTERED.
	if len(result.Tools) != 2 {
		t.Fatalf("got %d tools, want 2: %+v", len(result.Tools), result.Tools)
	}
	if result.Tools[0].Name != ToolFetch || result.Tools[1].Name != ToolPurge {
		t.Errorf("tool names = %q, %q; want %q, %q", result.Tools[0].Name, result.Tools[1].Name, ToolFetch, ToolPurge)
	}
	for _, tool := range result.Tools {
		if tool.Description == "" || len(tool.InputSchema) == 0 {
			t.Errorf("tool %q = %+v, want a description and an inputSchema", tool.Name, tool)
		}
	}
}

// The listing has to serialize identically every time, because the live proof
// compares a relayed listing against a directly-obtained one and concludes
// something about the RELAY. If this response were assembled from anything with
// nondeterministic ordering, that comparison would fail for a reason having
// nothing to do with the proxy.
func TestServe_ToolsList_IsByteForByteDeterministic(t *testing.T) {
	const frame = `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`
	first, _ := runServe(t, frame)
	second, _ := runServe(t, frame)

	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("got %d and %d replies, want 1 each", len(first), len(second))
	}
	if first[0] != second[0] {
		t.Errorf("two identical tools/list requests produced different bytes:\n %s\n %s", first[0], second[0])
	}
}

func TestServe_ToolsCall_ReturnsResultAndAppendsExactlyOneRecord(t *testing.T) {
	replies, recordPath := runServe(t, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"`+ToolFetch+`","arguments":{"message":"payload-marker-never-recorded"}}}`)

	if len(replies) != 1 {
		t.Fatalf("got %d replies, want 1: %v", len(replies), replies)
	}
	var result struct {
		Content []contentBlock `json:"content"`
		IsError bool           `json:"isError"`
	}
	decodeResult(t, replies[0], &result)
	if result.IsError {
		t.Errorf("isError = true, want false for the advertised tool %q", ToolFetch)
	}
	if len(result.Content) != 1 || !strings.Contains(result.Content[0].Text, ToolFetch) {
		t.Errorf("content = %+v, want one text block naming %q", result.Content, ToolFetch)
	}

	records := mustReadRecords(t, recordPath)
	if len(records) != 1 {
		t.Fatalf("got %d records, want exactly 1: %+v", len(records), records)
	}
	if records[0].Method != "tools/call" || records[0].Tool != ToolFetch {
		t.Errorf("record = %+v, want method tools/call and tool %q", records[0], ToolFetch)
	}
	if records[0].PID != os.Getpid() {
		t.Errorf("record pid = %d, want this process's %d", records[0].PID, os.Getpid())
	}
	// The arguments are deliberately not recorded: nothing needs them, and a
	// fixture that wrote request payloads to a file would be the one place in
	// this repository that logs frame contents.
	if strings.Contains(string(mustReadFile(t, recordPath)), "payload-marker") {
		t.Errorf("record file contains the call's arguments: %s", mustReadFile(t, recordPath))
	}
}

func TestServe_ToolsCall_UnadvertisedTool_IsError(t *testing.T) {
	replies, recordPath := runServe(t, `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"not-a-tool"}}`)

	var result struct {
		IsError bool `json:"isError"`
	}
	decodeResult(t, replies[0], &result)
	if !result.IsError {
		t.Errorf("isError = false for a tool this server does not advertise, want true")
	}
	// Still recorded: what ARRIVED is the question the record file answers, and
	// a call for an unknown tool arrived just as much as any other.
	if records := mustReadRecords(t, recordPath); len(records) != 1 || records[0].Tool != "not-a-tool" {
		t.Errorf("records = %+v, want one record naming the requested tool", records)
	}
}

func TestServe_UnknownMethod_AnswersMethodNotFound(t *testing.T) {
	replies, recordPath := runServe(t, `{"jsonrpc":"2.0","id":6,"method":"resources/list"}`)

	if len(replies) != 1 {
		t.Fatalf("got %d replies, want 1: %v", len(replies), replies)
	}
	var resp struct {
		Error *rpcError `json:"error"`
	}
	if err := json.Unmarshal([]byte(replies[0]), &resp); err != nil {
		t.Fatalf("decode reply: %v", err)
	}
	if resp.Error == nil || resp.Error.Code != mcpErrorCodeMethodNotFound {
		t.Errorf("reply = %s, want a %d error -- silence would leave a client waiting forever", replies[0], mcpErrorCodeMethodNotFound)
	}
	if records := mustReadRecords(t, recordPath); len(records) != 1 {
		t.Errorf("got %d records, want 1 -- an unsupported method still arrived", len(records))
	}
}

// A notification carries no id, so there is nothing to correlate a reply to and
// a conformant server sends none. It is still a call that ARRIVED, so it is
// still recorded -- the two halves are independent, which is why this asserts
// both.
func TestServe_Notification_RecordedButNotAnswered(t *testing.T) {
	replies, recordPath := runServe(t, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)

	if len(replies) != 0 {
		t.Errorf("got %d replies to a notification, want 0: %v", len(replies), replies)
	}
	records := mustReadRecords(t, recordPath)
	if len(records) != 1 || records[0].Method != "notifications/initialized" {
		t.Fatalf("records = %+v, want exactly one notifications/initialized", records)
	}
	if len(records[0].ID) != 0 {
		t.Errorf("record id = %s, want absent for a notification", records[0].ID)
	}
}

// The id is echoed as the bytes that arrived, never re-encoded from a parsed
// value. This input is the one that separates those two implementations: it
// exceeds float64's integer precision, so an id that went through interface{}
// would come back as 12345678901234567000 -- in the reply AND in the record,
// which is why both are checked here.
func TestServe_LargeIntegerID_EchoedVerbatimInReplyAndRecord(t *testing.T) {
	const id = "12345678901234567890"
	replies, recordPath := runServe(t, `{"jsonrpc":"2.0","id":`+id+`,"method":"tools/list"}`)

	if len(replies) != 1 {
		t.Fatalf("got %d replies, want 1", len(replies))
	}
	if !strings.Contains(replies[0], `"id":`+id) {
		t.Errorf("reply = %s, want it to carry id %s verbatim", replies[0], id)
	}
	records := mustReadRecords(t, recordPath)
	if len(records) != 1 || string(records[0].ID) != id {
		t.Errorf("record id = %s, want %s verbatim", records[0].ID, id)
	}
}

// --- surviving bad input -------------------------------------------------

// A fixture that dies on a bad line turns every proof downstream of it into a
// timeout with no cause. The malformed frames go FIRST so that the surviving
// reply is proof the server kept reading past them, and the record count is
// proof it did not record non-calls.
func TestServe_MalformedFrames_SurvivedAndNotRecorded(t *testing.T) {
	replies, recordPath := runServe(t,
		`{"jsonrpc":"2.0","id":1,`,             // truncated JSON
		`not json at all`,                      // not JSON
		``,                                     // empty line
		`[1,2,3]`,                              // valid JSON, not an object
		`{"jsonrpc":"2.0","id":9,"result":{}}`, // an object, but not a call: no method
		`{"jsonrpc":"2.0","id":10,"method":"tools/list"}`,
	)

	if len(replies) != 1 {
		t.Fatalf("got %d replies, want exactly 1 (only the last frame is a call): %v", len(replies), replies)
	}
	if !strings.Contains(replies[0], `"id":10`) {
		t.Errorf("reply = %s, want the answer to the one well-formed request", replies[0])
	}
	if records := mustReadRecords(t, recordPath); len(records) != 1 || records[0].Method != "tools/list" {
		t.Errorf("records = %+v, want exactly one tools/list -- a non-call must not inflate the record", records)
	}
}

// Positional params are legal JSON-RPC and MCP never sends them, but the
// failure direction matters: a call whose tool name cannot be read must still
// be RECORDED as having arrived. Silently-not-recorded is the one direction a
// fixture serving absence assertions may never fail in.
func TestServe_ToolsCallWithPositionalParams_StillRecorded(t *testing.T) {
	replies, recordPath := runServe(t, `{"jsonrpc":"2.0","id":11,"method":"tools/call","params":["fetch"]}`)

	if len(replies) != 1 {
		t.Fatalf("got %d replies, want 1: %v", len(replies), replies)
	}
	records := mustReadRecords(t, recordPath)
	if len(records) != 1 || records[0].Method != "tools/call" {
		t.Fatalf("records = %+v, want exactly one tools/call", records)
	}
	if records[0].Tool != "" {
		t.Errorf("record tool = %q, want empty -- no by-name tool was supplied", records[0].Tool)
	}
}

// --- the record file -----------------------------------------------------

// The proof reads this file WHILE the session is live, so this checks the
// records of a call are there before the server has stopped -- not merely that
// they turn up once it has.
func TestReadRecords_ReadableWhileTheServerIsStillRunning(t *testing.T) {
	recordPath := filepath.Join(t.TempDir(), "records.jsonl")
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- Serve(inR, outW, recordPath) }()

	replies := bufio.NewReader(outR)
	for i, frame := range []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"` + ToolPurge + `"}}`,
	} {
		if _, err := io.WriteString(inW, frame+"\n"); err != nil {
			t.Fatalf("write frame %d: %v", i, err)
		}
		if _, err := replies.ReadString('\n'); err != nil { // the reply proves the frame was handled
			t.Fatalf("read reply %d: %v", i, err)
		}
		// Read the file with the server still holding it open and still running.
		records := mustReadRecords(t, recordPath)
		if len(records) != i+1 {
			t.Fatalf("after %d handled frames the record file holds %d records: %+v", i+1, len(records), records)
		}
	}

	_ = inW.Close()
	if err := <-done; err != nil {
		t.Fatalf("Serve() = %v, want nil after the input closed", err)
	}
	_ = outR.Close()
}

// A record caught mid-write can only appear as a line with no terminating
// newline, and ReadRecords must not decode one. This asserts the property
// directly rather than trying to schedule a torn write: an interleaving that
// cannot be forced reliably cannot be asserted on reliably either.
func TestReadRecords_UnterminatedTailIsSkippedThenAppears(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.jsonl")
	const complete = `{"method":"initialize","pid":1}` + "\n"
	const partial = `{"method":"tools/ca`
	if err := os.WriteFile(path, []byte(complete+partial), 0o600); err != nil {
		t.Fatalf("write record file: %v", err)
	}

	records := mustReadRecords(t, path)
	if len(records) != 1 || records[0].Method != "initialize" {
		t.Fatalf("records = %+v, want only the complete one", records)
	}

	// The same bytes, once the write finishes: the skipped record is not lost,
	// only deferred to the next read.
	if err := os.WriteFile(path, []byte(complete+partial+`ll","pid":1}`+"\n"), 0o600); err != nil {
		t.Fatalf("rewrite record file: %v", err)
	}
	if records := mustReadRecords(t, path); len(records) != 2 || records[1].Method != "tools/call" {
		t.Errorf("records = %+v, want both once the second line is terminated", records)
	}
}

// The record file is opened for APPEND, not truncated: a proof that ran a
// second session against the same path would otherwise find the first
// session's calls gone, and "the denied call left no record" is a claim that
// cannot survive records disappearing behind it.
func TestServe_SecondSessionAppendsRatherThanTruncating(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.jsonl")
	for _, id := range []string{"1", "2"} {
		var out strings.Builder
		if err := Serve(strings.NewReader(`{"jsonrpc":"2.0","id":`+id+`,"method":"tools/list"}`+"\n"), &out, path); err != nil {
			t.Fatalf("Serve() = %v, want nil", err)
		}
	}
	records := mustReadRecords(t, path)
	if len(records) != 2 {
		t.Fatalf("got %d records after two sessions, want 2: %+v", len(records), records)
	}
	if string(records[0].ID) != "1" || string(records[1].ID) != "2" {
		t.Errorf("record ids = %s, %s; want 1, 2 in arrival order", records[0].ID, records[1].ID)
	}
}

// Zero records because the upstream never ran is exactly the condition under
// which an absence assertion passes for the wrong reason, so a missing file is
// an error rather than an empty slice.
func TestReadRecords_MissingFile_IsAnErrorNotZeroRecords(t *testing.T) {
	records, err := ReadRecords(filepath.Join(t.TempDir(), "never-created.jsonl"))
	if err == nil {
		t.Fatalf("ReadRecords() = %+v, nil; want an error for a file that does not exist", records)
	}
	if records != nil {
		t.Errorf("records = %+v, want nil alongside the error", records)
	}
}

func TestReadRecords_UndecodableLine_IsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "records.jsonl")
	if err := os.WriteFile(path, []byte("{\"method\":\"initialize\",\"pid\":1}\nnot a record\n"), 0o600); err != nil {
		t.Fatalf("write record file: %v", err)
	}
	if records, err := ReadRecords(path); err == nil {
		t.Fatalf("ReadRecords() = %+v, nil; want an error -- a corrupt record file must not read as a short one", records)
	}
}

// --- a recording failure is fatal, never swallowed -----------------------

// If the record file cannot be opened, the server must not answer a single
// frame: a server that kept serving while recording nothing would make "the
// denied call left no record" pass because NOTHING left a record.
func TestServe_UnwritableRecordPath_FailsWithoutAnsweringAnything(t *testing.T) {
	unwritable := filepath.Join(t.TempDir(), "no-such-dir", "records.jsonl")
	var out strings.Builder

	err := Serve(strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`+"\n"), &out, unwritable)
	if err == nil {
		t.Fatal("Serve() = nil, want an error when the record file cannot be opened")
	}
	if out.Len() != 0 {
		t.Errorf("Serve() answered %q with no record file open, want nothing", out.String())
	}
}

// A record that cannot be written once the server is already running must stop
// it, and must stop it BEFORE the frame is answered: a server that kept
// answering while recording nothing would make "the denied call left no record"
// pass because nothing left a record at all. serveRecording is what makes this
// reachable -- there is no portable way to make a real open file start failing.
func TestServeRecording_RecordWriteFailure_StopsWithoutAnsweringTheFrame(t *testing.T) {
	sentinel := errors.New("disk gone")
	var out strings.Builder
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n")

	err := serveRecording(in, &out, errWriter{err: sentinel})
	if !errors.Is(err, sentinel) {
		t.Fatalf("serveRecording() = %v, want it to wrap %v", err, sentinel)
	}
	if out.Len() != 0 {
		t.Errorf("serveRecording() answered %q despite failing to record it, want nothing", out.String())
	}
}

type errWriter struct{ err error }

func (w errWriter) Write([]byte) (int, error) { return 0, w.err }

func TestAppendRecord_WriteFailure_IsReturned(t *testing.T) {
	sentinel := errors.New("disk gone")
	err := appendRecord(errWriter{err: sentinel}, Record{Method: "tools/call", Tool: ToolFetch, PID: 1})
	if !errors.Is(err, sentinel) {
		t.Fatalf("appendRecord() = %v, want it to wrap %v", err, sentinel)
	}
}

// --- the binary, as the live proof will actually build and run it --------

// This is the one test that exercises cmd/mcp-upstream itself, and it exercises
// the exact mechanism Task 2 depends on: build into a temp directory with `go
// build -o`, spawn, feed frames on stdin, read the record file the process was
// given as its single argument. It is also the only place the PID field can be
// checked against a REAL child process id, which is what a proof that the proxy
// launches and reaps its child needs it for.
func TestMCPUpstreamBinary_BuiltAndRun_RecordsAgainstItsOwnPID(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "mcp-upstream")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/mcp-upstream")
	build.Dir = servicesModuleRoot(t)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build ./cmd/mcp-upstream: %v: %s", err, out)
	}

	recordPath := filepath.Join(t.TempDir(), "records.jsonl")
	runCtx, runCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer runCancel()
	cmd := exec.CommandContext(runCtx, binary, recordPath)
	cmd.Stdin = strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize"}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"` + ToolPurge + `"}}` + "\n")
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", binary, err)
	}
	pid := cmd.Process.Pid
	if err := cmd.Wait(); err != nil {
		t.Fatalf("%s: %v (stderr: %s)", binary, err, stderr.String())
	}

	if got := strings.Count(strings.TrimSuffix(stdout.String(), "\n"), "\n") + 1; got != 2 {
		t.Errorf("got %d reply lines, want 2: %q", got, stdout.String())
	}
	records := mustReadRecords(t, recordPath)
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2: %+v", len(records), records)
	}
	for _, rec := range records {
		if rec.PID != pid {
			t.Errorf("record %+v carries pid %d, want the child's own %d", rec, rec.PID, pid)
		}
	}
	if records[1].Tool != ToolPurge {
		t.Errorf("second record = %+v, want tool %q", records[1], ToolPurge)
	}
}

// A record path is refused rather than defaulted: a default would send a run's
// records somewhere the test does not read, making every absence assertion pass
// for the wrong reason.
func TestMCPUpstreamBinary_NoRecordPath_ExitsNonZero(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "mcp-upstream")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, "./cmd/mcp-upstream")
	build.Dir = servicesModuleRoot(t)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build ./cmd/mcp-upstream: %v: %s", err, out)
	}

	runCtx, runCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer runCancel()
	cmd := exec.CommandContext(runCtx, binary)
	cmd.Stdin = strings.NewReader("")
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("running the binary with no argument = %v, want a non-zero exit", err)
	}
}

// servicesModuleRoot resolves the module root from this file's own path, the
// same way cache_e2e_integration_test.go's identically named helper does -- a
// test's working directory is its own package directory, which is two levels
// below the module root here.
func servicesModuleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller could not resolve this file's own path")
	}
	return filepath.Join(filepath.Dir(file), "..", "..")
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %q: %v", path, err)
	}
	return data
}
