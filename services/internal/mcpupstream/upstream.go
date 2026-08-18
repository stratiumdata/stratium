// Package mcpupstream is the purpose-built MCP server the `mcp` enforcement surface's live proof
// relays to: it exists to be relayed to, and to report what reached it. Same spirit as
// deploy/docker/echo-upstream (the trivial HTTP upstream behind a real Envoy) and cmd/grpc-target
// (the real gRPC service behind `stratium-pep proxy`). cmd/mcp-upstream is the ten-line binary
// that wraps it; everything is here so the protocol can be exercised in-process rather than only
// through a spawned child.
//
// WHY THIS IS A PACKAGE INSIDE THE MODULE, NOT A LOOSE main.go OUTSIDE IT. The two precedents
// answer that question in opposite directions and both are right for their own case.
// echo-upstream sits outside deliberately: its entire agreement with the test that reads it is a
// three-field JSON object, mirrored by hand on the test side (extauthz_integration_test.go's
// echoUpstreamResponse "mirrors deploy/docker/echo-upstream/main.go's own echoResponse exactly").
// grpc-target sits inside because it imports the generated types the integration test also
// imports, and both sides need the identical shape. This one is the second case, and for a sharper
// reason than convenience: the proof it serves is an ABSENCE assertion -- a denied tools/call must
// be shown never to have ARRIVED, not merely to have errored at the caller -- and an absence
// assertion read through a hand-mirrored record format fails OPEN. Rename a field on one side and
// the reader decodes zero values, finds no record naming the denied tool, and passes for the wrong
// reason, silently, forever after. Record and ReadRecords below are therefore the single
// definition both this server and the test compile against, and ToolFetch/ToolPurge are exported
// for the identical reason: a test that types "fetch" as a string literal is one typo away from
// asserting the absence of a tool that was never advertised in the first place.
//
// The second, independent argument for inside: the binary is built BY THE TEST (the mcp surface is
// stdio, so its upstream is spawned by the test process, not by compose), with the same `go build
// -o <tempdir> ./cmd/...` that already builds stratium-pep in cache_e2e_integration_test.go. That
// build needs a module. echo-upstream gets away with having none only because Docker builds it
// with `go build main.go`, a mode that works solely because it imports nothing outside the
// standard library.
//
// THE RECORD IS OUT OF BAND, AND THAT IS THE WHOLE POINT. Every call this server receives is
// appended to a file the test reads directly. It is deliberately NOT retrievable through a tool
// call: a tools/call is exactly what the proxy gates, so an observation fetched that way would
// share a dependency with the thing being observed -- a denied call could suppress the very record
// proving it was denied. That defect class has been found nine times in this project in one phase.
//
// A RECORDING FAILURE IS FATAL, NEVER SWALLOWED. Serve stops on the first record it cannot write,
// and refuses to start at all if the record file cannot be opened. An absence assertion is only
// as good as the presence of everything else in the file: a server that kept answering frames
// while failing to record them would make "the denied call left no record" pass because NOTHING
// left a record. For the same reason nothing here buffers the record file -- a SIGKILLed upstream
// (the mid-session-death proof) must leave behind every record it already acknowledged.
//
// WHAT IT DELIBERATELY DOES NOT DO. It handles frames one at a time, in order: MCP permits
// pipelining and the proxy is genuinely concurrent, but that property is the PROXY's and is proven
// against it directly (mcp_test.go's TestRunMCP_PipelinedRequests_NotSerializedBehindEachOther),
// not something an upstream fixture needs to be able to fail. It negotiates nothing -- initialize
// answers with a fixed protocol version rather than echoing the client's. It implements no
// resources, prompts, logging, completion, or subscription methods, and answers any method it does
// not know with a JSON-RPC "method not found" rather than silence, so a client is never left
// waiting on a request that will never be answered. It records no tool ARGUMENTS: nothing needs
// them, and a fixture that wrote request payloads to a file would be the one place in this
// repository that logs frame contents.
package mcpupstream

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
)

// The identity this server reports from initialize. protocolVersion is a fixed MCP revision, not
// an echo of whatever the client asked for: real servers answer with a version THEY support, and
// a fixture that echoed the client's would agree with a client that asked for a version nobody
// implements.
const (
	protocolVersion = "2025-06-18"
	serverName      = "stratium-mcp-upstream"
	serverVersion   = "0.1.0"
)

// ToolFetch and ToolPurge are the two tools this server advertises, exported so a test names them
// from here rather than from a string literal of its own -- see the package doc on why a
// hand-copied name is an absence assertion that can pass for the wrong reason. Two, not one,
// because the tools/list proof needs one tool that would be permitted and one that would be
// denied if called; the names mirror grpc-target's own Fetch/Purge pair, which exists for exactly
// the same reason on the other proxy surface.
const (
	ToolFetch = "fetch"
	ToolPurge = "purge"
)

// maxFrameBytes matches cmd/stratium-pep/mcp.go's own limit exactly. This server only ever
// receives what that proxy already accepted and relayed, so a smaller limit here would reject
// frames the surface under test considers legitimate, and a larger one would be unreachable.
const maxFrameBytes = 32 * 1024 * 1024 // 32 MiB

// mcpErrorCodeMethodNotFound is JSON-RPC 2.0's own reserved code for an unimplemented method
// (-32601), not one of this project's application codes.
const mcpErrorCodeMethodNotFound = -32601

// Record is one call this server received, as it appears on one line of the record file. Both this
// server and the test that reads the file use this type; see the package doc on why that is not a
// convenience.
//
// PID is on every record rather than in a file of its own: it is how a proof identifies the child
// process the proxy launched -- the proxy chooses the pid, nothing else reports it, and a proof
// that the child exists during a session and is reaped afterwards needs it. Every record carries
// the same value; one file is cheaper than two.
//
// ID is the request id exactly as it arrived, unparsed. Kept as json.RawMessage for the same
// reason mcp.go never unmarshals an id into a Go type: a large integer id does not survive a
// float64 round trip, and this record is one half of the evidence that the id the caller sent is
// the id that reached the upstream.
type Record struct {
	Method string          `json:"method"`
	Tool   string          `json:"tool,omitempty"`
	ID     json.RawMessage `json:"id,omitempty"`
	PID    int             `json:"pid"`
}

// ReadRecords returns every complete record written to path so far. It is safe to call while the
// server is still running, which is the only way a proof can check what has arrived MID-session.
//
// Safe concurrently for two reasons that hold together, not one:
//
//   - Records are appended one whole line per os.File.Write, to a file opened O_APPEND, by a
//     single-threaded server -- there is never a second writer to interleave with, and
//     json.Marshal escapes any newline inside a string, so one record can never arrive as two
//     lines however hostile the tool name.
//   - A line without its terminating newline is skipped, not decoded. That is what makes a torn
//     read impossible to MISREAD rather than merely unlikely: a write caught mid-flight can only
//     ever appear as an unterminated tail, and this reader does not treat an unterminated tail as
//     a record at all. It reappears, complete, on the next call -- unless the writer DIED
//     mid-write, in which case that tail never completes and is dropped for good. That is the
//     right trade even in the one scenario that reaches it (a SIGKILLed upstream), because the
//     alternative is counting a half-written record as a whole one; and it is close to
//     unreachable in practice, since a ~60-byte record is one write to a regular file.
//
// A missing file is an error, not zero records: the server creates the file before it reads its
// first frame, so "not there" means the upstream never started -- which is exactly the condition
// under which an absence assertion would otherwise pass vacuously. A line that does not decode is
// an error for the same reason.
func ReadRecords(path string) ([]Record, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: the path is the test's own temp file, chosen by the caller, never request data
	if err != nil {
		return nil, fmt.Errorf("mcpupstream: read record file: %w", err)
	}
	var records []Record
	for rest := data; ; {
		i := bytes.IndexByte(rest, '\n')
		if i < 0 {
			return records, nil // an unterminated tail is a record still being written -- see above
		}
		line := rest[:i]
		rest = rest[i+1:]
		var rec Record
		if err := json.Unmarshal(line, &rec); err != nil {
			return nil, fmt.Errorf("mcpupstream: decode record %d: %w", len(records)+1, err)
		}
		records = append(records, rec)
	}
}

// appendRecord writes one record as one line with one Write call -- see ReadRecords on why one
// write per record, and not one per field or one per flush, is what makes the file safe to read
// while it is being written.
func appendRecord(w io.Writer, rec Record) error {
	line, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("mcpupstream: encode record: %w", err)
	}
	if _, err := w.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("mcpupstream: write record: %w", err)
	}
	return nil
}

// request is the subset of an incoming frame this server reads: the method, the id (echoed
// verbatim, never reconstructed), and params only far enough to find a tools/call's tool name.
// Params stays raw so that a frame carrying positional params -- which MCP never sends, but
// JSON-RPC permits -- is still RECORDED as the call it is, rather than being mistaken for a
// malformed frame and silently dropped. Silently-not-recorded is the one direction a fixture
// serving absence assertions must never fail in.
type request struct {
	Method string          `json:"method"`
	ID     json.RawMessage `json:"id"`
	Params json.RawMessage `json:"params"`
}

// response is a JSON-RPC reply this server authors. ID is json.RawMessage so the id echoes back as
// the bytes that arrived (RawMessage.MarshalJSON returns itself unchanged) -- the same technique,
// and the same reason, as mcp_authorize.go's jsonrpcErrorFrame.
type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type contentBlock struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// toolDescriptor is one entry of tools/list. The schema is a raw JSON constant rather than a map:
// this listing has to serialize to identical bytes every time so a proof can compare a relayed
// listing against a directly-obtained one and conclude something about the RELAY.
type toolDescriptor struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

var toolInputSchema = json.RawMessage(`{"type":"object","properties":{"message":{"type":"string"}}}`)

var advertisedTools = []toolDescriptor{
	{Name: ToolFetch, Description: "Fetch a message. Harmless; the tool a proof seeds as permitted.", InputSchema: toolInputSchema},
	{Name: ToolPurge, Description: "Purge a message. Destructive-sounding; the tool a proof seeds as denied.", InputSchema: toolInputSchema},
}

// Serve reads newline-delimited JSON-RPC frames from in, records every call, and writes replies to
// out, until in is exhausted or a record cannot be written. recordPath is created if absent and
// appended to otherwise.
//
// Nothing buffers out: a reply sitting in a bufio.Writer that never flushes is indistinguishable
// from a server that hung, and this one talks to a proxy that is waiting on exactly that line.
func Serve(in io.Reader, out io.Writer, recordPath string) error {
	f, err := os.OpenFile(recordPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // G304: the path is the operator's/test's own argument, never request data
	if err != nil {
		return fmt.Errorf("mcpupstream: open record file: %w", err)
	}
	defer func() { _ = f.Close() }()
	return serveRecording(in, out, f)
}

// serveRecording is Serve with the record file already open. It exists as its own function purely
// so the failure that must NOT be swallowed -- a record that cannot be written once the server is
// already running -- is reachable from a test. There is no portable way to make a real, already-open
// file start failing underneath a live process, and a "records are never swallowed" claim nothing
// can falsify is exactly the kind of claim this project keeps finding to be untrue.
func serveRecording(in io.Reader, out io.Writer, records io.Writer) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 0, 4096), maxFrameBytes)
	for scanner.Scan() {
		var req request
		if err := json.Unmarshal(scanner.Bytes(), &req); err != nil || req.Method == "" {
			// Not a call: a malformed line, or a frame with no method (a response, which a client
			// does not send). Dropped without a record and without a reply -- there is nothing to
			// reply TO, and recording a non-call would inflate the counts a proof asserts on. The
			// proxy already drops malformed frames before they reach here; this server must
			// survive one anyway, because a fixture that dies on a bad line turns every proof
			// downstream of it into a timeout with no cause.
			continue
		}
		tool := toolName(req)
		if err := appendRecord(records, Record{Method: req.Method, Tool: tool, ID: req.ID, PID: os.Getpid()}); err != nil {
			// Never swallowed, and the frame is not answered either: a server that kept serving
			// while failing to record would make "the denied call left no record" pass because
			// NOTHING left a record. See the package doc.
			return err
		}
		if len(req.ID) == 0 {
			continue // a notification (notifications/initialized, say): recorded, correctly unanswered
		}
		if err := writeFrame(out, reply(req.Method, req.ID, tool)); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("mcpupstream: read frame: %w", err)
	}
	return nil
}

// toolName extracts params.name for a tools/call and reports "" for everything else, including a
// tools/call whose params are not a by-name object. The extraction failing is not an error: the
// call still happened, still gets recorded, and reply below answers it with an isError result
// rather than pretending a tool ran.
func toolName(req request) string {
	if req.Method != "tools/call" {
		return ""
	}
	var params struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return ""
	}
	return params.Name
}

func reply(method string, id json.RawMessage, tool string) response {
	resp := response{JSONRPC: "2.0", ID: id}
	switch method {
	case "initialize":
		resp.Result = map[string]any{
			"protocolVersion": protocolVersion,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]any{"name": serverName, "version": serverVersion},
		}
	case "tools/list":
		resp.Result = map[string]any{"tools": advertisedTools}
	case "tools/call":
		resp.Result = callResult(tool)
	default:
		resp.Error = &rpcError{Code: mcpErrorCodeMethodNotFound, Message: fmt.Sprintf("%s: unsupported method %q", serverName, method)}
	}
	return resp
}

// callResult answers a tools/call. The result names the tool that ran, which is all a proof needs
// to tell the permitted tool's result from the denied one's -- there is deliberately no call
// counter (grpc-target has one only because it has no record file; here, counting is what the
// record file is for) and no echo of the arguments.
//
// An unadvertised tool gets isError rather than a success naming a tool this server does not have:
// a fixture that answered "ok" for anything asked of it could not distinguish a relay that worked
// from a relay that mangled the tool name.
func callResult(tool string) map[string]any {
	for _, t := range advertisedTools {
		if t.Name == tool {
			return map[string]any{
				"content": []contentBlock{{Type: "text", Text: serverName + ": " + tool}},
				"isError": false,
			}
		}
	}
	return map[string]any{
		"content": []contentBlock{{Type: "text", Text: serverName + ": no such tool " + tool}},
		"isError": true,
	}
}

// writeFrame emits one reply as one line with one Write call -- the same single-write discipline
// the record file uses, for the same reason: the proxy reads this stream line by line, and a
// reply split across writes is a reply a reader can observe half of.
func writeFrame(out io.Writer, resp response) error {
	line, err := json.Marshal(resp)
	if err != nil {
		return fmt.Errorf("mcpupstream: encode reply: %w", err)
	}
	if _, err := out.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("mcpupstream: write reply: %w", err)
	}
	return nil
}
