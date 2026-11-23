// extmcp.go implements the "extmcp" subcommand: a gRPC server answering
// agentgateway's ExtMcp contract (proto/agentgateway/ext_mcp.proto), which
// agentgateway calls for each MCP method a route's mcpGuardrails policy
// names, before it forwards the call to the MCP server behind it.
//
// It is the "mcp" subcommand's decision on a different transport. "mcp"
// stands in front of one MCP server on stdio; this stands beside a gateway
// that already fronts many. Both enforce mcpAuthorizer.authorize
// (mcp_authorize.go), so the session file, the cache, the token reissue and
// the wait on an approval are the same code, not a second copy.
//
// ONE IDENTITY. Like "mcp", this reads the delegation "session-start" wrote
// and decides every call as that agent and subject. McpRequest carries the
// caller's HTTP headers, and nothing here reads them: a token taken from a
// caller would need the proof-of-possession check extauthz.go makes, and
// ExtMcp does not report the URL that check needs.
//
// A REFUSAL IS AN ANSWER, NEVER AN RPC ERROR. agentgateway's failureMode
// decides what a failed ExtMcp call means, and failOpen forwards it. Every
// refusal here -- a policy deny, an unreachable PDP, a call that cannot be
// read -- is returned as an AuthorizationError inside a successful reply,
// which no failureMode can turn into an allow. extauthz.go's Check holds the
// same line for the same reason.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"

	"google.golang.org/grpc"

	"github.com/stratiumdata/stratium/internal/extmcp"
	"github.com/stratiumdata/stratium/internal/pdpgrpc"
)

func runExtmcpCmd(stderr io.Writer) int {
	var missing []string
	listenAddr := requiredEnv("STRATIUM_PEP_EXTMCP_LISTEN_ADDR", &missing)
	var listenErr error
	if len(missing) > 0 {
		listenErr = missingConfigError(missing)
	}
	hookCfg, hookErr := loadHookConfigFromEnv()
	cacheCfg, cacheErr := loadCacheConfigFromEnv()
	if err := combineConfigErrors(listenErr, hookErr, cacheErr); err != nil {
		_, _ = fmt.Fprintf(stderr, "stratium-pep: %s\n", err)
		return 1
	}

	conn, err := dialPDP(hookCfg.PDPAddr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "stratium-pep: could not create PDP client: %s\n", err)
		return 1
	}
	defer func() { _ = conn.Close() }()

	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "stratium-pep: could not listen on %s: %s\n", listenAddr, err)
		return 1
	}

	grpcServer := grpc.NewServer()
	extmcp.RegisterExtMcpServer(grpcServer, &extmcpServer{authz: &mcpAuthorizer{
		client:   pdpgrpc.NewPDPServiceClient(conn),
		cfg:      hookCfg,
		cacheCfg: cacheCfg,
		cache:    newDecisionCache(),
	}})

	_, _ = fmt.Fprintf(stderr, "stratium-pep: extmcp listening on %s (PDP %s, agent %s, subject %s)\n",
		listenAddr, hookCfg.PDPAddr, hookCfg.AgentID, hookCfg.Subject)

	if err := grpcServer.Serve(lis); err != nil {
		_, _ = fmt.Fprintf(stderr, "stratium-pep: extmcp server: %s\n", err)
		return 1
	}
	return 0
}

type extmcpServer struct {
	extmcp.UnimplementedExtMcpServer

	authz *mcpAuthorizer
}

// CheckRequest decides tools/call and passes every other method, the same
// split "mcp" makes (see mcp.go's package doc for why tools/list is not
// filtered).
//
// The tool the PDP is asked about is "<target>_<name>": the gateway's name
// for the MCP server, then the server's own name for the tool. Two servers
// behind one gateway can both offer a tool called "delete", and a policy
// has to be able to tell them apart. It is also the name agentgateway shows
// a client when a route has more than one target.
func (s *extmcpServer) CheckRequest(ctx context.Context, req *extmcp.McpRequest) (*extmcp.McpRequestResult, error) {
	if req.GetMethod() != "tools/call" {
		return &extmcp.McpRequestResult{Result: &extmcp.McpRequestResult_Pass{Pass: &extmcp.Pass{}}}, nil
	}

	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	targets := req.GetServiceNames()
	if err := json.Unmarshal(req.GetMcpRequest(), &params); err != nil || params.Name == "" || len(targets) != 1 || targets[0] == "" {
		return extmcpDeny("stratium-pep: malformed tools/call: one target and params.name are required"), nil //nolint:nilerr // a refusal is an answer, never an RPC error: see the package doc
	}

	if ok, reason := s.authz.authorize(ctx, targets[0]+"_"+params.Name, string(params.Arguments)); !ok {
		return extmcpDeny(reason), nil
	}
	return &extmcp.McpRequestResult{Result: &extmcp.McpRequestResult_Pass{Pass: &extmcp.Pass{}}}, nil
}

// CheckResponse passes everything. Nothing is decided after a tool has run;
// answering here keeps a policy that lists a response phase from failing
// closed on an unimplemented method.
func (s *extmcpServer) CheckResponse(context.Context, *extmcp.McpResponse) (*extmcp.McpResponseResult, error) {
	return &extmcp.McpResponseResult{Result: &extmcp.McpResponseResult_Pass{Pass: &extmcp.Pass{}}}, nil
}

func extmcpDeny(reason string) *extmcp.McpRequestResult {
	return &extmcp.McpRequestResult{Result: &extmcp.McpRequestResult_Error{Error: &extmcp.AuthorizationError{
		Code:   extmcp.AuthorizationError_PERMISSION_DENIED,
		Reason: reason,
	}}}
}
