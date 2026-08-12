package main

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"stratium/internal/pdpgrpc"
)

// fakePDP is a real PDPServiceServer, not a mocked client interface: tests
// in hook_test.go and session_start_test.go dial it over an actual TCP
// loopback connection through the generated gRPC client, the same code path
// runHookCmd/runSessionStartCmd use in production. That matters specifically
// for the declared_tier assertion in hook_test.go — a mock could only prove
// a Go struct field was left nil, where a real round trip proves the wire
// message never carried it.
//
// Decide, CreateDelegation, and GetApproval each get their own
// response/error/call-count fields below rather than sharing one, because a
// single test scenario can need one RPC left at its zero-value
// UnimplementedPDPServiceServer behavior while another is stubbed -- e.g.
// every escalation test in hook_test.go stubs Decide and GetApproval
// together but never touches CreateDelegation at all.
type fakePDP struct {
	pdpgrpc.UnimplementedPDPServiceServer

	resp *pdpgrpc.DecideResponse
	err  error
	// decideDelay, when positive, makes Decide block this long (or until ctx
	// is done, whichever comes first) before responding -- how a test
	// simulates a PDP that does not answer inside the client's
	// ConnectTimeout. The client gives up and returns codes.DeadlineExceeded
	// on its own once ctx expires regardless of what this handler does;
	// honoring ctx.Done() here just keeps the fake server's own goroutine
	// from outliving a test that already moved on.
	decideDelay time.Duration

	createResp *pdpgrpc.CreateDelegationResponse
	createErr  error

	// getApprovalResponses is consumed in call order, one entry per
	// GetApproval call; a call past the end of the slice repeats the last
	// entry rather than panicking, so a test can script "pending, pending,
	// approved" with exactly three entries without having to predict exactly
	// how many polls a given PollInterval/ApprovalTimeout pair produces.
	// getApprovalErr, when set, is returned on every call instead and takes
	// priority over the slice -- it scripts "unreachable"/"unknown id",
	// neither of which needs per-call sequencing.
	getApprovalResponses []*pdpgrpc.GetApprovalResponse
	getApprovalErr       error

	mu                 sync.Mutex
	lastReq            *pdpgrpc.DecideRequest
	calls              int
	lastCreateReq      *pdpgrpc.CreateDelegationRequest
	createCalls        int
	lastGetApprovalReq *pdpgrpc.GetApprovalRequest
	getApprovalCalls   int
}

func (f *fakePDP) Decide(ctx context.Context, req *pdpgrpc.DecideRequest) (*pdpgrpc.DecideResponse, error) {
	f.mu.Lock()
	f.calls++
	f.lastReq = req
	delay, err, resp := f.decideDelay, f.err, f.resp
	f.mu.Unlock()

	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if err != nil {
		return nil, err
	}
	return resp, nil
}

func (f *fakePDP) requestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakePDP) lastRequest() *pdpgrpc.DecideRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastReq
}

func (f *fakePDP) CreateDelegation(_ context.Context, req *pdpgrpc.CreateDelegationRequest) (*pdpgrpc.CreateDelegationResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.createCalls++
	f.lastCreateReq = req
	if f.createErr != nil {
		return nil, f.createErr
	}
	return f.createResp, nil
}

func (f *fakePDP) createRequestCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.createCalls
}

func (f *fakePDP) lastCreateRequest() *pdpgrpc.CreateDelegationRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastCreateReq
}

func (f *fakePDP) GetApproval(_ context.Context, req *pdpgrpc.GetApprovalRequest) (*pdpgrpc.GetApprovalResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastGetApprovalReq = req
	f.getApprovalCalls++
	if f.getApprovalErr != nil {
		return nil, f.getApprovalErr
	}
	if len(f.getApprovalResponses) == 0 {
		return nil, errors.New("fakePDP: GetApproval called with no scripted response")
	}
	idx := f.getApprovalCalls - 1
	if idx >= len(f.getApprovalResponses) {
		idx = len(f.getApprovalResponses) - 1
	}
	return f.getApprovalResponses[idx], nil
}

func (f *fakePDP) getApprovalCallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.getApprovalCalls
}

func (f *fakePDP) lastGetApprovalRequest() *pdpgrpc.GetApprovalRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastGetApprovalReq
}

// startFakePDP serves srv on an OS-assigned loopback port and returns a real
// gRPC client dialed to it. Server and client are both stopped via
// t.Cleanup.
func startFakePDP(t *testing.T, srv *fakePDP) pdpgrpc.PDPServiceClient {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	gs := grpc.NewServer()
	pdpgrpc.RegisterPDPServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	return dialTestClient(t, lis.Addr().String())
}

// unreachablePDPClient returns a client dialed to an address nothing is
// listening on: a listener is opened to reserve a real port, then closed
// immediately, so the dial target is a syntactically valid, guaranteed-idle
// loopback address rather than a guess at an unused port number.
func unreachablePDPClient(t *testing.T) pdpgrpc.PDPServiceClient {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := lis.Addr().String()
	if err := lis.Close(); err != nil {
		t.Fatalf("close reserved listener: %v", err)
	}

	return dialTestClient(t, addr)
}

func dialTestClient(t *testing.T, addr string) pdpgrpc.PDPServiceClient {
	t.Helper()

	conn, err := grpc.NewClient(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("create gRPC client: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return pdpgrpc.NewPDPServiceClient(conn)
}
