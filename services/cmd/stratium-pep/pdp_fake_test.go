package main

import (
	"context"
	"net"
	"sync"
	"testing"

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
// Decide and CreateDelegation each get their own response/error/call-count
// fields below rather than sharing one, because a single session_start_test
// scenario can need Decide left at its zero-value UnimplementedPDPServiceServer
// behavior while CreateDelegation is stubbed, and vice versa for hook_test.
type fakePDP struct {
	pdpgrpc.UnimplementedPDPServiceServer

	resp *pdpgrpc.DecideResponse
	err  error

	createResp *pdpgrpc.CreateDelegationResponse
	createErr  error

	mu            sync.Mutex
	lastReq       *pdpgrpc.DecideRequest
	calls         int
	lastCreateReq *pdpgrpc.CreateDelegationRequest
	createCalls   int
}

func (f *fakePDP) Decide(_ context.Context, req *pdpgrpc.DecideRequest) (*pdpgrpc.DecideResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.lastReq = req
	if f.err != nil {
		return nil, f.err
	}
	return f.resp, nil
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
