package main

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestLoadListenerLimitsFromEnv(t *testing.T) {
	t.Setenv("STRATIUM_PEP_MAX_CONCURRENT_STREAMS", "")
	t.Setenv("STRATIUM_PEP_MAX_CONNECTION_IDLE", "")
	t.Setenv("STRATIUM_PEP_MAX_CONNECTIONS", "")
	t.Setenv("STRATIUM_PEP_MAX_CONNECTIONS_PER_IP", "")
	got, err := loadListenerLimitsFromEnv()
	if err != nil {
		t.Fatalf("loadListenerLimitsFromEnv() error = %v", err)
	}
	if got.MaxConcurrentStreams != 256 || got.MaxConnectionIdle != 5*time.Minute {
		t.Errorf("defaults = %d streams, idle %s; want 256 and 5m", got.MaxConcurrentStreams, got.MaxConnectionIdle)
	}
	if got.MaxConnections != 10000 || got.MaxConnectionsPerIP != 1000 {
		t.Errorf("defaults = %d connections, %d per address; want 10000 and 1000", got.MaxConnections, got.MaxConnectionsPerIP)
	}

	t.Setenv("STRATIUM_PEP_MAX_CONNECTIONS", "400")
	t.Setenv("STRATIUM_PEP_MAX_CONNECTIONS_PER_IP", "8")
	if got, err = loadListenerLimitsFromEnv(); err != nil || got.MaxConnections != 400 || got.MaxConnectionsPerIP != 8 {
		t.Errorf("loadListenerLimitsFromEnv() = %+v, %v; want 400 connections, 8 per address", got, err)
	}
	t.Setenv("STRATIUM_PEP_MAX_CONNECTIONS", "")
	t.Setenv("STRATIUM_PEP_MAX_CONNECTIONS_PER_IP", "")

	t.Setenv("STRATIUM_PEP_MAX_CONCURRENT_STREAMS", "32")
	t.Setenv("STRATIUM_PEP_MAX_CONNECTION_IDLE", "90s")
	if got, err = loadListenerLimitsFromEnv(); err != nil || got.MaxConcurrentStreams != 32 || got.MaxConnectionIdle != 90*time.Second {
		t.Errorf("loadListenerLimitsFromEnv() = %+v, %v; want 32 streams, idle 90s", got, err)
	}

	for _, bad := range [][2]string{
		{"STRATIUM_PEP_MAX_CONCURRENT_STREAMS", "0"}, {"STRATIUM_PEP_MAX_CONCURRENT_STREAMS", "-1"},
		{"STRATIUM_PEP_MAX_CONCURRENT_STREAMS", "lots"}, {"STRATIUM_PEP_MAX_CONCURRENT_STREAMS", "5000000000"},
		{"STRATIUM_PEP_MAX_CONNECTION_IDLE", "0s"}, {"STRATIUM_PEP_MAX_CONNECTION_IDLE", "soon"},
		{"STRATIUM_PEP_MAX_CONNECTIONS", "0"}, {"STRATIUM_PEP_MAX_CONNECTIONS", "many"},
		{"STRATIUM_PEP_MAX_CONNECTIONS_PER_IP", "0"}, {"STRATIUM_PEP_MAX_CONNECTIONS_PER_IP", "1.5"},
	} {
		t.Setenv("STRATIUM_PEP_MAX_CONCURRENT_STREAMS", "")
		t.Setenv("STRATIUM_PEP_MAX_CONNECTION_IDLE", "")
		t.Setenv("STRATIUM_PEP_MAX_CONNECTIONS", "")
		t.Setenv("STRATIUM_PEP_MAX_CONNECTIONS_PER_IP", "")
		t.Setenv(bad[0], bad[1])
		if _, err := loadListenerLimitsFromEnv(); err == nil || !strings.Contains(err.Error(), bad[0]) {
			t.Errorf("%s=%q: error = %v, want one naming it", bad[0], bad[1], err)
		}
	}
}

// One connection may hold only so many calls at once; the next waits for one
// of them to finish.
func TestListenerLimits_CapConcurrentStreamsPerConnection(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 8)
	limits := listenerLimits{MaxConcurrentStreams: 2, MaxConnectionIdle: time.Minute}
	gs := newProxyGRPCServer(func(_ any, _ grpc.ServerStream) error {
		started <- struct{}{}
		<-release
		return nil
	}, limits.serverOptions()...)
	conn := serveAndDial(t, gs)

	open := func() {
		t.Helper()
		// Opening a stream past the cap blocks, so each is opened on its own
		// goroutine and counted by the handler.
		go func() {
			stream, err := conn.NewStream(context.Background(), proxyStreamDesc, "/echo.Echo/Method", grpc.ForceCodec(proxyCodec{}))
			if err == nil {
				_ = stream.CloseSend()
				_ = stream.RecvMsg(&proxyFrame{})
			}
		}()
	}
	// The first two first, and seen to start, so the client has the server's
	// settings before the third is opened and waits for room instead of being
	// refused.
	for range 2 {
		open()
	}
	for range 2 {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("a stream inside the cap did not start")
		}
	}
	open()
	select {
	case <-started:
		t.Fatal("a third stream started while two were still running, past a cap of 2")
	case <-time.After(300 * time.Millisecond):
	}
	close(release)
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("the waiting stream did not start once the others finished")
	}
}

// A proxied stream is ended once it has run for as long as the proxy allows,
// however quiet both ends are.
func TestForward_EndsAStreamThatRunsPastTheMaximumDuration(t *testing.T) {
	targetAddr := startSilentTarget(t)
	srv := &proxyServer{targetConn: dialInsecure(t, targetAddr), cfg: proxyConfig{MaxStreamDuration: 100 * time.Millisecond}}
	conn := startForwardOnlyServer(t, srv)

	stream, err := conn.NewStream(context.Background(), proxyStreamDesc, "/echo.Echo/Method", grpc.ForceCodec(proxyCodec{}))
	if err != nil {
		t.Fatalf("NewStream() error = %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- stream.RecvMsg(&proxyFrame{}) }()

	select {
	case err := <-done:
		if status.Code(err) != codes.DeadlineExceeded || !strings.Contains(err.Error(), "longer than") {
			t.Fatalf("stream ended with %v, want DeadlineExceeded saying it ran too long", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stream was still open long after the maximum duration")
	}
}

// startSilentTarget is a target that accepts any stream and then says nothing
// until the stream is cancelled.
func startSilentTarget(t *testing.T) string {
	t.Helper()
	gs := grpc.NewServer(
		grpc.UnknownServiceHandler(func(_ any, stream grpc.ServerStream) error {
			<-stream.Context().Done()
			return io.EOF
		}),
		grpc.ForceServerCodec(proxyCodec{}),
	)
	return serveOn(t, gs)
}

// serveOn serves gs on a loopback port for the life of the test and returns
// its address.
func serveOn(t *testing.T, gs *grpc.Server) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	return lis.Addr().String()
}

func serveAndDial(t *testing.T, gs *grpc.Server) *grpc.ClientConn {
	t.Helper()
	return dialInsecure(t, serveOn(t, gs))
}
