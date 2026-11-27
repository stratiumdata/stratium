package main

import (
	"context"
	"net"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"

	"github.com/stratiumdata/stratium/internal/config"
)

// A connection with no call in flight is closed by the server once it has
// been idle for the configured time.
func TestConnectionLimits_ClosesAnIdleConnection(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	gs := grpc.NewServer(connectionLimits(config.Config{
		MaxConcurrentStreams: 256, MaxConnectionIdle: 200 * time.Millisecond,
	})...)
	grpc_health_v1.RegisterHealthServer(gs, health.NewServer())
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient(lis.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := grpc_health_v1.NewHealthClient(conn).Check(ctx, &grpc_health_v1.HealthCheckRequest{}); err != nil {
		t.Fatalf("health check: %v", err)
	}
	if got := conn.GetState(); got != connectivity.Ready {
		t.Fatalf("state after a call = %v, want Ready", got)
	}
	// Left alone, the connection must stop being Ready: the server closed it.
	if !conn.WaitForStateChange(ctx, connectivity.Ready) {
		t.Fatal("the connection was still open long after the idle time")
	}
}
