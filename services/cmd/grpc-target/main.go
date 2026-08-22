// Command grpc-target is the real gRPC service Task 4's proxy proof
// (services/internal/store/proxy_integration_test.go) puts `stratium-pep
// proxy` in front of -- deploy/docker/docker-compose.yml's own grpc-target
// service. Generated from proto/target/v1/target.proto
// (services/internal/grpctarget): unlike deploy/docker/echo-upstream/main.go
// (Phase 10's own trivial HTTP upstream), this speaks real gRPC with real
// generated request/response types, so a caller going through the proxy's
// passthrough codec (cmd/stratium-pep/proxy.go's own package doc,
// PASSTHROUGH CODEC) carries genuine protobuf-encoded messages end to end --
// not the hand-rolled raw-byte proxyFrame payload proxy_test.go's own unit
// tests construct directly.
//
// This is `make integration`'s own test fixture -- it never ships anywhere,
// carries no secret, and authenticates no caller (that is stratium-pep
// proxy's own job, one hop upstream of every request this process ever
// receives) -- so it stays deliberately as small as echo-upstream: one file,
// an in-memory counter, no persistence.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	"stratium/pkg/grpctarget"
)

// listenAddr is fixed, not read from the environment: unlike stratium-pdp
// and stratium-pep (real, shipped binaries whose deployment shape genuinely
// varies), this process has exactly one deployment -- deploy/docker/
// docker-compose.yml's own grpc-target service -- so a configurable address
// would be a knob nothing ever turns. ":50051" mirrors every PDP compose
// service's own internal port for the same reason theirs is fixed inside
// each container: docker-compose's own network namespacing, not this
// process, is what keeps that port from colliding with anything else.
const listenAddr = ":50051"

// trailerKey is the response trailer TestIntegration_Proxy_
// PermittedActionReachesUpstream (proxy_integration_test.go) checks
// survives the proxy's own relay intact -- proof 1's own "trailers
// included" requirement. Its value embeds the SAME call number the
// response body itself carries (echo, below), so a test can cross-check
// the trailer and the body agree about which call they belong to, not just
// that a trailer of some kind arrived.
const trailerKey = "x-grpc-target-call"

// targetServer implements TargetServiceServer. callCount is the one piece
// of state this process keeps: every Fetch, Purge, or opened Chat stream
// increments it once, and CallCount reports it back to a caller that
// dialled this service directly -- see target.proto's own doc comment on
// why that direct channel exists at all.
type targetServer struct {
	grpctarget.UnimplementedTargetServiceServer
	callCount atomic.Int64
}

// echo is Fetch and Purge's shared body: both are the identical "echo the
// message, report the call number, set the matching trailer" shape --
// nothing about their handling differs, only their TOOL IDENTITY (the full
// method string a caller dials) differs, which is all a proof needs to seed
// one as permitted and the other as denied. grpc.SetTrailer's own error is
// checked and returned, not ignored -- this file is not a _test.go (no
// errcheck exclusion applies to it, per the root .golangci.yml), and a
// trailer failing to set silently would make proof 1's own "trailers
// included" requirement pass or fail on the wrong signal.
func (s *targetServer) echo(ctx context.Context, req *grpctarget.EchoRequest) (*grpctarget.EchoResponse, error) {
	n := s.callCount.Add(1)
	if err := grpc.SetTrailer(ctx, metadata.Pairs(trailerKey, fmt.Sprintf("call-%d", n))); err != nil {
		return nil, fmt.Errorf("grpc-target: set trailer: %w", err)
	}
	return &grpctarget.EchoResponse{Message: req.GetMessage(), CallNumber: n}, nil
}

func (s *targetServer) Fetch(ctx context.Context, req *grpctarget.EchoRequest) (*grpctarget.EchoResponse, error) {
	return s.echo(ctx, req)
}

func (s *targetServer) Purge(ctx context.Context, req *grpctarget.EchoRequest) (*grpctarget.EchoResponse, error) {
	return s.echo(ctx, req)
}

// Chat counts once per opened stream (not once per message): the property
// TestIntegration_Proxy_StreamAuthorizedOnceForwardsBothDirections cares
// about is whether the STREAM reached this service, not how many messages
// crossed it, mirroring proxy_test.go's own P4 proofs one layer up.
func (s *targetServer) Chat(stream grpctarget.TargetService_ChatServer) error {
	s.callCount.Add(1)
	for {
		msg, err := stream.Recv()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if err := stream.Send(&grpctarget.ChatMessage{Message: msg.GetMessage()}); err != nil {
			return err
		}
	}
}

// CallCount never increments callCount itself -- a caller polling this RPC
// repeatedly (or a proof calling it before and after a denied call) must
// not perturb the very count it is reading.
func (s *targetServer) CallCount(_ context.Context, _ *grpctarget.CallCountRequest) (*grpctarget.CallCountResponse, error) {
	return &grpctarget.CallCountResponse{Count: s.callCount.Load()}, nil
}

func main() {
	lis, err := net.Listen("tcp", listenAddr) //nolint:gosec // G102: binds every interface the same way every PDP compose service's own STRATIUM_LISTEN_ADDR (":50051") does -- required for docker-compose's own port mapping to reach this container at all. This process authenticates no caller and holds no secret (that is stratium-pep proxy's job, one hop upstream); it is `make integration`'s own throwaway test fixture, published to an ephemeral host port like every other PDP compose service, never a real deployment
	if err != nil {
		log.Fatalf("grpc-target: listen on %s: %v", listenAddr, err)
	}
	gs := grpc.NewServer()
	grpctarget.RegisterTargetServiceServer(gs, &targetServer{})
	log.Printf("grpc-target: listening on %s", listenAddr)
	if err := gs.Serve(lis); err != nil {
		log.Fatalf("grpc-target: serve: %v", err)
	}
}
