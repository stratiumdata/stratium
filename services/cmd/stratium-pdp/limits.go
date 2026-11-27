package main

import (
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"

	"github.com/stratiumdata/stratium/internal/config"
)

// A connection whose peer has gone without closing it is found by a ping
// every keepaliveTime that goes unanswered for keepaliveTimeout. grpc-go's own
// default is a ping every two hours. The same values the PEP's listeners use
// (cmd/stratium-pep/listener.go).
const (
	keepaliveTime    = time.Minute
	keepaliveTimeout = 20 * time.Second

	// handshakeTimeout is how long a new connection has to finish its TLS and
	// HTTP/2 handshakes. Until it does it holds a connection slot
	// (internal/connlimit) having shown nothing; grpc-go's own default lets
	// it do that for two minutes.
	handshakeTimeout = 10 * time.Second
)

// connectionLimits bounds what one client connection may hold open. grpc-go's
// own defaults are no limit on calls in flight, and a connection kept for as
// long as the client likes however idle it is.
//
// No keepalive.EnforcementPolicy is set: grpc-go's default already closes a
// connection whose client pings more often than every five minutes.
func connectionLimits(cfg config.Config) []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.MaxConcurrentStreams(cfg.MaxConcurrentStreams),
		grpc.ConnectionTimeout(handshakeTimeout),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: cfg.MaxConnectionIdle,
			Time:              keepaliveTime,
			Timeout:           keepaliveTimeout,
		}),
	}
}
