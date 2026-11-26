package main

import (
	"fmt"
	"math"
	"os"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

// listenerLimits bounds what one client connection may hold open on a PEP
// network surface (proxy, extauthz, extmcp). grpc-go's own defaults are no
// limit on calls in flight, and a connection kept for as long as the client
// likes however idle it is.
type listenerLimits struct {
	// MaxConcurrentStreams is the most calls one connection may have in
	// flight; one more waits for one of them to finish.
	MaxConcurrentStreams uint32 // STRATIUM_PEP_MAX_CONCURRENT_STREAMS, default 256
	// MaxConnectionIdle is how long a connection with no call in flight is
	// kept before the server closes it. The client reconnects on its next
	// call.
	MaxConnectionIdle time.Duration // STRATIUM_PEP_MAX_CONNECTION_IDLE, default 5m
}

const (
	maxConcurrentStreamsVar = "STRATIUM_PEP_MAX_CONCURRENT_STREAMS"
	maxConnectionIdleVar    = "STRATIUM_PEP_MAX_CONNECTION_IDLE"

	// A connection whose peer has gone without closing it is found by a ping
	// every keepaliveTime that goes unanswered for keepaliveTimeout. grpc-go's
	// own default is a ping every two hours.
	keepaliveTime    = time.Minute
	keepaliveTimeout = 20 * time.Second
)

// loadListenerLimitsFromEnv reads the limits, each with a default.
func loadListenerLimitsFromEnv() (listenerLimits, error) {
	l := listenerLimits{MaxConcurrentStreams: 256, MaxConnectionIdle: 5 * time.Minute}
	if v := os.Getenv(maxConcurrentStreamsVar); v != "" {
		n, err := strconv.ParseUint(v, 10, 32)
		if err != nil || n < 1 || n > math.MaxUint32 {
			return listenerLimits{}, fmt.Errorf("%s must be an integer of at least 1, got %q", maxConcurrentStreamsVar, v)
		}
		l.MaxConcurrentStreams = uint32(n)
	}
	if v := os.Getenv(maxConnectionIdleVar); v != "" {
		d, err := requiredDuration(maxConnectionIdleVar, v)
		if err != nil {
			return listenerLimits{}, err
		}
		l.MaxConnectionIdle = d
	}
	return l, nil
}

// serverOptions are the limits as options for grpc.NewServer.
//
// No keepalive.EnforcementPolicy is set: grpc-go's default already closes a
// connection whose client pings more often than every five minutes.
func (l listenerLimits) serverOptions() []grpc.ServerOption {
	return []grpc.ServerOption{
		grpc.MaxConcurrentStreams(l.MaxConcurrentStreams),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle: l.MaxConnectionIdle,
			Time:              keepaliveTime,
			Timeout:           keepaliveTimeout,
		}),
	}
}
