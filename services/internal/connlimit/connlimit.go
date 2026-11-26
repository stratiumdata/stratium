// Package connlimit caps how many connections a listener holds open, in all
// and from any one source address.
//
// Every other limit in this system is per connection or per session; without
// this one a client could simply open more connections. A connection past a
// limit is accepted and closed at once, not left waiting: the client learns
// straight away and backs off, and nothing queues in the kernel's backlog
// behind connections that will never be served.
//
// The per-source limit means what it says only when clients connect
// directly. Behind a load balancer that connects from its own addresses,
// every client is one source; set that limit as high as the total there, and
// limit per client at the load balancer.
package connlimit

import (
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Limits is the most connections a listener holds open. Zero is no limit.
type Limits struct {
	// Max is the most in all.
	Max int
	// MaxPerSource is the most from one source: an IPv4 address, or an IPv6
	// /64, which is what one client is given.
	MaxPerSource int
}

// refusalLogInterval is the least time between two log lines about refused
// connections, so a flood of them is not also a flood of log lines.
const refusalLogInterval = 10 * time.Second

// Listen wraps inner so that it admits no more connections than limits
// allows.
func Listen(inner net.Listener, limits Limits) net.Listener {
	return &listener{Listener: inner, limits: limits, bySource: map[netip.Addr]int{}}
}

type listener struct {
	net.Listener
	limits Limits

	mu       sync.Mutex
	open     int
	bySource map[netip.Addr]int
	// refused counts connections closed since the last log line about them.
	refused int
	lastLog time.Time
}

// Accept returns the next connection the limits admit, closing any that they
// do not.
func (l *listener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		source := sourceOf(c.RemoteAddr())
		if l.admit(source) {
			return &conn{Conn: c, release: func() { l.release(source) }}, nil
		}
		_ = c.Close()
	}
}

func (l *listener) admit(source netip.Addr) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	overTotal := l.limits.Max > 0 && l.open >= l.limits.Max
	overSource := l.limits.MaxPerSource > 0 && l.bySource[source] >= l.limits.MaxPerSource
	if overTotal || overSource {
		l.refused++
		if now := time.Now(); now.Sub(l.lastLog) >= refusalLogInterval {
			slog.Warn("connections refused: over the connection limit",
				"listener", l.Addr().String(), "refused", l.refused, "open", l.open,
				"last_source", source.String(), "over_total", overTotal, "over_source", overSource)
			l.refused, l.lastLog = 0, now
		}
		return false
	}
	l.open++
	l.bySource[source]++
	return true
}

func (l *listener) release(source netip.Addr) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.open--
	if l.bySource[source]--; l.bySource[source] <= 0 {
		delete(l.bySource, source)
	}
}

// conn gives its slot back when it is closed, once.
type conn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *conn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}

// sourceOf is what a remote address counts as: its IPv4 address, or the /64
// its IPv6 address is in. An address this cannot read (not TCP) is the zero
// Addr, so all such connections count as one source.
func sourceOf(remote net.Addr) netip.Addr {
	tcp, ok := remote.(*net.TCPAddr)
	if !ok {
		return netip.Addr{}
	}
	addr := tcp.AddrPort().Addr().Unmap()
	if addr.Is6() {
		if prefix, err := addr.Prefix(64); err == nil {
			return prefix.Addr()
		}
	}
	return addr
}
