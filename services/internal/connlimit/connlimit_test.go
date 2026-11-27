package connlimit

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// serve accepts on l for the life of the test and holds every connection it
// is given open, so a slot stays taken until the client closes.
func serve(t *testing.T, l net.Listener) {
	t.Helper()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, c); _ = c.Close() }()
		}
	}()
	t.Cleanup(func() { _ = l.Close() })
}

func listen(t *testing.T, limits Limits) net.Listener {
	t.Helper()
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	l := Listen(inner, limits)
	serve(t, l)
	return l
}

func dial(t *testing.T, l net.Listener) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// refused reports whether the server closed c: a read returns at once with an
// error. A connection that was admitted is held open, so the read times out.
func refused(t *testing.T, c net.Conn) bool {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, err := c.Read(make([]byte, 1))
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	return err != nil
}

func TestListen_RefusesConnectionsPastTheTotal_AndAdmitsAgainWhenOneCloses(t *testing.T) {
	l := listen(t, Limits{Max: 2})
	first, second := dial(t, l), dial(t, l)
	if refused(t, first) || refused(t, second) {
		t.Fatal("a connection inside the limit was refused")
	}
	if !refused(t, dial(t, l)) {
		t.Fatal("a third connection was admitted past a limit of 2")
	}

	_ = first.Close()
	// The server notices the close on its own goroutine; give it a moment.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if !refused(t, dial(t, l)) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("no connection was admitted after one of the two closed")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestListen_RefusesConnectionsPastTheLimitForOneSource(t *testing.T) {
	l := listen(t, Limits{Max: 100, MaxPerSource: 1})
	if refused(t, dial(t, l)) {
		t.Fatal("the first connection from a source was refused")
	}
	if !refused(t, dial(t, l)) {
		t.Fatal("a second connection from the same address was admitted past a limit of 1")
	}
}

func TestListen_ZeroLimitsRefuseNothing(t *testing.T) {
	l := listen(t, Limits{})
	for i := range 5 {
		if refused(t, dial(t, l)) {
			t.Fatalf("connection %d was refused with no limits set", i)
		}
	}
}

// One client holds a whole IPv6 /64, so that is what counts as one source.
func TestSourceOf(t *testing.T) {
	tcp := func(ip string) net.Addr { return &net.TCPAddr{IP: net.ParseIP(ip), Port: 1234} }
	same := [][2]string{
		{"192.0.2.7", "192.0.2.7"},
		{"2001:db8:1:2::1", "2001:db8:1:2:ffff:ffff:ffff:ffff"},
		{"::ffff:192.0.2.7", "192.0.2.7"}, // an IPv4 address as IPv6 writes it
	}
	for _, p := range same {
		if sourceOf(tcp(p[0])) != sourceOf(tcp(p[1])) {
			t.Errorf("%s and %s are different sources, want the same", p[0], p[1])
		}
	}
	different := [][2]string{{"192.0.2.7", "192.0.2.8"}, {"2001:db8:1:2::1", "2001:db8:1:3::1"}}
	for _, p := range different {
		if sourceOf(tcp(p[0])) == sourceOf(tcp(p[1])) {
			t.Errorf("%s and %s are the same source, want different", p[0], p[1])
		}
	}
}
