package agent

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// Check is one prerequisite. Fix is the exact command that resolves it.
type Check struct {
	Name  string
	Probe func() error
	Fix   string
}

// Precheck runs every check and reports ALL failures at once, not just the
// first: a reader with three things missing should learn that in one run
// rather than three.
func Precheck(checks ...Check) error {
	var b strings.Builder
	failed := 0
	for _, c := range checks {
		if err := c.Probe(); err != nil {
			failed++
			fmt.Fprintf(&b, "\n  %s: %v", c.Name, err)
			if c.Fix != "" {
				fmt.Fprintf(&b, "\n      fix: %s", c.Fix)
			}
		}
	}
	if failed == 0 {
		return nil
	}
	return fmt.Errorf("%d prerequisite(s) not met — this is setup, not a policy denial:%s", failed, b.String())
}

// DialCheck probes a TCP address. Used for ollama, litellm and the surfaces.
func DialCheck(addr string) func() error {
	return func() error {
		conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			return err
		}
		return conn.Close()
	}
}
