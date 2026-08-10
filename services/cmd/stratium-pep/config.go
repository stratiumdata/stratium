// config.go holds the small pieces hookConfig (hook.go) and
// sessionStartConfig (session_start.go) load identically: both require
// STRATIUM_PEP_PDP_ADDR, STRATIUM_PEP_AGENT_ID, STRATIUM_PEP_SUBJECT,
// STRATIUM_PEP_SESSION_FILE, and STRATIUM_PEP_CONNECT_TIMEOUT, with no
// default for any of them -- the same rule internal/config.Load uses for the
// PDP itself: a PEP that starts against a guessed PDP address, or that waits
// forever (or not at all) for a reply, is worse than one that refuses to
// start, because it fails at the first tool call in a way that looks like a
// policy denial rather than a misconfiguration.
package main

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// requiredEnv reads key from the environment, appending key to *missing when
// it is unset or empty. Both config loaders call this once per required
// variable and check len(*missing) only after every one has been read, so an
// error names every missing variable at once rather than stopping at the
// first -- a developer fixing configuration should not have to run the
// binary repeatedly to discover each missing value in turn.
func requiredEnv(key string, missing *[]string) string {
	v := os.Getenv(key)
	if v == "" {
		*missing = append(*missing, key)
	}
	return v
}

// missingConfigError formats the "every missing variable at once" error both
// config loaders return once their presence checks are done.
func missingConfigError(missing []string) error {
	return fmt.Errorf("missing required configuration: %s", strings.Join(missing, ", "))
}

// requiredDuration parses raw -- already confirmed non-empty by requiredEnv
// -- as a duration and requires it to be positive. Shared by hookConfig and
// sessionStartConfig for STRATIUM_PEP_CONNECT_TIMEOUT: a zero or negative
// timeout would mean every PDP call fails before it starts, or never times
// out at all, and either is worth its own explicit error rather than
// surfacing later as a confusing context.WithTimeout deadline.
func requiredDuration(key, raw string) (time.Duration, error) {
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", key, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive, got %s", key, d)
	}
	return d, nil
}
