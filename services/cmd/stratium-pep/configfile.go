// configfile.go implements `--config <file>`: a file of STRATIUM_PEP_*
// settings that replaces the environment's before any subcommand reads its
// configuration.
//
// The environment a hook runs in is whatever the harness hands it, and a
// harness builds that from files the governed agent may be able to write (a
// project settings file can set environment variables). A hook entry an
// administrator installed can instead name a file only the administrator can
// write. The file is then the whole configuration: every STRATIUM_PEP_*
// variable already in the environment is dropped first, so an optional
// setting the file leaves out (STRATIUM_PEP_PDP_INSECURE, say) cannot be
// supplied from the environment either. The proxy and certificate-trust
// variables the Go runtime and grpc-go read for themselves go with them.
package main

import (
	"fmt"
	"os"
	"strings"
)

const configKeyPrefix = "STRATIUM_PEP_"

// ambientNetworkEnv names the variables, outside the STRATIUM_PEP_ prefix,
// that change where a connection goes or whose certificate it accepts. Go's
// TLS and proxy support and grpc-go read them straight from the environment,
// so a pinned configuration has to drop them too; GRPC_-prefixed variables are
// dropped as a group (see pinnedEnvDropped). Matched without regard to case,
// because the proxy variables are honoured in both spellings.
var ambientNetworkEnv = []string{
	"SSL_CERT_FILE", "SSL_CERT_DIR",
	"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
	"GODEBUG",
}

// pinnedEnvDropped reports whether --config removes key from the environment.
func pinnedEnvDropped(key string) bool {
	if strings.HasPrefix(key, configKeyPrefix) {
		return true
	}
	upper := strings.ToUpper(key)
	if strings.HasPrefix(upper, "GRPC_") {
		return true
	}
	for _, name := range ambientNetworkEnv {
		if upper == name {
			return true
		}
	}
	return false
}

// applyConfigFile looks for `--config <file>` in a subcommand's arguments and,
// when present, clears every variable pinnedEnvDropped names from the process
// environment and sets each KEY=value line of that file in its place. Blank lines and lines starting with # are skipped; a value is
// everything after the first "=", trimmed of surrounding space, taken
// literally (no quoting, no expansion). Any error leaves the caller unable to
// trust its configuration, so callers refuse to run rather than fall back to
// the environment.
func applyConfigFile(args []string) error {
	path, ok, err := configFlag(args)
	if err != nil || !ok {
		return err
	}
	raw, err := os.ReadFile(path) // #nosec G304 G703 -- the path is the operator's own flag
	if err != nil {
		return fmt.Errorf("--config: %w", err)
	}
	for _, kv := range os.Environ() {
		if key, _, _ := strings.Cut(kv, "="); pinnedEnvDropped(key) {
			if err := os.Unsetenv(key); err != nil {
				return fmt.Errorf("--config: clearing %s: %w", key, err)
			}
		}
	}
	for n, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		key = strings.TrimSpace(key)
		if !found || !strings.HasPrefix(key, configKeyPrefix) {
			return fmt.Errorf("--config: %s line %d: want %sNAME=value", path, n+1, configKeyPrefix)
		}
		if err := os.Setenv(key, strings.TrimSpace(value)); err != nil {
			return fmt.Errorf("--config: %s line %d: %w", path, n+1, err)
		}
	}
	return nil
}

// configFlag returns the value of `--config <file>` or `--config=<file>`.
func configFlag(args []string) (path string, ok bool, err error) {
	path, ok, err = flagValue(args, "--config")
	if err != nil {
		return "", false, fmt.Errorf("--config needs a file path")
	}
	return path, ok, nil
}

// flagValue finds `name value` or `name=value` in args. A flag that is
// present with no value is an error, never "absent".
func flagValue(args []string, name string) (value string, ok bool, err error) {
	for i, a := range args {
		if v, found := strings.CutPrefix(a, name+"="); found {
			value, ok = v, true
		} else if a == name {
			if i+1 >= len(args) {
				return "", false, fmt.Errorf("%s needs a value", name)
			}
			value, ok = args[i+1], true
		}
		if ok && value == "" {
			return "", false, fmt.Errorf("%s needs a value", name)
		}
		if ok {
			return value, true, nil
		}
	}
	return "", false, nil
}
