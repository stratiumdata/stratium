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
// supplied from the environment either.
package main

import (
	"fmt"
	"os"
	"strings"
)

const configKeyPrefix = "STRATIUM_PEP_"

// applyConfigFile looks for `--config <file>` in a subcommand's arguments and,
// when present, clears every STRATIUM_PEP_* variable from the process
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
		if key, _, _ := strings.Cut(kv, "="); strings.HasPrefix(key, configKeyPrefix) {
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
	for i, a := range args {
		if v, found := strings.CutPrefix(a, "--config="); found {
			path, ok = v, true
		} else if a == "--config" {
			if i+1 >= len(args) {
				return "", false, fmt.Errorf("--config needs a file path")
			}
			path, ok = args[i+1], true
		}
		if ok && path == "" {
			return "", false, fmt.Errorf("--config needs a file path")
		}
		if ok {
			return path, true, nil
		}
	}
	return "", false, nil
}
