package fipsruntime

import (
	"os"
	"runtime/debug"
	"strings"

	"stratium/pkg/security/fipsbuild"
)

// Enabled reports whether FIPS runtime mode is active.
func Enabled() bool {
	if !fipsbuild.Enabled {
		return false
	}
	if strings.Contains(os.Getenv("GODEBUG"), "fips140=off") {
		return false
	}
	if _, ok := GoFIPSBuildSetting(); ok {
		return true
	}
	return strings.Contains(os.Getenv("GODEBUG"), "fips140=on")
}

// GoFIPSBuildSetting returns the GOFIPS140 build setting embedded in the binary.
func GoFIPSBuildSetting() (string, bool) {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "", false
	}
	for _, setting := range info.Settings {
		if setting.Key == "GOFIPS140" {
			return setting.Value, true
		}
	}
	return "", false
}

// GoDebugSetting extracts a single key from GODEBUG.
func GoDebugSetting(key string) (string, bool) {
	raw := os.Getenv("GODEBUG")
	if raw == "" {
		return "", false
	}
	for _, part := range strings.Split(raw, ",") {
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		if kv[0] == key {
			return kv[1], true
		}
	}
	return "", false
}
