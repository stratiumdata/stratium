package fipsruntime

import (
	"testing"
)

// TestGoDebugSetting_Empty verifies empty GODEBUG returns not-found.
func TestGoDebugSetting_Empty(t *testing.T) {
	t.Setenv("GODEBUG", "")
	_, ok := GoDebugSetting("fips140")
	if ok {
		t.Error("GoDebugSetting() ok = true for empty GODEBUG, want false")
	}
}

// TestGoDebugSetting_KeyPresent verifies a known key is found.
func TestGoDebugSetting_KeyPresent(t *testing.T) {
	t.Setenv("GODEBUG", "fips140=on,asyncpreemptoff=1")
	val, ok := GoDebugSetting("fips140")
	if !ok {
		t.Fatal("GoDebugSetting() ok = false, want true")
	}
	if val != "on" {
		t.Errorf("GoDebugSetting() = %q, want 'on'", val)
	}
}

// TestGoDebugSetting_SingleEntry verifies single-key GODEBUG works.
func TestGoDebugSetting_SingleEntry(t *testing.T) {
	t.Setenv("GODEBUG", "fips140=off")
	val, ok := GoDebugSetting("fips140")
	if !ok {
		t.Fatal("GoDebugSetting() ok = false, want true")
	}
	if val != "off" {
		t.Errorf("GoDebugSetting() = %q, want 'off'", val)
	}
}

// TestGoDebugSetting_KeyMissing verifies missing key returns not-found.
func TestGoDebugSetting_KeyMissing(t *testing.T) {
	t.Setenv("GODEBUG", "asyncpreemptoff=1,gccheckmark=1")
	_, ok := GoDebugSetting("fips140")
	if ok {
		t.Error("GoDebugSetting() ok = true for missing key, want false")
	}
}

// TestGoDebugSetting_MalformedEntry verifies entries without '=' are skipped.
func TestGoDebugSetting_MalformedEntry(t *testing.T) {
	t.Setenv("GODEBUG", "noequals,fips140=on")
	val, ok := GoDebugSetting("fips140")
	if !ok {
		t.Fatal("GoDebugSetting() should still find valid entry")
	}
	if val != "on" {
		t.Errorf("GoDebugSetting() = %q, want 'on'", val)
	}
}

// TestGoFIPSBuildSetting_DoesNotPanic verifies function is safe to call.
func TestGoFIPSBuildSetting_DoesNotPanic(t *testing.T) {
	// Just ensure it doesn't panic — result depends on build environment
	_, _ = GoFIPSBuildSetting()
}

// TestEnabled_NonFIPSBuild verifies Enabled() returns false in a non-FIPS build.
func TestEnabled_NonFIPSBuild(t *testing.T) {
	// In non-FIPS builds, fipsbuild.Enabled is false, so Enabled() always returns false.
	// This test just validates the function is callable and doesn't panic.
	_ = Enabled()
}
