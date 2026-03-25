//go:build !fips

package key_manager

import "testing"

func TestCoverageFinal80_ParseTouchPolicyFromYKManInfo(t *testing.T) {
	// Found
	output := []byte("Touch policy: Always\nAnother line\n")
	policy, err := parseTouchPolicyFromYKManInfo(output)
	if err != nil {
		t.Fatalf("parseTouchPolicyFromYKManInfo: %v", err)
	}
	if policy != "always" {
		t.Fatalf("expected always, got %s", policy)
	}

	// Not found
	_, err = parseTouchPolicyFromYKManInfo([]byte("no relevant line\n"))
	if err == nil {
		t.Fatal("expected error when touch policy not found")
	}
}

func TestCoverageFinal80_ParseTouchPolicyFromPIVStatus(t *testing.T) {
	output := []byte("Slot 9d:\n  Touch policy: Always\n")
	policy, err := parseTouchPolicyFromPIVStatus(output, "9d")
	if err != nil {
		t.Fatalf("parseTouchPolicyFromPIVStatus: %v", err)
	}
	if policy != "always" {
		t.Fatalf("expected always, got %s", policy)
	}

	// Empty slot defaults to 9d
	policy2, err := parseTouchPolicyFromPIVStatus(output, "")
	if err != nil {
		t.Fatalf("parseTouchPolicyFromPIVStatus empty slot: %v", err)
	}
	if policy2 != "always" {
		t.Fatalf("expected always, got %s", policy2)
	}

	// No match
	_, err = parseTouchPolicyFromPIVStatus([]byte("nothing here\n"), "9c")
	if err == nil {
		t.Fatal("expected error when policy not found for slot")
	}
}

func TestCoverageFinal80_ExtractTouchPolicyFromLine(t *testing.T) {
	// Empty line
	_, ok := extractTouchPolicyFromLine("")
	if ok {
		t.Fatal("expected false for empty line")
	}

	// No touch/policy
	_, ok = extractTouchPolicyFromLine("some random line")
	if !ok {
		// Try with touch keyword
	}

	// With colon separator
	val, ok := extractTouchPolicyFromLine("Touch policy: Always")
	if !ok || val != "always" {
		t.Fatalf("expected always, got %s (ok=%t)", val, ok)
	}

	// With equals separator
	val, ok = extractTouchPolicyFromLine("touch_policy=cached")
	if !ok || val != "cached" {
		t.Fatalf("expected cached, got %s (ok=%t)", val, ok)
	}

	// "Touch required for use" variant
	val, ok = extractTouchPolicyFromLine("Touch required for use: true")
	if !ok {
		t.Fatal("expected match for 'touch required for use'")
	}
}

func TestCoverageFinal80_ValidateTouchPolicy(t *testing.T) {
	if err := validateTouchPolicy("9d", "Always"); err != nil {
		t.Fatal(err)
	}
	if err := validateTouchPolicy("9d", "cached"); err == nil {
		t.Fatal("expected error for non-always policy")
	}
}

func TestCoverageFinal80_NormalizeTouchPolicy(t *testing.T) {
	if got := normalizeTouchPolicy("  ALWAYS, "); got != "always" {
		t.Fatalf("expected always, got %s", got)
	}
	if got := normalizeTouchPolicy("for cached"); got != "cached" {
		t.Fatalf("expected cached, got %s", got)
	}
}

func TestCoverageFinal80_NormalizeTouchPolicy_WithSpaces(t *testing.T) {
	// Value with spaces triggers line 168-169
	result := normalizeTouchPolicy("always required")
	if result != "always" {
		t.Fatalf("expected 'always', got '%s'", result)
	}
}

func TestCoverageFinal80_ExtractTouchPolicyFromLine_NoSeparator(t *testing.T) {
	// Touch policy without colon/equals - hits the fallback to last field
	val, ok := extractTouchPolicyFromLine("Touch policy Always")
	if !ok {
		t.Fatal("expected match")
	}
	if val != "always" {
		t.Fatalf("expected always, got %s", val)
	}
}

func TestCoverageFinal80_ParseTouchPolicyFromPIVStatus_FallbackNoSlotHeader(t *testing.T) {
	// Output with touch policy but no explicit slot header - triggers fallback at line 127
	output := []byte("Touch policy: Always\n")
	policy, err := parseTouchPolicyFromPIVStatus(output, "9c")
	if err != nil {
		t.Fatalf("parseTouchPolicyFromPIVStatus fallback: %v", err)
	}
	if policy != "always" {
		t.Fatalf("expected always, got %s", policy)
	}
}

func TestCoverageFinal80_CollapseWhitespace(t *testing.T) {
	result := collapseWhitespace("  hello   world  ")
	if result != "hello world" {
		t.Fatalf("expected 'hello world', got '%s'", result)
	}
}
