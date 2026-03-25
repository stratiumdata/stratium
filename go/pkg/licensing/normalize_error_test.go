package licensing

import (
	"errors"
	"testing"
)

// TestNormalizeError_NilErr verifies fallback message is used when err is nil.
func TestNormalizeError_NilErr(t *testing.T) {
	err := normalizeError(nil, "fallback message")
	if err == nil {
		t.Fatal("normalizeError(nil, ...) should return non-nil error")
	}
	if err.Error() != "fallback message" {
		t.Errorf("normalizeError(nil, ...) = %q, want 'fallback message'", err.Error())
	}
}

// TestNormalizeError_NonNilErr verifies the original error is preserved.
func TestNormalizeError_NonNilErr(t *testing.T) {
	original := errors.New("original error")
	err := normalizeError(original, "fallback")
	if err != original {
		t.Errorf("normalizeError(err, ...) returned different error, want original")
	}
}
