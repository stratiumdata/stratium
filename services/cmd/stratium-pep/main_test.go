package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestDispatch_NoArgs_UsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := dispatch(nil, strings.NewReader(""), &stdout, &stderr)

	if code != 1 {
		t.Errorf("dispatch() = %d, want 1", code)
	}
	if stderr.Len() == 0 {
		t.Error("stderr is empty, want a usage message")
	}
}

func TestDispatch_UnknownSubcommand_UsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := dispatch([]string{"bogus"}, strings.NewReader(""), &stdout, &stderr)

	if code != 1 {
		t.Errorf("dispatch() = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "bogus") {
		t.Errorf("stderr = %q, want it to name the unknown subcommand", stderr.String())
	}
}
