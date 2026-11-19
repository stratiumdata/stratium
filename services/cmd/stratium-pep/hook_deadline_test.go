package main

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"
	"time"
)

func TestHookBudget_CoversEveryBoundedStep(t *testing.T) {
	cfg := hookConfig{ConnectTimeout: 5 * time.Second, ApprovalTimeout: 120 * time.Second}
	if got, want := hookBudget(cfg), 140*time.Second; got != want {
		t.Fatalf("hookBudget = %s, want %s", got, want)
	}
}

func TestRunWithDeadline_DeniesWhenTheRunOutlivesItsBudget(t *testing.T) {
	release := make(chan struct{})
	defer close(release)

	var stdout bytes.Buffer
	code := runWithDeadline(20*time.Millisecond, &stdout, func(w io.Writer) int {
		<-release // a run that would otherwise never answer
		_, _ = w.Write([]byte("late output that must not reach stdout"))
		return 0
	})

	if code != 2 {
		t.Fatalf("exit code = %d, want 2 (deny)", code)
	}
	var out hookOutput
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil {
		t.Fatalf("stdout is not one deny document: %v (%q)", err, stdout.String())
	}
	if out.HookSpecificOutput.PermissionDecision != "deny" {
		t.Fatalf("permissionDecision = %q, want deny", out.HookSpecificOutput.PermissionDecision)
	}
}

func TestRunWithDeadline_PassesThroughARunThatAnswersInTime(t *testing.T) {
	var stdout bytes.Buffer
	code := runWithDeadline(time.Minute, &stdout, func(w io.Writer) int {
		_, _ = w.Write([]byte("answer"))
		return 0
	})
	if code != 0 || stdout.String() != "answer" {
		t.Fatalf("got code %d stdout %q, want 0 and the run's own output", code, stdout.String())
	}
}
