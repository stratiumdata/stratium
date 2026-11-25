package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestRequestDeadline_BoundsACallWithNoDeadlineOfItsOwn(t *testing.T) {
	intercept := requestDeadline(20 * time.Millisecond)
	// A handler that waits on its context, as one queued for a database
	// connection does, and reports what it was told as an Internal error.
	blocked := func(ctx context.Context, _ any) (any, error) {
		<-ctx.Done()
		return nil, status.Errorf(codes.Internal, "load agent: %s", ctx.Err())
	}

	done := make(chan error, 1)
	go func() {
		_, err := intercept(context.Background(), nil, nil, blocked)
		done <- err
	}()
	select {
	case err := <-done:
		if status.Code(err) != codes.DeadlineExceeded {
			t.Errorf("code = %v (%v), want DeadlineExceeded", status.Code(err), err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the call was still running long after the deadline")
	}
}

func TestRequestDeadline_LeavesOtherOutcomesAlone(t *testing.T) {
	intercept := requestDeadline(time.Minute)

	resp, err := intercept(context.Background(), nil, nil, func(context.Context, any) (any, error) { return "ok", nil })
	if err != nil || resp != "ok" {
		t.Errorf("a call that finishes = (%v, %v), want (ok, nil)", resp, err)
	}

	want := status.Error(codes.NotFound, "agent unknown")
	_, err = intercept(context.Background(), nil, nil, func(context.Context, any) (any, error) { return nil, want })
	if !errors.Is(err, want) {
		t.Errorf("a handler's own error = %v, want it unchanged", err)
	}

	// A caller's shorter deadline still applies, and is reported as the
	// caller's, not as this server's.
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	_, err = intercept(ctx, nil, nil, func(ctx context.Context, _ any) (any, error) {
		<-ctx.Done()
		return nil, status.FromContextError(ctx.Err()).Err()
	})
	if status.Code(err) != codes.DeadlineExceeded {
		t.Errorf("code under the caller's deadline = %v, want DeadlineExceeded", status.Code(err))
	}
}
