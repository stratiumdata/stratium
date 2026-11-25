package main

import (
	"context"
	"errors"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// requestDeadline gives every call at most d to finish, whatever deadline the
// caller set or did not set. grpc-go applies none of its own, so a caller
// that sets none would otherwise wait as long as the database made it: for a
// pooled connection, or for the audit append lock.
//
// A call that runs out of time fails, which every caller treats as a denial.
// It is reported as DeadlineExceeded in place of whichever error the handler
// built from the cancelled context, so a PEP's log says what happened.
func requestDeadline(d time.Duration) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		ctx, cancel := context.WithTimeout(ctx, d)
		defer cancel()
		resp, err := handler(ctx, req)
		if err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, status.Error(codes.DeadlineExceeded, "the call did not finish within the time the PDP allows one")
		}
		return resp, err
	}
}
