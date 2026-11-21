package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLimitBody(t *testing.T) {
	var readErr error
	h := limitBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, readErr = io.ReadAll(r.Body)
	}))
	over := strings.Repeat("x", maxBodyBytes+1)

	// Declared length over the limit: refused before the handler runs.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/policies", strings.NewReader(over)))
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("declared oversize body: status = %d, want 413", rec.Code)
	}

	// Undeclared length: the handler's read fails at the limit.
	req := httptest.NewRequest(http.MethodPost, "/v1/policies", io.NopCloser(strings.NewReader(over)))
	req.ContentLength = -1
	h.ServeHTTP(httptest.NewRecorder(), req)
	if readErr == nil {
		t.Error("undeclared oversize body: handler read all of it, want an error at the limit")
	}

	// At the limit: untouched.
	readErr = nil
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/v1/policies", strings.NewReader(over[1:])))
	if rec.Code != http.StatusOK || readErr != nil {
		t.Errorf("body at the limit: status = %d, read error = %v, want 200 and nil", rec.Code, readErr)
	}
}
