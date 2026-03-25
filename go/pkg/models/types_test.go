package models

import (
	"errors"
	"testing"
)

func TestError_Error(t *testing.T) {
	tests := []struct {
		name string
		err  *Error
		want string
	}{
		{
			"with wrapped error",
			&Error{Code: "ENCRYPTION_FAILED", Message: "bad key", Err: errors.New("underlying cause")},
			"ENCRYPTION_FAILED: bad key: underlying cause",
		},
		{
			"without wrapped error",
			&Error{Code: "KEY_NOT_FOUND", Message: "no such key"},
			"KEY_NOT_FOUND: no such key",
		},
		{
			"empty message with wrapped error",
			&Error{Code: "AUTH_FAILED", Message: "", Err: errors.New("token expired")},
			"AUTH_FAILED: : token expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.want {
				t.Errorf("Error() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestError_Unwrap(t *testing.T) {
	sentinel := errors.New("root cause")
	e := &Error{Code: "DECRYPTION_FAILED", Message: "oops", Err: sentinel}

	unwrapped := e.Unwrap()
	if unwrapped != sentinel {
		t.Errorf("Unwrap() = %v, want %v", unwrapped, sentinel)
	}
}

func TestError_Unwrap_Nil(t *testing.T) {
	e := &Error{Code: "INTEGRITY_FAILED", Message: "hash mismatch"}
	if e.Unwrap() != nil {
		t.Error("Unwrap() should return nil when no wrapped error")
	}
}

func TestError_ErrorsIs(t *testing.T) {
	sentinel := errors.New("root")
	e := &Error{Code: "ENCRYPTION_FAILED", Message: "msg", Err: sentinel}

	if !errors.Is(e, sentinel) {
		t.Error("errors.Is() should find the wrapped sentinel error")
	}
}

func TestErrorCodes(t *testing.T) {
	codes := []string{
		ErrCodeKeyNotFound,
		ErrCodeAuthFailed,
		ErrCodeAccessDenied,
		ErrCodeInvalidPolicy,
		ErrCodeEncryptionFailed,
		ErrCodeDecryptionFailed,
		ErrCodeIntegrityFailed,
		ErrCodeInvalidManifest,
	}
	for _, code := range codes {
		if code == "" {
			t.Errorf("error code constant is empty")
		}
	}
}
