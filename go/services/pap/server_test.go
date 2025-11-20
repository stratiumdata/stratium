package pap

import (
	"testing"

	"github.com/google/uuid"
)

func TestParseUUID(t *testing.T) {
	server := &Server{}

	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{
			name:    "Valid UUID",
			input:   "123e4567-e89b-12d3-a456-426614174000",
			wantErr: false,
		},
		{
			name:    "Invalid UUID",
			input:   "invalid-uuid",
			wantErr: true,
		},
		{
			name:    "Empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "UUID without hyphens",
			input:   "123e4567e89b12d3a456426614174000",
			wantErr: false, // Go's UUID parser actually accepts this format
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := server.parseUUID(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error but got none")
				}
				return
			}

			if err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if result == uuid.Nil {
				t.Error("Expected non-nil UUID")
			}

			// Verify the parsed UUID matches the input
			expectedUUID, _ := uuid.Parse(tt.input)
			if result != expectedUUID {
				t.Errorf("Expected UUID %v, got %v", expectedUUID, result)
			}
		})
	}
}

func TestParseUUID_RoundTrip(t *testing.T) {
	server := &Server{}

	// Generate a UUID and verify round-trip parsing
	originalUUID := uuid.New()
	uuidString := originalUUID.String()

	parsedUUID, err := server.parseUUID(uuidString)
	if err != nil {
		t.Fatalf("Failed to parse valid UUID: %v", err)
	}

	if parsedUUID != originalUUID {
		t.Errorf("Round-trip failed: expected %v, got %v", originalUUID, parsedUUID)
	}
}

func BenchmarkParseUUID(b *testing.B) {
	server := &Server{}
	validUUID := "123e4567-e89b-12d3-a456-426614174000"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := server.parseUUID(validUUID)
		if err != nil {
			b.Fatal(err)
		}
	}
}
