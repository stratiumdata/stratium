package encryption

import (
	"testing"
)

func TestParseAlgorithm(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    Algorithm
		wantErr bool
	}{
		// KEM algorithms
		{
			name:    "Parse KYBER512",
			input:   "KYBER512",
			want:    KYBER512,
			wantErr: false,
		},
		{
			name:    "Parse KYBER768",
			input:   "KYBER768",
			want:    KYBER768,
			wantErr: false,
		},
		{
			name:    "Parse KYBER1024",
			input:   "KYBER1024",
			want:    KYBER1024,
			wantErr: false,
		},
		// RSA algorithms
		{
			name:    "Parse RSA2048",
			input:   "RSA2048",
			want:    RSA2048,
			wantErr: false,
		},
		{
			name:    "Parse RSA3072",
			input:   "RSA3072",
			want:    RSA3072,
			wantErr: false,
		},
		{
			name:    "Parse RSA4096",
			input:   "RSA4096",
			want:    RSA4096,
			wantErr: false,
		},
		// ECC algorithms
		{
			name:    "Parse P256",
			input:   "P256",
			want:    ECC_P256,
			wantErr: false,
		},
		{
			name:    "Parse P384",
			input:   "P384",
			want:    ECC_P384,
			wantErr: false,
		},
		{
			name:    "Parse P521",
			input:   "P521",
			want:    ECC_P521,
			wantErr: false,
		},
		// Invalid algorithms
		{
			name:    "Invalid algorithm",
			input:   "INVALID",
			want:    "",
			wantErr: true,
		},
		{
			name:    "Empty string",
			input:   "",
			want:    "",
			wantErr: true,
		},
		{
			name:    "Lowercase algorithm",
			input:   "kyber512",
			want:    "",
			wantErr: true,
		},
		{
			name:    "Mixed case algorithm",
			input:   "Kyber512",
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseAlgorithm(tt.input)

			if (err != nil) != tt.wantErr {
				t.Errorf("ParseAlgorithm() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseAlgorithm() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAlgorithmConstants(t *testing.T) {
	// Test that all algorithm constants are defined
	algorithms := []Algorithm{
		KYBER512,
		KYBER768,
		KYBER1024,
		RSA2048,
		RSA3072,
		RSA4096,
		ECC_P256,
		ECC_P384,
		ECC_P521,
	}

	for _, alg := range algorithms {
		if alg == "" {
			t.Errorf("Algorithm constant is empty")
		}

		// Test that each algorithm can be parsed back
		parsed, err := ParseAlgorithm(string(alg))
		if err != nil {
			t.Errorf("Failed to parse algorithm %s: %v", alg, err)
		}

		if parsed != alg {
			t.Errorf("Parsed algorithm %v doesn't match original %v", parsed, alg)
		}
	}
}

func TestAlgorithmString(t *testing.T) {
	tests := []struct {
		alg  Algorithm
		want string
	}{
		{KYBER512, "KYBER512"},
		{KYBER768, "KYBER768"},
		{KYBER1024, "KYBER1024"},
		{RSA2048, "RSA2048"},
		{RSA3072, "RSA3072"},
		{RSA4096, "RSA4096"},
		{ECC_P256, "P256"},
		{ECC_P384, "P384"},
		{ECC_P521, "P521"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if string(tt.alg) != tt.want {
				t.Errorf("Algorithm string = %v, want %v", tt.alg, tt.want)
			}
		})
	}
}

// Benchmark tests
func BenchmarkParseAlgorithm_Valid(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = ParseAlgorithm("KYBER768")
	}
}

func BenchmarkParseAlgorithm_Invalid(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = ParseAlgorithm("INVALID")
	}
}
