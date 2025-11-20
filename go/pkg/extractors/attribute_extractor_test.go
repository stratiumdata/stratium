package extractors

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"stratium/pkg/models"
)

func TestExtractAttributeKeyValue(t *testing.T) {
	tests := []struct {
		name         string
		attributeURI string
		wantKey      string
		wantValue    string
		wantErr      bool
	}{
		{
			name:         "Standard classification attribute",
			attributeURI: "http://example.com/attr/classification/value/secret",
			wantKey:      "classification",
			wantValue:    "secret",
			wantErr:      false,
		},
		{
			name:         "Classification with top-secret value",
			attributeURI: "http://example.com/attr/classification/value/top-secret",
			wantKey:      "classification",
			wantValue:    "top-secret",
			wantErr:      false,
		},
		{
			name:         "Department attribute",
			attributeURI: "http://example.com/attr/department/value/engineering",
			wantKey:      "department",
			wantValue:    "engineering",
			wantErr:      false,
		},
		{
			name:         "Multiple path segments in value",
			attributeURI: "http://example.com/attr/role/value/admin/super",
			wantKey:      "role",
			wantValue:    "admin/super",
			wantErr:      false,
		},
		{
			name:         "Trailing slash in URI",
			attributeURI: "http://example.com/attr/classification/value/secret/",
			wantKey:      "classification",
			wantValue:    "secret",
			wantErr:      false,
		},
		{
			name:         "Empty URI",
			attributeURI: "",
			wantKey:      "",
			wantValue:    "",
			wantErr:      true,
		},
		{
			name:         "URI with /value/ but no value after",
			attributeURI: "http://example.com/attr/classification/value/",
			wantKey:      "",
			wantValue:    "",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, gotValue, err := ExtractAttributeKeyValue(tt.attributeURI)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractAttributeKeyValue() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotKey != tt.wantKey {
				t.Errorf("ExtractAttributeKeyValue() key = %v, want %v", gotKey, tt.wantKey)
			}
			if gotValue != tt.wantValue {
				t.Errorf("ExtractAttributeKeyValue() value = %v, want %v", gotValue, tt.wantValue)
			}
		})
	}
}

func TestExtractAttributeName(t *testing.T) {
	tests := []struct {
		name         string
		attributeURI string
		want         string
		wantErr      bool
	}{
		{
			name:         "Classification attribute",
			attributeURI: "http://example.com/attr/classification/value/secret",
			want:         "classification",
			wantErr:      false,
		},
		{
			name:         "Department attribute",
			attributeURI: "http://example.com/attr/department/value/engineering",
			want:         "department",
			wantErr:      false,
		},
		{
			name:         "Role attribute",
			attributeURI: "http://example.com/attr/role/value/admin",
			want:         "role",
			wantErr:      false,
		},
		{
			name:         "Empty URI",
			attributeURI: "",
			want:         "",
			wantErr:      true,
		},
		{
			name:         "URI without /attr/ separator",
			attributeURI: "http://example.com/classification/value/secret",
			want:         "",
			wantErr:      true,
		},
		{
			name:         "URI without /value/ separator",
			attributeURI: "http://example.com/attr/classification/secret",
			want:         "",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractAttributeName(tt.attributeURI)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractAttributeName() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("ExtractAttributeName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractAttributesFromPolicy(t *testing.T) {
	tests := []struct {
		name    string
		policy  *models.ZtdfPolicy
		want    map[string]string
		wantErr bool
	}{
		{
			name: "Policy with multiple attributes",
			policy: &models.ZtdfPolicy{
				Body: &models.ZtdfPolicy_Body{
					DataAttributes: []*models.ZtdfPolicy_Body_Attribute{
						{
							Attribute:   "http://example.com/attr/classification/value/secret",
							DisplayName: "classification",
						},
						{
							Attribute:   "http://example.com/attr/department/value/engineering",
							DisplayName: "department",
						},
						{
							Attribute:   "http://example.com/attr/clearance/value/top-secret",
							DisplayName: "clearance",
						},
					},
				},
			},
			want: map[string]string{
				"classification": "secret",
				"department":     "engineering",
				"clearance":      "top-secret",
			},
			wantErr: false,
		},
		{
			name: "Policy with single attribute",
			policy: &models.ZtdfPolicy{
				Body: &models.ZtdfPolicy_Body{
					DataAttributes: []*models.ZtdfPolicy_Body_Attribute{
						{
							Attribute:   "http://example.com/attr/classification/value/confidential",
							DisplayName: "classification",
						},
					},
				},
			},
			want: map[string]string{
				"classification": "confidential",
			},
			wantErr: false,
		},
		{
			name: "Policy with empty display name",
			policy: &models.ZtdfPolicy{
				Body: &models.ZtdfPolicy_Body{
					DataAttributes: []*models.ZtdfPolicy_Body_Attribute{
						{
							Attribute:   "http://example.com/attr/classification/value/secret",
							DisplayName: "",
						},
						{
							Attribute:   "http://example.com/attr/department/value/engineering",
							DisplayName: "department",
						},
					},
				},
			},
			want: map[string]string{
				"classification": "secret",
				"department":     "engineering",
			},
			wantErr: false,
		},
		{
			name: "Policy with no attributes",
			policy: &models.ZtdfPolicy{
				Body: &models.ZtdfPolicy_Body{
					DataAttributes: []*models.ZtdfPolicy_Body_Attribute{},
				},
			},
			want:    map[string]string{},
			wantErr: false,
		},
		{
			name:    "Nil policy",
			policy:  nil,
			want:    nil,
			wantErr: true,
		},
		{
			name: "Policy with nil body",
			policy: &models.ZtdfPolicy{
				Body: nil,
			},
			want:    nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractAttributesFromPolicy(tt.policy)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractAttributesFromPolicy() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got) != len(tt.want) {
					t.Errorf("ExtractAttributesFromPolicy() got %d attributes, want %d", len(got), len(tt.want))
					return
				}
				for key, wantValue := range tt.want {
					if gotValue, ok := got[key]; !ok {
						t.Errorf("ExtractAttributesFromPolicy() missing key %s", key)
					} else if gotValue != wantValue {
						t.Errorf("ExtractAttributesFromPolicy() key %s = %v, want %v", key, gotValue, wantValue)
					}
				}
			}
		})
	}
}

func TestExtractResourceAttributes(t *testing.T) {
	// Create a sample policy
	policy := &models.ZtdfPolicy{
		Uuid: "test-policy-123",
		Body: &models.ZtdfPolicy_Body{
			DataAttributes: []*models.ZtdfPolicy_Body_Attribute{
				{
					Attribute:   "http://example.com/attr/classification/value/secret",
					DisplayName: "classification",
					IsDefault:   false,
				},
				{
					Attribute:   "http://example.com/attr/department/value/engineering",
					DisplayName: "department",
					IsDefault:   false,
				},
			},
		},
		TdfSpecVersion: "1.0.0",
	}

	// Marshal to JSON
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("Failed to marshal policy: %v", err)
	}

	// Encode to base64
	base64Policy := base64.StdEncoding.EncodeToString(policyJSON)

	tests := []struct {
		name         string
		base64Policy string
		want         map[string]string
		wantErr      bool
	}{
		{
			name:         "Valid base64 policy",
			base64Policy: base64Policy,
			want: map[string]string{
				"classification": "secret",
				"department":     "engineering",
			},
			wantErr: false,
		},
		{
			name:         "Invalid base64",
			base64Policy: "not-valid-base64!!!",
			want:         nil,
			wantErr:      true,
		},
		{
			name:         "Valid base64 but invalid JSON",
			base64Policy: base64.StdEncoding.EncodeToString([]byte("not json")),
			want:         nil,
			wantErr:      true,
		},
		{
			name:         "Empty string",
			base64Policy: "",
			want:         nil,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExtractResourceAttributes(tt.base64Policy)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractResourceAttributes() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got) != len(tt.want) {
					t.Errorf("ExtractResourceAttributes() got %d attributes, want %d", len(got), len(tt.want))
					return
				}
				for key, wantValue := range tt.want {
					if gotValue, ok := got[key]; !ok {
						t.Errorf("ExtractResourceAttributes() missing key %s", key)
					} else if gotValue != wantValue {
						t.Errorf("ExtractResourceAttributes() key %s = %v, want %v", key, gotValue, wantValue)
					}
				}
			}
		})
	}
}

// Benchmark tests
func BenchmarkExtractAttributeKeyValue(b *testing.B) {
	uri := "http://example.com/attr/classification/value/secret"
	for i := 0; i < b.N; i++ {
		_, _, _ = ExtractAttributeKeyValue(uri)
	}
}

func BenchmarkExtractAttributesFromPolicy(b *testing.B) {
	policy := &models.ZtdfPolicy{
		Body: &models.ZtdfPolicy_Body{
			DataAttributes: []*models.ZtdfPolicy_Body_Attribute{
				{
					Attribute:   "http://example.com/attr/classification/value/secret",
					DisplayName: "classification",
				},
				{
					Attribute:   "http://example.com/attr/department/value/engineering",
					DisplayName: "department",
				},
				{
					Attribute:   "http://example.com/attr/clearance/value/top-secret",
					DisplayName: "clearance",
				},
			},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = ExtractAttributesFromPolicy(policy)
	}
}
