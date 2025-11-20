package ztdf

import (
	"encoding/base64"
	"testing"

	"github.com/stratiumdata/go-sdk/gen/models"
	"google.golang.org/protobuf/encoding/protojson"
)

// ===== CreatePolicy Tests =====

func TestCreatePolicy(t *testing.T) {
	keyAccessURL := "kas.example.com:50053"
	attributes := []Attribute{
		{
			URI:         "http://example.com/attr/classification/value/secret",
			DisplayName: "Classification: Secret",
			IsDefault:   true,
		},
		{
			URI:         "http://example.com/attr/department/value/engineering",
			DisplayName: "Department: Engineering",
			IsDefault:   false,
		},
	}

	policy := CreatePolicy(keyAccessURL, attributes)

	// Verify policy is not nil
	if policy == nil {
		t.Fatal("CreatePolicy() returned nil")
	}

	// Verify UUID is set
	if policy.Uuid == "" {
		t.Error("CreatePolicy() did not set UUID")
	}

	// Verify TDF spec version
	if policy.TdfSpecVersion != TDFSpecVersion {
		t.Errorf("CreatePolicy() TDFSpecVersion = %s, want %s", policy.TdfSpecVersion, TDFSpecVersion)
	}

	// Verify body exists
	if policy.Body == nil {
		t.Fatal("CreatePolicy() body is nil")
	}

	// Verify data attributes
	if len(policy.Body.DataAttributes) != len(attributes) {
		t.Errorf("CreatePolicy() data attributes count = %d, want %d", len(policy.Body.DataAttributes), len(attributes))
	}

	// Verify each attribute
	for i, attr := range attributes {
		if policy.Body.DataAttributes[i].Attribute != attr.URI {
			t.Errorf("CreatePolicy() attribute[%d].Attribute = %s, want %s", i, policy.Body.DataAttributes[i].Attribute, attr.URI)
		}
		if policy.Body.DataAttributes[i].DisplayName != attr.DisplayName {
			t.Errorf("CreatePolicy() attribute[%d].DisplayName = %s, want %s", i, policy.Body.DataAttributes[i].DisplayName, attr.DisplayName)
		}
		if policy.Body.DataAttributes[i].IsDefault != attr.IsDefault {
			t.Errorf("CreatePolicy() attribute[%d].IsDefault = %v, want %v", i, policy.Body.DataAttributes[i].IsDefault, attr.IsDefault)
		}
		if policy.Body.DataAttributes[i].Kas_URL != keyAccessURL {
			t.Errorf("CreatePolicy() attribute[%d].Kas_URL = %s, want %s", i, policy.Body.DataAttributes[i].Kas_URL, keyAccessURL)
		}
	}
}

func TestCreatePolicy_EmptyAttributes(t *testing.T) {
	keyAccessURL := "kas.example.com:50053"
	policy := CreatePolicy(keyAccessURL, []Attribute{})

	if policy == nil {
		t.Fatal("CreatePolicy() returned nil")
	}

	if len(policy.Body.DataAttributes) != 0 {
		t.Errorf("CreatePolicy() expected 0 attributes, got %d", len(policy.Body.DataAttributes))
	}
}

// ===== CreateClassificationPolicy Tests =====

func TestCreateClassificationPolicy(t *testing.T) {
	tests := []struct {
		name           string
		keyAccessURL   string
		classification string
		expectedURI    string
		expectedDisplay string
	}{
		{
			name:            "secret classification",
			keyAccessURL:    "kas.example.com:50053",
			classification:  "secret",
			expectedURI:     "http://example.com/attr/classification/value/secret",
			expectedDisplay: "Classification: secret",
		},
		{
			name:            "confidential classification",
			keyAccessURL:    "localhost:50053",
			classification:  "confidential",
			expectedURI:     "http://example.com/attr/classification/value/confidential",
			expectedDisplay: "Classification: confidential",
		},
		{
			name:            "public classification",
			keyAccessURL:    "kas.stratium.io:443",
			classification:  "public",
			expectedURI:     "http://example.com/attr/classification/value/public",
			expectedDisplay: "Classification: public",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := CreateClassificationPolicy(tt.keyAccessURL, tt.classification)

			if policy == nil {
				t.Fatal("CreateClassificationPolicy() returned nil")
			}

			if policy.Body == nil {
				t.Fatal("CreateClassificationPolicy() body is nil")
			}

			if len(policy.Body.DataAttributes) != 1 {
				t.Errorf("CreateClassificationPolicy() expected 1 attribute, got %d", len(policy.Body.DataAttributes))
			}

			attr := policy.Body.DataAttributes[0]
			if attr.Attribute != tt.expectedURI {
				t.Errorf("CreateClassificationPolicy() attribute = %s, want %s", attr.Attribute, tt.expectedURI)
			}

			if attr.DisplayName != tt.expectedDisplay {
				t.Errorf("CreateClassificationPolicy() displayName = %s, want %s", attr.DisplayName, tt.expectedDisplay)
			}

			if !attr.IsDefault {
				t.Error("CreateClassificationPolicy() attribute should be default")
			}

			if attr.Kas_URL != tt.keyAccessURL {
				t.Errorf("CreateClassificationPolicy() kas_url = %s, want %s", attr.Kas_URL, tt.keyAccessURL)
			}
		})
	}
}

// ===== CreateMultiAttributePolicy Tests =====

func TestCreateMultiAttributePolicy(t *testing.T) {
	keyAccessURL := "kas.example.com:50053"
	attributeValues := map[string]string{
		"classification": "secret",
		"department":     "engineering",
		"project":        "stratium",
	}

	policy := CreateMultiAttributePolicy(keyAccessURL, attributeValues)

	if policy == nil {
		t.Fatal("CreateMultiAttributePolicy() returned nil")
	}

	if policy.Body == nil {
		t.Fatal("CreateMultiAttributePolicy() body is nil")
	}

	if len(policy.Body.DataAttributes) != len(attributeValues) {
		t.Errorf("CreateMultiAttributePolicy() expected %d attributes, got %d", len(attributeValues), len(policy.Body.DataAttributes))
	}

	// Verify all attributes are present (order may vary due to map iteration)
	foundAttrs := make(map[string]bool)
	hasDefault := false

	for _, attr := range policy.Body.DataAttributes {
		foundAttrs[attr.Attribute] = true
		if attr.IsDefault {
			hasDefault = true
		}
		if attr.Kas_URL != keyAccessURL {
			t.Errorf("CreateMultiAttributePolicy() kas_url = %s, want %s", attr.Kas_URL, keyAccessURL)
		}
	}

	// Verify at least one attribute is marked as default
	if !hasDefault {
		t.Error("CreateMultiAttributePolicy() should have at least one default attribute")
	}

	// Verify all expected attributes are present
	for attrType, value := range attributeValues {
		expectedURI := "http://example.com/attr/" + attrType + "/value/" + value
		if !foundAttrs[expectedURI] {
			t.Errorf("CreateMultiAttributePolicy() missing attribute: %s", expectedURI)
		}
	}
}

func TestCreateMultiAttributePolicy_EmptyMap(t *testing.T) {
	keyAccessURL := "kas.example.com:50053"
	policy := CreateMultiAttributePolicy(keyAccessURL, map[string]string{})

	if policy == nil {
		t.Fatal("CreateMultiAttributePolicy() returned nil")
	}

	if len(policy.Body.DataAttributes) != 0 {
		t.Errorf("CreateMultiAttributePolicy() expected 0 attributes, got %d", len(policy.Body.DataAttributes))
	}
}

// ===== EncodePolicyToBase64 Tests =====

func TestEncodePolicyToBase64(t *testing.T) {
	policy := CreateClassificationPolicy("kas.example.com:50053", "secret")

	policyBase64, err := EncodePolicyToBase64(policy)
	if err != nil {
		t.Fatalf("EncodePolicyToBase64() error: %v", err)
	}

	if policyBase64 == "" {
		t.Fatal("EncodePolicyToBase64() returned empty string")
	}

	// Verify it's valid base64
	decoded, err := base64.StdEncoding.DecodeString(policyBase64)
	if err != nil {
		t.Fatalf("EncodePolicyToBase64() produced invalid base64: %v", err)
	}

	// Verify it's valid JSON that can be unmarshaled
	decodedPolicy := &models.ZtdfPolicy{}
	if err := protojson.Unmarshal(decoded, decodedPolicy); err != nil {
		t.Fatalf("EncodePolicyToBase64() produced invalid protobuf JSON: %v", err)
	}

	// Verify the decoded policy matches the original
	if decodedPolicy.Uuid != policy.Uuid {
		t.Errorf("EncodePolicyToBase64() decoded UUID = %s, want %s", decodedPolicy.Uuid, policy.Uuid)
	}
}

// Note: EncodePolicyToBase64 with nil policy is handled gracefully by protobuf
// marshaling, so we don't test for error in this case

// ===== ParsePolicyFromManifest Tests =====

func TestParsePolicyFromManifest(t *testing.T) {
	// Create a policy and encode it
	originalPolicy := CreateClassificationPolicy("kas.example.com:50053", "secret")
	policyBase64, err := EncodePolicyToBase64(originalPolicy)
	if err != nil {
		t.Fatalf("Failed to encode policy: %v", err)
	}

	// Create a manifest with the policy
	manifest := &models.Manifest{
		EncryptionInformation: &models.EncryptionInformation{
			Policy: policyBase64,
		},
	}

	// Parse the policy
	parsedPolicy, err := ParsePolicyFromManifest(manifest)
	if err != nil {
		t.Fatalf("ParsePolicyFromManifest() error: %v", err)
	}

	// Verify parsed policy matches original
	if parsedPolicy.Uuid != originalPolicy.Uuid {
		t.Errorf("ParsePolicyFromManifest() UUID = %s, want %s", parsedPolicy.Uuid, originalPolicy.Uuid)
	}

	if parsedPolicy.TdfSpecVersion != originalPolicy.TdfSpecVersion {
		t.Errorf("ParsePolicyFromManifest() TdfSpecVersion = %s, want %s", parsedPolicy.TdfSpecVersion, originalPolicy.TdfSpecVersion)
	}

	if len(parsedPolicy.Body.DataAttributes) != len(originalPolicy.Body.DataAttributes) {
		t.Errorf("ParsePolicyFromManifest() attributes count = %d, want %d", len(parsedPolicy.Body.DataAttributes), len(originalPolicy.Body.DataAttributes))
	}
}

func TestParsePolicyFromManifest_NilManifest(t *testing.T) {
	_, err := ParsePolicyFromManifest(nil)
	if err == nil {
		t.Error("ParsePolicyFromManifest() expected error for nil manifest, got nil")
	}
}

func TestParsePolicyFromManifest_MissingEncryptionInfo(t *testing.T) {
	manifest := &models.Manifest{}
	_, err := ParsePolicyFromManifest(manifest)
	if err == nil {
		t.Error("ParsePolicyFromManifest() expected error for missing encryption info, got nil")
	}
}

func TestParsePolicyFromManifest_InvalidBase64(t *testing.T) {
	manifest := &models.Manifest{
		EncryptionInformation: &models.EncryptionInformation{
			Policy: "not-valid-base64!!!",
		},
	}

	_, err := ParsePolicyFromManifest(manifest)
	if err == nil {
		t.Error("ParsePolicyFromManifest() expected error for invalid base64, got nil")
	}
}

func TestParsePolicyFromManifest_InvalidJSON(t *testing.T) {
	invalidJSON := base64.StdEncoding.EncodeToString([]byte("not valid JSON"))
	manifest := &models.Manifest{
		EncryptionInformation: &models.EncryptionInformation{
			Policy: invalidJSON,
		},
	}

	_, err := ParsePolicyFromManifest(manifest)
	if err == nil {
		t.Error("ParsePolicyFromManifest() expected error for invalid JSON, got nil")
	}
}

// ===== ValidatePolicy Tests =====

func TestValidatePolicy(t *testing.T) {
	tests := []struct {
		name    string
		policy  *models.ZtdfPolicy
		wantErr bool
	}{
		{
			name:    "valid policy",
			policy:  CreateClassificationPolicy("kas.example.com:50053", "secret"),
			wantErr: false,
		},
		{
			name:    "nil policy",
			policy:  nil,
			wantErr: true,
		},
		{
			name: "missing UUID",
			policy: &models.ZtdfPolicy{
				Uuid: "",
				Body: &models.ZtdfPolicy_Body{
					DataAttributes: []*models.ZtdfPolicy_Body_Attribute{
						{
							Attribute: "http://example.com/attr/test",
							Kas_URL:   "kas.example.com:50053",
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "missing body",
			policy: &models.ZtdfPolicy{
				Uuid: "test-uuid",
				Body: nil,
			},
			wantErr: true,
		},
		{
			name: "empty data attributes",
			policy: &models.ZtdfPolicy{
				Uuid: "test-uuid",
				Body: &models.ZtdfPolicy_Body{
					DataAttributes: []*models.ZtdfPolicy_Body_Attribute{},
				},
			},
			wantErr: true,
		},
		{
			name: "missing attribute URI",
			policy: &models.ZtdfPolicy{
				Uuid: "test-uuid",
				Body: &models.ZtdfPolicy_Body{
					DataAttributes: []*models.ZtdfPolicy_Body_Attribute{
						{
							Attribute: "",
							Kas_URL:   "kas.example.com:50053",
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "missing KAS URL",
			policy: &models.ZtdfPolicy{
				Uuid: "test-uuid",
				Body: &models.ZtdfPolicy_Body{
					DataAttributes: []*models.ZtdfPolicy_Body_Attribute{
						{
							Attribute: "http://example.com/attr/test",
							Kas_URL:   "",
						},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePolicy(tt.policy)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePolicy() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// ===== GetPolicyInfo Tests =====

func TestGetPolicyInfo(t *testing.T) {
	// Create a policy
	policy := CreateMultiAttributePolicy("kas.example.com:50053", map[string]string{
		"classification": "secret",
		"department":     "engineering",
	})

	// Encode policy to base64
	policyBase64, err := EncodePolicyToBase64(policy)
	if err != nil {
		t.Fatalf("Failed to encode policy: %v", err)
	}

	// Create a TrustedDataObject with manifest
	tdo := &TrustedDataObject{
		Manifest: &models.Manifest{
			EncryptionInformation: &models.EncryptionInformation{
				Policy: policyBase64,
				Method: &models.EncryptionInformation_Method{
					Algorithm: AlgorithmAES256GCM,
				},
				IntegrityInformation: &models.EncryptionInformation_IntegrityInformation{
					SegmentHashAlg: AlgorithmGMAC,
				},
			},
		},
	}

	// Get policy info
	info, err := GetPolicyInfo(tdo)
	if err != nil {
		t.Fatalf("GetPolicyInfo() error: %v", err)
	}

	// Verify policy info
	if info.UUID != policy.Uuid {
		t.Errorf("GetPolicyInfo() UUID = %s, want %s", info.UUID, policy.Uuid)
	}

	if info.TDFSpecVersion != policy.TdfSpecVersion {
		t.Errorf("GetPolicyInfo() TDFSpecVersion = %s, want %s", info.TDFSpecVersion, policy.TdfSpecVersion)
	}

	if info.EncryptionMethod != AlgorithmAES256GCM {
		t.Errorf("GetPolicyInfo() EncryptionMethod = %s, want %s", info.EncryptionMethod, AlgorithmAES256GCM)
	}

	if info.IntegrityMethod != AlgorithmGMAC {
		t.Errorf("GetPolicyInfo() IntegrityMethod = %s, want %s", info.IntegrityMethod, AlgorithmGMAC)
	}

	if info.KeyAccessURL != "kas.example.com:50053" {
		t.Errorf("GetPolicyInfo() KeyAccessURL = %s, want kas.example.com:50053", info.KeyAccessURL)
	}

	if len(info.DataAttributes) != 2 {
		t.Errorf("GetPolicyInfo() expected 2 attributes, got %d", len(info.DataAttributes))
	}
}

func TestGetPolicyInfo_NilTDO(t *testing.T) {
	tdo := &TrustedDataObject{
		Manifest: nil,
	}

	_, err := GetPolicyInfo(tdo)
	if err == nil {
		t.Error("GetPolicyInfo() expected error for nil manifest, got nil")
	}
}

func TestGetPolicyInfo_InvalidPolicy(t *testing.T) {
	tdo := &TrustedDataObject{
		Manifest: &models.Manifest{
			EncryptionInformation: &models.EncryptionInformation{
				Policy: "invalid-base64!!!",
			},
		},
	}

	_, err := GetPolicyInfo(tdo)
	if err == nil {
		t.Error("GetPolicyInfo() expected error for invalid policy, got nil")
	}
}

// ===== Integration Tests =====

func TestPolicyRoundTrip(t *testing.T) {
	// Create original policy
	original := CreateMultiAttributePolicy("kas.example.com:50053", map[string]string{
		"classification": "top-secret",
		"department":     "r&d",
		"project":        "quantum",
	})

	// Validate original
	if err := ValidatePolicy(original); err != nil {
		t.Fatalf("Original policy is invalid: %v", err)
	}

	// Encode to base64
	encoded, err := EncodePolicyToBase64(original)
	if err != nil {
		t.Fatalf("Failed to encode policy: %v", err)
	}

	// Create manifest
	manifest := &models.Manifest{
		EncryptionInformation: &models.EncryptionInformation{
			Policy: encoded,
		},
	}

	// Parse from manifest
	decoded, err := ParsePolicyFromManifest(manifest)
	if err != nil {
		t.Fatalf("Failed to parse policy: %v", err)
	}

	// Validate decoded
	if err := ValidatePolicy(decoded); err != nil {
		t.Fatalf("Decoded policy is invalid: %v", err)
	}

	// Verify UUID matches
	if decoded.Uuid != original.Uuid {
		t.Errorf("Round trip: UUID = %s, want %s", decoded.Uuid, original.Uuid)
	}

	// Verify attribute count matches
	if len(decoded.Body.DataAttributes) != len(original.Body.DataAttributes) {
		t.Errorf("Round trip: attributes count = %d, want %d", len(decoded.Body.DataAttributes), len(original.Body.DataAttributes))
	}
}
