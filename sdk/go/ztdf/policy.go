package ztdf

import (
	"encoding/base64"
	"fmt"

	"github.com/google/uuid"
	"github.com/stratiumdata/go-sdk/gen/models"
	"google.golang.org/protobuf/encoding/protojson"
)

// CreatePolicy creates a ZTDF policy from attributes.
//
// Example:
//
//	policy := ztdf.CreatePolicy("kas.example.com:50053", []ztdf.Attribute{
//	    {
//	        URI:         "http://example.com/attr/classification/value/secret",
//	        DisplayName: "Classification: Secret",
//	        IsDefault:   true,
//	    },
//	})
func CreatePolicy(keyAccessURL string, attributes []Attribute) *models.ZtdfPolicy {
	dataAttrs := make([]*models.ZtdfPolicy_Body_Attribute, len(attributes))
	for i, attr := range attributes {
		dataAttrs[i] = &models.ZtdfPolicy_Body_Attribute{
			Attribute:   attr.URI,
			DisplayName: attr.DisplayName,
			IsDefault:   attr.IsDefault,
			Kas_URL:     keyAccessURL,
		}
	}

	return &models.ZtdfPolicy{
		Uuid: uuid.New().String(),
		Body: &models.ZtdfPolicy_Body{
			DataAttributes: dataAttrs,
		},
		TdfSpecVersion: TDFSpecVersion,
	}
}

// CreateClassificationPolicy creates a policy with standard classification levels.
//
// Example:
//
//	policy := ztdf.CreateClassificationPolicy("kas.example.com:50053", "secret")
func CreateClassificationPolicy(keyAccessURL, classification string) *models.ZtdfPolicy {
	displayName := fmt.Sprintf("Classification: %s", classification)
	uri := fmt.Sprintf(ClassificationURITemplate, classification)

	return CreatePolicy(keyAccessURL, []Attribute{
		{
			URI:         uri,
			DisplayName: displayName,
			IsDefault:   true,
		},
	})
}

// CreateMultiAttributePolicy creates a policy with multiple attributes.
//
// Example:
//
//	policy := ztdf.CreateMultiAttributePolicy("kas.example.com:50053", map[string]string{
//	    "classification": "secret",
//	    "department":     "engineering",
//	    "project":        "stratium",
//	})
func CreateMultiAttributePolicy(keyAccessURL string, attributeValues map[string]string) *models.ZtdfPolicy {
	attributes := make([]Attribute, 0, len(attributeValues))
	isFirst := true

	for attrType, value := range attributeValues {
		attributes = append(attributes, Attribute{
			URI:         fmt.Sprintf(AttributeURITemplate, attrType, value),
			DisplayName: fmt.Sprintf("%s: %s", attrType, value),
			IsDefault:   isFirst,
		})
		isFirst = false
	}

	return CreatePolicy(keyAccessURL, attributes)
}

// ParsePolicyFromManifest extracts and parses the policy from a ZTDF manifest.
//
// Example:
//
//	policy, err := ztdf.ParsePolicyFromManifest(tdo.Manifest)
//	if err != nil {
//	    log.Fatal(err)
//	}
func ParsePolicyFromManifest(manifest *models.Manifest) (*models.ZtdfPolicy, error) {
	if manifest == nil || manifest.EncryptionInformation == nil {
		return nil, fmt.Errorf("invalid manifest: missing encryption information")
	}

	policyBase64 := manifest.EncryptionInformation.Policy
	policyJSON, err := base64.StdEncoding.DecodeString(policyBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode policy: %w", err)
	}

	policy := &models.ZtdfPolicy{}
	if err := protojson.Unmarshal(policyJSON, policy); err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy: %w", err)
	}

	return policy, nil
}

// GetPolicyInfo extracts human-readable policy information from a ZTDF.
//
// Example:
//
//	info, err := ztdf.GetPolicyInfo(tdo)
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Policy UUID: %s\n", info.UUID)
//	for _, attr := range info.DataAttributes {
//	    fmt.Printf("  - %s: %s\n", attr.DisplayName, attr.Attribute)
//	}
func GetPolicyInfo(tdo *TrustedDataObject) (*PolicyInfo, error) {
	policy, err := ParsePolicyFromManifest(tdo.Manifest)
	if err != nil {
		return nil, err
	}

	info := &PolicyInfo{
		UUID:           policy.Uuid,
		TDFSpecVersion: policy.TdfSpecVersion,
	}

	if policy.Body != nil {
		info.DataAttributes = make([]PolicyAttribute, len(policy.Body.DataAttributes))
		for i, attr := range policy.Body.DataAttributes {
			info.DataAttributes[i] = PolicyAttribute{
				Attribute:   attr.Attribute,
				DisplayName: attr.DisplayName,
				IsDefault:   attr.IsDefault,
				KasURL:      attr.Kas_URL,
			}
			if i == 0 {
				info.KeyAccessURL = attr.Kas_URL
			}
		}
	}

	if tdo.Manifest.EncryptionInformation != nil {
		if tdo.Manifest.EncryptionInformation.Method != nil {
			info.EncryptionMethod = tdo.Manifest.EncryptionInformation.Method.Algorithm
		}
		if tdo.Manifest.EncryptionInformation.IntegrityInformation != nil {
			info.IntegrityMethod = tdo.Manifest.EncryptionInformation.IntegrityInformation.SegmentHashAlg
		}
	}

	return info, nil
}

// EncodePolicyToBase64 encodes a policy to base64-encoded JSON.
//
// Example:
//
//	policyBase64, err := ztdf.EncodePolicyToBase64(policy)
//	if err != nil {
//	    log.Fatal(err)
//	}
func EncodePolicyToBase64(policy *models.ZtdfPolicy) (string, error) {
	policyJSON, err := protojson.Marshal(policy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal policy: %w", err)
	}
	return base64.StdEncoding.EncodeToString(policyJSON), nil
}

// ValidatePolicy performs basic validation on a ZTDF policy.
//
// Example:
//
//	if err := ztdf.ValidatePolicy(policy); err != nil {
//	    log.Fatal("Invalid policy:", err)
//	}
func ValidatePolicy(policy *models.ZtdfPolicy) error {
	if policy == nil {
		return fmt.Errorf("policy cannot be nil")
	}
	if policy.Uuid == "" {
		return fmt.Errorf("policy UUID is required")
	}
	if policy.Body == nil {
		return fmt.Errorf("policy body is required")
	}
	if len(policy.Body.DataAttributes) == 0 {
		return fmt.Errorf("policy must have at least one data attribute")
	}
	for i, attr := range policy.Body.DataAttributes {
		if attr.Attribute == "" {
			return fmt.Errorf("data attribute %d: attribute URI is required", i)
		}
		if attr.Kas_URL == "" {
			return fmt.Errorf("data attribute %d: KAS URL is required", i)
		}
	}
	return nil
}
