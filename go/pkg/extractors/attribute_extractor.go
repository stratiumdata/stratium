package extractors

import (
	"encoding/base64"
	"fmt"
	"strings"

	"stratium/pkg/models"

	"google.golang.org/protobuf/encoding/protojson"
)

// ExtractResourceAttributes extracts resource attributes from a ZTDF policy manifest
// The policy is expected to be base64-encoded JSON containing ZtdfPolicy protobuf structure
func ExtractResourceAttributes(base64Policy string) (map[string]string, error) {
	// Decode base64
	policyBytes, err := base64.StdEncoding.DecodeString(base64Policy)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 policy: %w", err)
	} else if len(policyBytes) == 0 {
		return nil, fmt.Errorf("policy is empty")
	}

	// Parse JSON into ZtdfPolicy structure
	var policy models.ZtdfPolicy
	if err := protojson.Unmarshal(policyBytes, &policy); err != nil {
		return nil, fmt.Errorf("failed to unmarshal policy JSON: %w", err)
	}

	// Extract attributes from policy body
	return ExtractAttributesFromPolicy(&policy)
}

// ExtractAttributesFromPolicy extracts attributes from a ZtdfPolicy protobuf message
func ExtractAttributesFromPolicy(policy *models.ZtdfPolicy) (map[string]string, error) {
	if policy == nil {
		return nil, fmt.Errorf("policy is nil")
	}

	if policy.Body == nil {
		return nil, fmt.Errorf("policy body is nil")
	}

	attributes := make(map[string]string)

	// Iterate through attributes
	for _, attr := range policy.Body.DataAttributes {
		// Extract value from attribute URI
		key, value, err := ExtractAttributeKeyValue(attr.Attribute)
		if err != nil {
			// Log warning but continue processing other attributes
			// In production, you might want to use a proper logger
			continue
		}

		// Use display_name as key, extracted value as value
		attributes[key] = value
	}

	return attributes, nil
}

// ExtractAttributeValue extracts the value portion from a ZTDF attribute URI
// Option A: Extract from URI pattern like "http://example.com/attr/classification/value/secret"
// Returns the last segment after "/value/" in the URI
func ExtractAttributeKeyValue(attributeURI string) (string, string, error) {
	if attributeURI == "" {
		return "", "", fmt.Errorf("attribute URI is empty")
	}

	// Look for "/value/" segment in the URI
	valueSeparator := "/value/"
	valueIndex := strings.LastIndex(attributeURI, valueSeparator)

	// Extract everything before "/value/"
	key := attributeURI[:valueIndex]

	// Find last "/" in the current key string
	keyIndex := strings.LastIndex(key, "/")

	// Get the last section of the key string
	key = key[keyIndex+len("/"):]

	// Extract everything after "/value/"
	value := attributeURI[valueIndex+len(valueSeparator):]

	// Trim any trailing slashes
	value = strings.TrimSuffix(value, "/")

	if value == "" {
		return "", "", fmt.Errorf("extracted value is empty from URI: %s", attributeURI)
	}

	return key, value, nil
}

// ExtractAttributeName extracts the attribute name from a ZTDF attribute URI
// For URI like "http://example.com/attr/classification/value/secret", returns "classification"
func ExtractAttributeName(attributeURI string) (string, error) {
	if attributeURI == "" {
		return "", fmt.Errorf("attribute URI is empty")
	}

	// Look for pattern "/attr/{name}/value/"
	attrSeparator := "/attr/"
	valueSeparator := "/value/"

	attrIndex := strings.Index(attributeURI, attrSeparator)
	valueIndex := strings.Index(attributeURI, valueSeparator)

	if attrIndex == -1 || valueIndex == -1 || valueIndex <= attrIndex {
		return "", fmt.Errorf("could not extract attribute name from URI: %s", attributeURI)
	}

	// Extract the segment between "/attr/" and "/value/"
	startIndex := attrIndex + len(attrSeparator)
	name := attributeURI[startIndex:valueIndex]

	if name == "" {
		return "", fmt.Errorf("extracted attribute name is empty from URI: %s", attributeURI)
	}

	return name, nil
}
