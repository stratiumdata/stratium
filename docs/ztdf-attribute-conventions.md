# ZTDF Attribute URI Conventions

## Overview

The Zero Trust Data Format (ZTDF) standard defines a structured approach to data protection using attribute-based access control. This document defines the attribute URI conventions and naming standards for ZTDF integration with the Stratium platform.

## ZTDF Attribute URI Structure

ZTDF attributes follow a hierarchical URI structure for namespacing and organization:

```
urn:ztdf:<domain>:<attribute_type>:<attribute_name>
```

### Components

- **`urn:ztdf`**: Fixed prefix identifying ZTDF namespace
- **`domain`**: Organization or standard domain (e.g., `nato`, `dod`, `commercial`)
- **`attribute_type`**: Category of attribute (e.g., `classification`, `handling`, `dissemination`)
- **`attribute_name`**: Specific attribute name

### Examples

```
urn:ztdf:nato:classification:secret
urn:ztdf:nato:handling:nato-releasable
urn:ztdf:dod:classification:top-secret
urn:ztdf:commercial:sensitivity:confidential
```

## Standard Attribute Types

### 1. Classification Attributes

**URI Pattern**: `urn:ztdf:<domain>:classification:<level>`

**Purpose**: Define the security classification level of data or user clearance

**Common Levels** (NATO/DoD):
- `unclassified`
- `restricted`
- `confidential`
- `secret`
- `top-secret`

**Commercial Equivalents**:
- `public`
- `internal`
- `confidential`
- `restricted`
- `highly-confidential`

**Hierarchy**: Higher classifications can access lower classifications (e.g., SECRET can access CONFIDENTIAL and RESTRICTED)

**Example Usage**:
```json
{
  "subject_attributes": {
    "sub": "alice@nato.int",
    "classification": "urn:ztdf:nato:classification:secret"
  },
  "resource_attributes": {
    "name": "operation-report.ztdf",
    "classification": "urn:ztdf:nato:classification:confidential"
  },
  "action": "read"
}
```

### 2. Handling Attributes

**URI Pattern**: `urn:ztdf:<domain>:handling:<code>`

**Purpose**: Define special handling requirements for data

**Common Codes**:
- `nato-releasable` - Releasable to NATO partners
- `noforn` - No foreign nationals
- `orcon` - Originator controlled
- `nocontract` - No contractors
- `propin` - Proprietary information

**Example Usage**:
```json
{
  "subject_attributes": {
    "sub": "bob@contractor.com",
    "clearance": "urn:ztdf:dod:classification:secret",
    "foreign_national": "false"
  },
  "resource_attributes": {
    "name": "tactical-briefing.ztdf",
    "classification": "urn:ztdf:dod:classification:secret",
    "handling": "urn:ztdf:dod:handling:noforn"
  },
  "action": "read"
}
```

### 3. Dissemination Controls

**URI Pattern**: `urn:ztdf:<domain>:dissemination:<control>`

**Purpose**: Control who can receive or view the data

**Common Controls**:
- `rel-to:<country-code>` - Releasable to specific country
- `rel-to-nato` - Releasable to NATO
- `rel-to-five-eyes` - Releasable to Five Eyes nations
- `eyes-only` - Eyes only distribution

**Example Usage**:
```json
{
  "resource_attributes": {
    "name": "intelligence-report.ztdf",
    "classification": "urn:ztdf:nato:classification:confidential",
    "dissemination": "urn:ztdf:nato:dissemination:rel-to-nato"
  }
}
```

### 4. Caveat Markings

**URI Pattern**: `urn:ztdf:<domain>:caveat:<code>`

**Purpose**: Additional restrictions or special access programs

**Common Caveats**:
- `sap:<program-name>` - Special Access Program
- `sci:<compartment>` - Sensitive Compartmented Information
- `tk:<codeword>` - TALENT KEYHOLE

**Example Usage**:
```json
{
  "subject_attributes": {
    "sub": "charlie@intel.gov",
    "classification": "urn:ztdf:dod:classification:top-secret",
    "caveat": "urn:ztdf:dod:caveat:sci:si-gamma"
  }
}
```

### 5. Privacy Markings

**URI Pattern**: `urn:ztdf:<domain>:privacy:<type>`

**Purpose**: Identify privacy-sensitive information

**Common Types**:
- `pii` - Personally Identifiable Information
- `phi` - Protected Health Information
- `pci` - Payment Card Information
- `itar` - International Traffic in Arms Regulations
- `gdpr` - GDPR protected data

**Example Usage**:
```json
{
  "resource_attributes": {
    "name": "patient-records.ztdf",
    "classification": "urn:ztdf:commercial:sensitivity:confidential",
    "privacy": "urn:ztdf:commercial:privacy:phi"
  }
}
```

## ZTDF Manifest Integration

ZTDF files include a manifest with attribute assertions. The platform can extract these attributes for access control decisions.

### Manifest Example

```json
{
  "manifest": {
    "encryptionInformation": {
      "keyAccess": [
        {
          "type": "wrapped",
          "url": "https://kas.example.com/v2/rewrap",
          "protocol": "kas",
          "wrappedKey": "base64-encoded-key"
        }
      ],
      "policy": "base64-encoded-policy",
      "method": {
        "algorithm": "AES-256-GCM"
      }
    },
    "assertions": [
      {
        "id": "assertion-1",
        "type": "handling",
        "scope": "tdo",
        "appliesToState": "encrypted",
        "statement": {
          "format": "urn",
          "value": "urn:ztdf:nato:classification:secret"
        }
      },
      {
        "id": "assertion-2",
        "type": "handling",
        "scope": "tdo",
        "appliesToState": "encrypted",
        "statement": {
          "format": "urn",
          "value": "urn:ztdf:nato:handling:nato-releasable"
        }
      }
    ]
  }
}
```

### Extracting Attributes from Manifest

When processing ZTDF files, extract assertion URIs and map them to resource attributes:

```go
func ExtractResourceAttributes(manifest *ZTDFManifest) map[string]string {
    attrs := make(map[string]string)

    for _, assertion := range manifest.Assertions {
        if assertion.Statement.Format == "urn" {
            uri := assertion.Statement.Value

            // Parse ZTDF URI
            parts := strings.Split(uri, ":")
            if len(parts) >= 4 && parts[0] == "urn" && parts[1] == "ztdf" {
                attrType := parts[3]  // e.g., "classification"
                attrValue := uri       // Full URI

                // Map to resource attributes
                switch attrType {
                case "classification":
                    attrs["classification"] = attrValue
                case "handling":
                    attrs["handling"] = attrValue
                case "dissemination":
                    attrs["dissemination"] = attrValue
                case "caveat":
                    attrs["caveat"] = attrValue
                case "privacy":
                    attrs["privacy"] = attrValue
                }
            }
        }
    }

    return attrs
}
```

## Platform Integration Patterns

### Pattern 1: Direct URI Matching

**Use Case**: Exact match required between subject and resource URIs

```json
{
  "subject_attributes": {
    "sub": "user@example.com",
    "classification": "urn:ztdf:nato:classification:secret"
  },
  "resource_attributes": {
    "name": "document.ztdf",
    "classification": "urn:ztdf:nato:classification:secret"
  },
  "action": "read"
}
```

**Result**: ALLOW if classifications match exactly

### Pattern 2: Hierarchical Classification

**Use Case**: Higher clearance can access lower classified data

**Policy Example** (JSON Policy Language):
```json
{
  "version": "1.0",
  "rules": [
    {
      "id": "classification-hierarchy",
      "effect": "allow",
      "conditions": {
        "allOf": [
          {
            "subject": {
              "classification": {
                "$classificationLevel": {
                  "$gte": {
                    "$resource": "classification"
                  }
                }
              }
            }
          }
        ]
      }
    }
  ]
}
```

**Classification Level Mapping**:
```go
var classificationLevels = map[string]int{
    "urn:ztdf:nato:classification:unclassified": 0,
    "urn:ztdf:nato:classification:restricted":   1,
    "urn:ztdf:nato:classification:confidential": 2,
    "urn:ztdf:nato:classification:secret":       3,
    "urn:ztdf:nato:classification:top-secret":   4,
}
```

### Pattern 3: Handling Code Enforcement

**Use Case**: Enforce special handling requirements

```go
// Entitlement example
{
    "name": "NOFORN-cleared-users",
    "subject_attributes": {
        "foreign_national": "false",
        "clearance": "urn:ztdf:dod:classification:secret"
    },
    "resource_attributes": {
        "handling": "urn:ztdf:dod:handling:noforn"
    },
    "actions": ["read", "write"],
    "enabled": true
}
```

### Pattern 4: Multiple Assertion Matching

**Use Case**: Resource has multiple ZTDF assertions that must all be satisfied

```json
{
  "subject_attributes": {
    "sub": "user@nato.int",
    "classification": "urn:ztdf:nato:classification:secret",
    "country": "usa",
    "clearance_type": "nato-cleared"
  },
  "resource_attributes": {
    "name": "operation-plan.ztdf",
    "classification": "urn:ztdf:nato:classification:secret",
    "dissemination": "urn:ztdf:nato:dissemination:rel-to-nato",
    "handling": "urn:ztdf:nato:handling:nato-releasable"
  },
  "action": "read"
}
```

## Simplified Attribute Names

For ease of use, the platform supports both full URIs and simplified attribute names:

### Mapping Table

| Simplified Name | Full URI |
|----------------|----------|
| `UNCLASSIFIED` | `urn:ztdf:nato:classification:unclassified` |
| `RESTRICTED` | `urn:ztdf:nato:classification:restricted` |
| `CONFIDENTIAL` | `urn:ztdf:nato:classification:confidential` |
| `SECRET` | `urn:ztdf:nato:classification:secret` |
| `TOP_SECRET` | `urn:ztdf:nato:classification:top-secret` |
| `NOFORN` | `urn:ztdf:dod:handling:noforn` |
| `REL_TO_NATO` | `urn:ztdf:nato:dissemination:rel-to-nato` |

### Usage Example

Both formats are equivalent:

```json
// Using full URI
{
  "subject_attributes": {
    "classification": "urn:ztdf:nato:classification:secret"
  }
}

// Using simplified name (automatically mapped)
{
  "subject_attributes": {
    "classification": "SECRET"
  }
}
```

## ZTDF Validator Integration

The platform includes a ZTDF validator that checks manifest integrity and extracts attributes:

```go
import "stratium/pkg/validators"

// Validate ZTDF file and extract attributes
func ValidateAndExtractAttributes(ztdfData []byte) (map[string]string, error) {
    validator := validators.NewZTDFValidator()

    // Validate manifest structure
    if err := validator.Validate(ztdfData); err != nil {
        return nil, fmt.Errorf("invalid ZTDF: %w", err)
    }

    // Parse manifest
    var manifest validators.ZTDFManifest
    if err := json.Unmarshal(ztdfData, &manifest); err != nil {
        return nil, err
    }

    // Extract resource attributes from assertions
    attrs := ExtractResourceAttributes(&manifest)

    return attrs, nil
}
```

## Best Practices

### 1. Use Full URIs in Storage

Store full ZTDF URIs in entitlements and policies for clarity and auditability:

```go
// Good
"classification": "urn:ztdf:nato:classification:secret"

// Avoid
"classification": "SECRET"
```

### 2. Normalize at API Boundary

Convert simplified names to full URIs at the API layer:

```go
func NormalizeZTDFAttributes(attrs map[string]string) map[string]string {
    normalized := make(map[string]string)

    for k, v := range attrs {
        if k == "classification" {
            // Normalize classification values
            normalized[k] = NormalizeClassification(v)
        } else {
            normalized[k] = v
        }
    }

    return normalized
}
```

### 3. Validate ZTDF Files Before Access Decisions

Always validate ZTDF manifests before extracting attributes:

```go
func CheckZTDFAccess(userID string, ztdfFile []byte) (bool, error) {
    // 1. Validate ZTDF manifest
    attrs, err := ValidateAndExtractAttributes(ztdfFile)
    if err != nil {
        return false, fmt.Errorf("invalid ZTDF: %w", err)
    }

    // 2. Get user clearance
    user, err := GetUser(userID)
    if err != nil {
        return false, err
    }

    // 3. Check access decision
    req := &GetDecisionRequest{
        SubjectAttributes: map[string]string{
            "sub":            userID,
            "classification": user.Clearance,
        },
        ResourceAttributes: attrs,
        Action: "read",
    }

    resp, err := client.GetDecision(ctx, req)
    if err != nil {
        return false, err
    }

    return resp.Decision == Decision_DECISION_ALLOW, nil
}
```

### 4. Audit ZTDF Access

Always log ZTDF access decisions with full assertion details:

```go
log.Printf("ZTDF access: user=%s, file=%s, classification=%s, decision=%s",
    userID, fileName, attrs["classification"], decision)
```

### 5. Handle Multiple Assertions

When a ZTDF has multiple assertions, all must be satisfied:

```go
func CheckAllAssertions(userAttrs, resourceAttrs map[string]string) bool {
    // Check classification
    if !CheckClassification(userAttrs["classification"], resourceAttrs["classification"]) {
        return false
    }

    // Check handling codes
    if !CheckHandling(userAttrs, resourceAttrs["handling"]) {
        return false
    }

    // Check dissemination controls
    if !CheckDissemination(userAttrs, resourceAttrs["dissemination"]) {
        return false
    }

    return true
}
```

## Key Access Service (KAS) Integration

When working with ZTDF encryption, the Key Access Service must also enforce attribute-based access:

```go
// KAS checks attributes before providing wrapped keys
func (k *KeyAccessService) GetWrappedKey(req *GetWrappedKeyRequest) (*WrappedKey, error) {
    // Extract attributes from ZTDF policy
    policyAttrs := ExtractPolicyAttributes(req.Policy)

    // Check access decision
    decision := &GetDecisionRequest{
        SubjectAttributes:  req.UserAttributes,
        ResourceAttributes: policyAttrs,
        Action:            "decrypt",
    }

    resp, err := k.pdp.GetDecision(ctx, decision)
    if err != nil {
        return nil, err
    }

    if resp.Decision != Decision_DECISION_ALLOW {
        return nil, fmt.Errorf("access denied: %s", resp.Reason)
    }

    // Provide wrapped key
    return k.rewrapKey(req.WrappedKey, req.PublicKey)
}
```

## Testing ZTDF Attributes

### Test Case Template

```go
func TestZTDFAttributeMatching(t *testing.T) {
    tests := []struct {
        name              string
        userClassification string
        fileClassification string
        expectAllow       bool
    }{
        {
            name:              "SECRET user accesses CONFIDENTIAL file",
            userClassification: "urn:ztdf:nato:classification:secret",
            fileClassification: "urn:ztdf:nato:classification:confidential",
            expectAllow:       true, // Higher can access lower
        },
        {
            name:              "CONFIDENTIAL user accesses SECRET file",
            userClassification: "urn:ztdf:nato:classification:confidential",
            fileClassification: "urn:ztdf:nato:classification:secret",
            expectAllow:       false, // Lower cannot access higher
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            req := &GetDecisionRequest{
                SubjectAttributes: map[string]string{
                    "sub": "test-user",
                    "classification": tt.userClassification,
                },
                ResourceAttributes: map[string]string{
                    "name": "test.ztdf",
                    "classification": tt.fileClassification,
                },
                Action: "read",
            }

            resp, err := client.GetDecision(ctx, req)
            if err != nil {
                t.Fatal(err)
            }

            allowed := resp.Decision == Decision_DECISION_ALLOW
            if allowed != tt.expectAllow {
                t.Errorf("Expected allow=%v, got %v. Reason: %s",
                    tt.expectAllow, allowed, resp.Reason)
            }
        })
    }
}
```

## Related Documentation

- [API Documentation](./api-attribute-based-access-control.md)
- [ZTDF Specification](https://github.com/opentdf/spec)
- [STANAG 4774 Validator](../pkg/validators/ztdf.go)
- [Key Access Service](../services/key-access/README.md)

## References

- OpenTDF Project: https://github.com/opentdf
- ZTDF Specification: https://github.com/opentdf/spec/blob/main/schema/tdf.md
- NATO Security Classifications: https://www.nato.int/cps/en/natohq/topics_48527.htm
- DoD Classification Guide: https://www.esd.whs.mil/DD/DoD-Issuances/