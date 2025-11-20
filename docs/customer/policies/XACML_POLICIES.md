# XACML Policy Creation Guide

XACML (eXtensible Access Control Markup Language) is an XML-based standard for expressing enterprise-grade access control policies with strong compliance and auditing capabilities.

## Table of Contents
- [Overview](#overview)
- [When to Use XACML](#when-to-use-xacml)
- [XACML Basics](#xacml-basics)
- [Policy Structure](#policy-structure)
- [Examples](#examples)
- [Best Practices](#best-practices)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)

## Overview

XACML is an OASIS standard for attribute-based access control (ABAC) that provides:

- **Industry Standard**: Recognized compliance framework
- **Enterprise Features**: Policy sets, combining algorithms, obligations
- **Audit Trail**: Built-in obligation and advice mechanisms
- **Interoperability**: Standard format across systems
- **Formal Semantics**: Well-defined evaluation behavior

**Current Version**: XACML 3.0 (Stratium supports XACML 3.0 and 2.0)

## When to Use XACML

Choose XACML policies when you need:

✅ **Compliance Requirements**
- Regulatory compliance (HIPAA, SOX, GDPR)
- Enterprise governance requirements
- Formal audit trails
- Standardized policy format

✅ **Enterprise Features**
- Policy sets with combining algorithms
- Obligations (actions that must be performed)
- Advice (recommended actions)
- Multi-decision requests

✅ **Interoperability**
- Integration with XACML-compliant systems
- Policy portability between vendors
- Standard tooling support

❌ **Don't use XACML when:**
- Simple policies are sufficient (use JSON)
- Team lacks XML expertise
- Fast iteration is priority (XACML is verbose)
- No compliance requirements

## XACML Basics

### Core Components

1. **PolicySet**: Container for multiple policies
2. **Policy**: Container for rules
3. **Rule**: Individual authorization decision
4. **Target**: Applicability criteria
5. **Condition**: Boolean expression
6. **Effect**: Permit or Deny

### Decision Flow

```
Request
  ↓
PolicySet
  ↓
Policy (Target matches?)
  ↓
Rule (Target matches?)
  ↓
Condition (Evaluates true?)
  ↓
Effect (Permit/Deny)
```

### Combining Algorithms

Determines how multiple policy/rule decisions are combined:

- **deny-overrides**: Any Deny → final Deny
- **permit-overrides**: Any Permit → final Permit
- **first-applicable**: First match wins
- **deny-unless-permit**: Deny unless explicit Permit
- **permit-unless-deny**: Permit unless explicit Deny

## Policy Structure

### Basic XACML Policy

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
        PolicyId="policy:unique-id"
        Version="1.0"
        RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides">

    <Description>Human readable description</Description>

    <Target>
        <!-- Applicability criteria -->
    </Target>

    <Rule RuleId="rule:1" Effect="Permit">
        <Description>Rule description</Description>
        <Target>
            <!-- Rule-specific target -->
        </Target>
        <Condition>
            <!-- Boolean condition -->
        </Condition>
    </Rule>

</Policy>
```

### Stratium XACML Policy Format

When creating XACML policies in Stratium, wrap the XML content:

```json
{
  "name": "XACML Policy Name",
  "description": "Policy description",
  "effect": "allow",
  "language": "xacml",
  "priority": 100,
  "enabled": true,
  "policy_content": "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Policy xmlns=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17\" PolicyId=\"policy:example\" Version=\"1.0\" RuleCombiningAlgId=\"urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides\">...</Policy>"
}
```

## Examples

### Example 1: Simple Department Access

Allow engineering department to access engineering resources:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
        PolicyId="policy:engineering-access"
        Version="1.0"
        RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides">

    <Description>Engineering department access to engineering resources</Description>

    <Target>
        <AnyOf>
            <AllOf>
                <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
                    <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">engineering_data</AttributeValue>
                    <AttributeDesignator
                        AttributeId="resource:type"
                        Category="urn:oasis:names:tc:xacml:3.0:attribute-category:resource"
                        DataType="http://www.w3.org/2001/XMLSchema#string"
                        MustBePresent="true"/>
                </Match>
            </AllOf>
        </AnyOf>
    </Target>

    <Rule RuleId="rule:engineering-staff" Effect="Permit">
        <Description>Allow engineering staff</Description>
        <Condition>
            <Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
                <Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:string-one-and-only">
                    <AttributeDesignator
                        AttributeId="subject:department"
                        Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject"
                        DataType="http://www.w3.org/2001/XMLSchema#string"
                        MustBePresent="true"/>
                </Apply>
                <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">engineering</AttributeValue>
            </Apply>
        </Condition>
    </Rule>

</Policy>
```

### Example 2: Role-Based Access with Actions

Different permissions for different roles:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
        PolicyId="policy:rbac-example"
        Version="1.0"
        RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:first-applicable">

    <Description>Role-based access control</Description>

    <Rule RuleId="rule:admin-full-access" Effect="Permit">
        <Description>Admins have full access</Description>
        <Target>
            <AnyOf>
                <AllOf>
                    <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
                        <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">admin</AttributeValue>
                        <AttributeDesignator
                            AttributeId="subject:role"
                            Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject"
                            DataType="http://www.w3.org/2001/XMLSchema#string"
                            MustBePresent="true"/>
                    </Match>
                </AllOf>
            </AnyOf>
        </Target>
    </Rule>

    <Rule RuleId="rule:manager-read-write" Effect="Permit">
        <Description>Managers can read and write</Description>
        <Target>
            <AnyOf>
                <AllOf>
                    <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
                        <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">manager</AttributeValue>
                        <AttributeDesignator
                            AttributeId="subject:role"
                            Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject"
                            DataType="http://www.w3.org/2001/XMLSchema#string"
                            MustBePresent="true"/>
                    </Match>
                </AllOf>
            </AnyOf>
        </Target>
        <Condition>
            <Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:or">
                <Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
                    <Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:string-one-and-only">
                        <AttributeDesignator
                            AttributeId="action:id"
                            Category="urn:oasis:names:tc:xacml:3.0:attribute-category:action"
                            DataType="http://www.w3.org/2001/XMLSchema#string"
                            MustBePresent="true"/>
                    </Apply>
                    <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">read</AttributeValue>
                </Apply>
                <Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
                    <Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:string-one-and-only">
                        <AttributeDesignator
                            AttributeId="action:id"
                            Category="urn:oasis:names:tc:xacml:3.0:attribute-category:action"
                            DataType="http://www.w3.org/2001/XMLSchema#string"
                            MustBePresent="true"/>
                    </Apply>
                    <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">write</AttributeValue>
                </Apply>
            </Apply>
        </Condition>
    </Rule>

    <Rule RuleId="rule:user-read-only" Effect="Permit">
        <Description>Regular users can only read</Description>
        <Target>
            <AnyOf>
                <AllOf>
                    <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
                        <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">user</AttributeValue>
                        <AttributeDesignator
                            AttributeId="subject:role"
                            Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject"
                            DataType="http://www.w3.org/2001/XMLSchema#string"
                            MustBePresent="true"/>
                    </Match>
                    <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
                        <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">read</AttributeValue>
                        <AttributeDesignator
                            AttributeId="action:id"
                            Category="urn:oasis:names:tc:xacml:3.0:attribute-category:action"
                            DataType="http://www.w3.org/2001/XMLSchema#string"
                            MustBePresent="true"/>
                    </Match>
                </AllOf>
            </AnyOf>
        </Target>
    </Rule>

</Policy>
```

### Example 3: Hierarchical Clearance (XACML 3.0)

Using comparison functions for security clearance:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
        PolicyId="policy:clearance-check"
        Version="1.0"
        RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides">

    <Description>Security clearance hierarchy check</Description>

    <Rule RuleId="rule:clearance-sufficient" Effect="Permit">
        <Description>Allow if clearance >= classification</Description>
        <Condition>
            <Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:integer-greater-than-or-equal">
                <Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:integer-one-and-only">
                    <AttributeDesignator
                        AttributeId="subject:clearance-level"
                        Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject"
                        DataType="http://www.w3.org/2001/XMLSchema#integer"
                        MustBePresent="true"/>
                </Apply>
                <Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:integer-one-and-only">
                    <AttributeDesignator
                        AttributeId="resource:classification-level"
                        Category="urn:oasis:names:tc:xacml:3.0:attribute-category:resource"
                        DataType="http://www.w3.org/2001/XMLSchema#integer"
                        MustBePresent="true"/>
                </Apply>
            </Apply>
        </Condition>
    </Rule>

</Policy>
```

**Note**: Clearance levels should be numeric:
- UNCLASSIFIED = 0
- RESTRICTED = 1
- CONFIDENTIAL = 2
- SECRET = 3
- TOP-SECRET = 4

### Example 4: Time-Based Access

Restrict access to business hours:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
        PolicyId="policy:business-hours"
        Version="1.0"
        RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides">

    <Description>Allow access only during business hours</Description>

    <Rule RuleId="rule:time-restriction" Effect="Permit">
        <Description>9 AM to 5 PM, Monday to Friday</Description>
        <Condition>
            <Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:and">
                <!-- Hour between 9 and 17 -->
                <Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:integer-greater-than-or-equal">
                    <Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:integer-one-and-only">
                        <AttributeDesignator
                            AttributeId="environment:current-hour"
                            Category="urn:oasis:names:tc:xacml:3.0:attribute-category:environment"
                            DataType="http://www.w3.org/2001/XMLSchema#integer"
                            MustBePresent="true"/>
                    </Apply>
                    <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#integer">9</AttributeValue>
                </Apply>
                <Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:integer-less-than">
                    <Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:integer-one-and-only">
                        <AttributeDesignator
                            AttributeId="environment:current-hour"
                            Category="urn:oasis:names:tc:xacml:3.0:attribute-category:environment"
                            DataType="http://www.w3.org/2001/XMLSchema#integer"
                            MustBePresent="true"/>
                    </Apply>
                    <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#integer">17</AttributeValue>
                </Apply>
                <!-- Day is Mon-Fri -->
                <Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:string-is-in">
                    <Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:string-one-and-only">
                        <AttributeDesignator
                            AttributeId="environment:current-day"
                            Category="urn:oasis:names:tc:xacml:3.0:attribute-category:environment"
                            DataType="http://www.w3.org/2001/XMLSchema#string"
                            MustBePresent="true"/>
                    </Apply>
                    <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">Monday</AttributeValue>
                    <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">Tuesday</AttributeValue>
                    <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">Wednesday</AttributeValue>
                    <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">Thursday</AttributeValue>
                    <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">Friday</AttributeValue>
                </Apply>
            </Apply>
        </Condition>
    </Rule>

</Policy>
```

### Example 5: PolicySet with Multiple Policies

Combining multiple policies:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<PolicySet xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
           PolicySetId="policyset:document-access"
           Version="1.0"
           PolicyCombiningAlgId="urn:oasis:names:tc:xacml:3.0:policy-combining-algorithm:deny-overrides">

    <Description>Document access control policy set</Description>

    <Target>
        <AnyOf>
            <AllOf>
                <Match MatchId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
                    <AttributeValue DataType="http://www.w3.org/2001/XMLSchema#string">document</AttributeValue>
                    <AttributeDesignator
                        AttributeId="resource:type"
                        Category="urn:oasis:names:tc:xacml:3.0:attribute-category:resource"
                        DataType="http://www.w3.org/2001/XMLSchema#string"
                        MustBePresent="true"/>
                </Match>
            </AllOf>
        </AnyOf>
    </Target>

    <!-- Policy 1: Clearance check -->
    <Policy PolicyId="policy:clearance" Version="1.0"
            RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides">
        <Description>Check security clearance</Description>
        <Rule RuleId="rule:clearance-check" Effect="Permit">
            <Condition>
                <!-- clearance >= classification logic here -->
            </Condition>
        </Rule>
    </Policy>

    <!-- Policy 2: Business hours -->
    <Policy PolicyId="policy:time-based" Version="1.0"
            RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides">
        <Description>Business hours restriction</Description>
        <Rule RuleId="rule:time-check" Effect="Permit">
            <Condition>
                <!-- time-based logic here -->
            </Condition>
        </Rule>
    </Policy>

</PolicySet>
```

## Best Practices

### 1. Use Descriptive IDs

```xml
<!-- ✅ Good -->
<Policy PolicyId="policy:engineering-database-access" Version="1.0">
    <Rule RuleId="rule:engineering-staff-read" Effect="Permit">

<!-- ❌ Bad -->
<Policy PolicyId="pol1" Version="1.0">
    <Rule RuleId="r1" Effect="Permit">
```

### 2. Choose Appropriate Combining Algorithms

```xml
<!-- For security: deny-overrides (any deny wins) -->
<Policy RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:deny-overrides">

<!-- For performance: first-applicable (stop at first match) -->
<Policy RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:first-applicable">

<!-- For permissive: permit-overrides (any permit wins) -->
<Policy RuleCombiningAlgId="urn:oasis:names:tc:xacml:3.0:rule-combining-algorithm:permit-overrides">
```

### 3. Use Targets for Efficiency

```xml
<!-- ✅ Good - Target filters applicability -->
<Policy PolicyId="policy:example">
    <Target>
        <AnyOf>
            <AllOf>
                <Match MatchId="...">
                    <!-- Filter to specific resource type -->
                </Match>
            </AllOf>
        </AnyOf>
    </Target>
    <Rule>...</Rule>
</Policy>

<!-- ❌ Bad - No target, evaluates all rules -->
<Policy PolicyId="policy:example">
    <Rule>
        <Condition>
            <!-- All filtering in condition -->
        </Condition>
    </Rule>
</Policy>
```

### 4. Validate XML

Always validate XACML against the schema:

```bash
xmllint --schema xacml-core-v3-schema-wd-17.xsd policy.xml
```

### 5. Use Comments

```xml
<!-- Document complex logic -->
<Policy PolicyId="policy:complex-access">
    <!-- This policy checks:
         1. User clearance level
         2. Resource classification
         3. Time of access
         All conditions must be met for permit -->
    <Rule RuleId="rule:multi-check" Effect="Permit">
        ...
    </Rule>
</Policy>
```

### 6. Version Policies

```xml
<!-- Always include version -->
<Policy PolicyId="policy:example" Version="2.1">
    <Description>v2.1: Added time-based restrictions</Description>
    ...
</Policy>
```

## Testing

### Validate XACML Syntax

```bash
POST /api/v1/policies/validate
Content-Type: application/json

{
  "language": "xacml",
  "policy_content": "<?xml version=\"1.0\"...>"
}
```

### Test Policy Evaluation

```bash
POST /api/v1/policies/test
Content-Type: application/json

{
  "policy": {
    "effect": "allow",
    "language": "xacml",
    "policy_content": "<?xml version=\"1.0\"...>"
  },
  "evaluation_context": {
    "subject": {
      "role": "admin",
      "clearance-level": 3
    },
    "resource": {
      "type": "document",
      "classification-level": 2
    },
    "action": "read"
  }
}
```

### Test Tools

- **XACML Online Tools**: [XACML.io](https://xacml.io)
- **XML Validators**: xmllint, XML validators
- **XACML Simulators**: AT&T XACML tools

## Troubleshooting

### Common XML Errors

**Problem**: Invalid XML syntax

```xml
<!-- ❌ Wrong - Unclosed tag -->
<Policy PolicyId="test">
    <Rule RuleId="r1" Effect="Permit">
</Policy>

<!-- ✅ Correct -->
<Policy PolicyId="test">
    <Rule RuleId="r1" Effect="Permit">
    </Rule>
</Policy>
```

### Namespace Issues

**Problem**: Missing or incorrect namespace

```xml
<!-- ❌ Wrong - No namespace -->
<Policy PolicyId="test">

<!-- ✅ Correct - XACML 3.0 namespace -->
<Policy xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17"
        PolicyId="test">
```

### Attribute Category Errors

**Problem**: Incorrect category URN

```xml
<!-- ❌ Wrong - Invalid category -->
<AttributeDesignator
    AttributeId="role"
    Category="subject"
    DataType="..."/>

<!-- ✅ Correct - Full URN -->
<AttributeDesignator
    AttributeId="role"
    Category="urn:oasis:names:tc:xacml:1.0:subject-category:access-subject"
    DataType="..."/>
```

### Function ID Errors

```xml
<!-- ❌ Wrong - Invalid function -->
<Apply FunctionId="string-equals">

<!-- ✅ Correct - Full URN -->
<Apply FunctionId="urn:oasis:names:tc:xacml:1.0:function:string-equal">
```

## XACML vs Other Formats

| Feature | JSON | OPA | XACML |
|---------|------|-----|-------|
| **Verbosity** | Low | Medium | High |
| **Learning Curve** | Low | Medium | High |
| **Compliance** | Low | Medium | High |
| **Tooling** | Good | Good | Excellent |
| **Interoperability** | Low | Medium | High |
| **Best For** | Simple rules | Complex logic | Enterprise/Compliance |

## Common XACML Functions

### String Functions
- `string-equal`: Compare strings
- `string-is-in`: Check string in bag
- `string-concatenate`: Join strings

### Numeric Functions
- `integer-equal`: Compare integers
- `integer-greater-than`: Numeric comparison
- `integer-add`: Addition

### Boolean Functions
- `and`: Logical AND
- `or`: Logical OR
- `not`: Logical NOT

### Bag Functions
- `string-bag-size`: Count elements
- `string-is-in`: Element in bag
- `string-bag-intersection`: Common elements

## Next Steps

- [Learn about JSON Policies](./JSON_POLICIES.md) for simpler rules
- [Learn about OPA Policies](./OPA_POLICIES.md) for flexible logic
- [Policy Best Practices](./BEST_PRACTICES.md)
- [XACML 3.0 Specification](http://docs.oasis-open.org/xacml/3.0/xacml-3.0-core-spec-os-en.html)

## API Reference

### Create XACML Policy

```bash
POST /api/v1/policies
Content-Type: application/json

{
  "name": "My XACML Policy",
  "effect": "allow",
  "language": "xacml",
  "policy_content": "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Policy xmlns=\"urn:oasis:names:tc:xacml:3.0:core:schema:wd-17\"...>...</Policy>"
}
```

**Note**: Escape quotes and newlines in JSON.

## Support

Need help with XACML?
- [XACML 3.0 Specification](http://docs.oasis-open.org/xacml/3.0/)
- [XACML.io Tools](https://xacml.io)
- Contact support: support@stratium.example
