# Entitlement Examples

A collection of common entitlement patterns and real-world examples for various use cases.

## Table of Contents
- [Department-Based Access](#department-based-access)
- [Role-Based Access](#role-based-access)
- [Project-Based Access](#project-based-access)
- [Time-Based Access](#time-based-access)
- [Location-Based Access](#location-based-access)
- [Multi-Level Access](#multi-level-access)
- [Contractor and Partner Access](#contractor-and-partner-access)
- [Emergency Access](#emergency-access)

## Department-Based Access

### Example 1: Department Database Access

Grant department members access to their department's databases:

```json
{
  "name": "Finance Department Database Access",
  "description": "Finance team can access finance databases",
  "enabled": true,
  "subject_attributes": {
    "department": "finance"
  },
  "resource_attributes": {
    "resource_type": "database",
    "owner": "finance"
  },
  "actions": ["read", "write", "query"]
}
```

### Example 2: Cross-Department Read Access

Allow multiple departments read-only access to shared resources:

```json
{
  "name": "Shared Reports Read Access",
  "description": "Finance and Operations can read shared reports",
  "enabled": true,
  "subject_attributes": {
    "department": ["finance", "operations", "executive"]
  },
  "resource_attributes": {
    "resource_type": "report",
    "category": "shared"
  },
  "actions": ["read", "export"]
}
```

## Role-Based Access

### Example 3: Manager Approval Access

Managers can approve requests across departments:

```json
{
  "name": "Manager Approval Rights",
  "description": "All managers can approve requests",
  "enabled": true,
  "subject_attributes": {
    "role": "manager"
  },
  "resource_attributes": {
    "resource_type": "approval_request"
  },
  "actions": ["read", "approve", "reject", "comment"]
}
```

### Example 4: Admin Full Access

Administrators have full access to system resources:

```json
{
  "name": "Administrator Full Access",
  "description": "Admins can perform all operations",
  "enabled": true,
  "subject_attributes": {
    "role": "admin"
  },
  "resource_attributes": {
    "resource_type": ["database", "application", "system"]
  },
  "actions": ["read", "write", "delete", "admin", "configure"]
}
```

### Example 5: Analyst Data Access

Data analysts can read and export analytics data:

```json
{
  "name": "Analyst Data Access",
  "description": "Data analysts can access analytics datasets",
  "enabled": true,
  "subject_attributes": {
    "role": "data_analyst",
    "department": "analytics"
  },
  "resource_attributes": {
    "resource_type": "dataset",
    "category": "analytics"
  },
  "actions": ["read", "query", "export", "visualize"]
}
```

## Project-Based Access

### Example 6: Project Team Access

Grant project team members access to project resources:

```json
{
  "name": "Project Alpha Team Access",
  "description": "Project Alpha team can access project resources",
  "enabled": true,
  "subject_attributes": {
    "project": "alpha",
    "employee_type": "full-time"
  },
  "resource_attributes": {
    "project": "alpha",
    "resource_type": ["document", "code_repository", "design"]
  },
  "actions": ["read", "write", "comment", "share"]
}
```

### Example 7: Project Lead Extended Access

Project leads have additional permissions:

```json
{
  "name": "Project Lead Admin Access",
  "description": "Project leads can manage project resources",
  "enabled": true,
  "subject_attributes": {
    "role": "project_lead",
    "project": "beta"
  },
  "resource_attributes": {
    "project": "beta",
    "resource_type": ["document", "code_repository", "settings"]
  },
  "actions": ["read", "write", "delete", "admin", "manage_permissions"]
}
```

### Example 8: Multi-Project Access

Users assigned to multiple projects:

```json
{
  "name": "Multi-Project Developer Access",
  "description": "Developers can access their assigned projects",
  "enabled": true,
  "subject_attributes": {
    "role": "developer",
    "projects": ["alpha", "beta", "gamma"]
  },
  "resource_attributes": {
    "resource_type": "code_repository"
  },
  "actions": ["read", "write", "commit", "review"]
}
```

## Time-Based Access

### Example 9: Business Hours Only

Restrict access to business hours:

```json
{
  "name": "Business Hours Database Access",
  "description": "Analysts can access production database during business hours only",
  "enabled": true,
  "subject_attributes": {
    "role": "analyst",
    "department": "analytics"
  },
  "resource_attributes": {
    "resource_type": "database",
    "environment": "production"
  },
  "actions": ["read", "query"],
  "conditions": {
    "time_based": {
      "days_of_week": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"],
      "hours": {
        "start": 9,
        "end": 17
      },
      "timezone": "America/New_York"
    }
  }
}
```

### Example 10: Temporary Access

Grant time-limited access for a specific period:

```json
{
  "name": "Q1 Audit Access",
  "description": "Auditors have temporary access during Q1 audit period",
  "enabled": true,
  "subject_attributes": {
    "role": "auditor",
    "audit_id": "q1-2025"
  },
  "resource_attributes": {
    "resource_type": "financial_record",
    "fiscal_year": "2024"
  },
  "actions": ["read", "export"],
  "conditions": {
    "time_based": {
      "start_time": "2025-01-01T00:00:00Z",
      "end_time": "2025-03-31T23:59:59Z"
    }
  }
}
```

### Example 11: Weekend Maintenance Window

Allow maintenance operations only during weekends:

```json
{
  "name": "Weekend Maintenance Access",
  "description": "DevOps can perform maintenance during weekends",
  "enabled": true,
  "subject_attributes": {
    "role": "devops",
    "team": "infrastructure"
  },
  "resource_attributes": {
    "resource_type": "server",
    "environment": "production"
  },
  "actions": ["admin", "configure", "restart", "update"],
  "conditions": {
    "time_based": {
      "days_of_week": ["Saturday", "Sunday"]
    }
  }
}
```

## Location-Based Access

### Example 12: Regional Data Access

Users can only access data from their region:

```json
{
  "name": "Regional Employee Data Access",
  "description": "HR staff can only access data from their region",
  "enabled": true,
  "subject_attributes": {
    "department": "hr",
    "region": "US-East"
  },
  "resource_attributes": {
    "resource_type": "employee_record",
    "region": "US-East"
  },
  "actions": ["read", "update"]
}
```

### Example 13: GDPR Compliance - EU Only

EU customer data only accessible from EU:

```json
{
  "name": "EU Customer Data - EU Access Only",
  "description": "GDPR compliance: EU customer data accessible only from EU",
  "enabled": true,
  "subject_attributes": {
    "location": "EU",
    "department": "customer_support"
  },
  "resource_attributes": {
    "resource_type": "customer_data",
    "data_region": "EU"
  },
  "actions": ["read", "update"],
  "conditions": {
    "location_based": {
      "allowed_countries": ["DE", "FR", "IT", "ES", "NL", "BE", "PL", "SE"],
      "allowed_regions": ["eu-west", "eu-central"]
    }
  }
}
```

### Example 14: Global Access for Executives

Executives can access data from any region:

```json
{
  "name": "Executive Global Data Access",
  "description": "C-level executives have global data access",
  "enabled": true,
  "subject_attributes": {
    "role": "executive",
    "level": "c-level"
  },
  "resource_attributes": {
    "resource_type": ["report", "dashboard", "financial_data"]
  },
  "actions": ["read", "export", "share"]
}
```

## Multi-Level Access

### Example 15: Tiered Document Access

Different access levels based on role hierarchy:

```json
{
  "name": "Confidential Document - Manager Access",
  "description": "Managers and above can access confidential documents",
  "enabled": true,
  "subject_attributes": {
    "role": ["manager", "director", "vp", "executive"],
    "clearance": "CONFIDENTIAL"
  },
  "resource_attributes": {
    "resource_type": "document",
    "classification": "CONFIDENTIAL"
  },
  "actions": ["read", "comment"]
}
```

### Example 16: Clearance-Based Access

Security clearance-based access:

```json
{
  "name": "Secret Clearance Document Access",
  "description": "Users with SECRET clearance can access SECRET documents",
  "enabled": true,
  "subject_attributes": {
    "clearance": ["SECRET", "TOP-SECRET"],
    "training_completed": true
  },
  "resource_attributes": {
    "resource_type": "document",
    "classification": "SECRET"
  },
  "actions": ["read", "annotate"]
}
```

## Contractor and Partner Access

### Example 17: Contractor Limited Access

Contractors have restricted access:

```json
{
  "name": "Contractor Project Access",
  "description": "Contractors can access only assigned project resources",
  "enabled": true,
  "subject_attributes": {
    "employee_type": "contractor",
    "project": "beta",
    "background_check": "completed"
  },
  "resource_attributes": {
    "project": "beta",
    "resource_type": ["document", "code_repository"],
    "sensitivity": "LOW"
  },
  "actions": ["read", "write"],
  "conditions": {
    "time_based": {
      "start_time": "2025-01-01T00:00:00Z",
      "end_time": "2025-06-30T23:59:59Z",
      "days_of_week": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"],
      "hours": {
        "start": 9,
        "end": 17
      }
    }
  }
}
```

### Example 18: Partner Read-Only Access

External partners have read-only access to shared resources:

```json
{
  "name": "Partner Shared Resource Access",
  "description": "External partners can view shared collaboration documents",
  "enabled": true,
  "subject_attributes": {
    "user_type": "partner",
    "partner_company": "acme-corp",
    "agreement_signed": true
  },
  "resource_attributes": {
    "resource_type": "document",
    "sharing": "partner",
    "project": "joint-venture"
  },
  "actions": ["read", "comment"]
}
```

### Example 19: Vendor Support Access

Vendors have limited support access:

```json
{
  "name": "Vendor Support Access",
  "description": "Vendors can access support tickets and logs",
  "enabled": true,
  "subject_attributes": {
    "user_type": "vendor",
    "vendor_id": "vendor-123",
    "support_agreement": "active"
  },
  "resource_attributes": {
    "resource_type": ["support_ticket", "system_log"],
    "product": "enterprise-platform"
  },
  "actions": ["read", "comment", "update_status"]
}
```

## Emergency Access

### Example 20: On-Call Engineer Emergency Access

On-call engineers have elevated access during incidents:

```json
{
  "name": "On-Call Emergency Production Access",
  "description": "On-call engineers can access production during incidents",
  "enabled": true,
  "subject_attributes": {
    "role": "engineer",
    "on_call_status": "active"
  },
  "resource_attributes": {
    "resource_type": ["server", "database", "logs"],
    "environment": "production"
  },
  "actions": ["read", "admin", "restart"],
  "conditions": {
    "require_justification": true,
    "require_incident_ticket": true
  }
}
```

### Example 21: Security Team Incident Response

Security team emergency access during security incidents:

```json
{
  "name": "Security Incident Response Access",
  "description": "Security team full access during active incidents",
  "enabled": true,
  "subject_attributes": {
    "department": "security",
    "role": ["security_analyst", "security_engineer"],
    "incident_response_trained": true
  },
  "resource_attributes": {
    "resource_type": ["system", "logs", "user_data", "audit_logs"]
  },
  "actions": ["read", "admin", "export", "analyze"],
  "conditions": {
    "require_justification": true,
    "require_incident_id": true,
    "max_duration_hours": 24
  }
}
```

## Complex Combinations

### Example 22: Multi-Attribute Healthcare Access

Healthcare provider access with multiple requirements:

```json
{
  "name": "Patient Record Access - Healthcare Provider",
  "description": "Healthcare providers can access patient records with proper credentials",
  "enabled": true,
  "subject_attributes": {
    "role": "healthcare_provider",
    "department": "cardiology",
    "license_status": "active",
    "hipaa_training": "completed",
    "location": "hospital-main"
  },
  "resource_attributes": {
    "resource_type": "patient_record",
    "department": "cardiology",
    "data_category": "medical"
  },
  "actions": ["read", "update", "annotate"],
  "conditions": {
    "time_based": {
      "days_of_week": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
    },
    "require_justification": true,
    "require_patient_consent": true
  }
}
```

### Example 23: Financial Trading Platform Access

Traders with compliance requirements:

```json
{
  "name": "Trading Platform Access - Licensed Traders",
  "description": "Licensed traders can access trading platform during market hours",
  "enabled": true,
  "subject_attributes": {
    "role": "trader",
    "license_type": "series_7",
    "license_status": "active",
    "compliance_training": "current",
    "background_check": "passed"
  },
  "resource_attributes": {
    "resource_type": "trading_platform",
    "market": "equities"
  },
  "actions": ["read", "trade", "analyze"],
  "conditions": {
    "time_based": {
      "days_of_week": ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday"],
      "hours": {
        "start": 9,
        "end": 16
      },
      "timezone": "America/New_York"
    },
    "require_audit_trail": true
  }
}
```

### Example 24: Government Classified System Access

Multi-layer security for classified systems:

```json
{
  "name": "Classified System Access - Top Secret",
  "description": "Access to top secret systems with full verification",
  "enabled": true,
  "subject_attributes": {
    "clearance": "TOP-SECRET",
    "clearance_status": "active",
    "need_to_know": true,
    "security_training": "current",
    "polygraph": "passed",
    "citizenship": "US",
    "facility_access": "authorized"
  },
  "resource_attributes": {
    "resource_type": "classified_system",
    "classification": "TOP-SECRET",
    "program": "special-access"
  },
  "actions": ["read", "process"],
  "conditions": {
    "location_based": {
      "allowed_facilities": ["site-alpha", "site-bravo"],
      "require_secure_network": true
    },
    "require_two_person_rule": true,
    "require_audit_trail": true
  }
}
```

## Testing Entitlements

Test your entitlements with sample requests:

```bash
# Test entitlement
POST /api/v1/entitlements/test
Content-Type: application/json

{
  "subject_attributes": {
    "department": "engineering",
    "role": "engineer",
    "project": "alpha"
  },
  "resource_attributes": {
    "resource_type": "code_repository",
    "project": "alpha"
  },
  "action": "write"
}
```

## Next Steps

- [Creating Entitlements Guide](./CREATING_ENTITLEMENTS.md)
- [JSON Policy Examples](../policies/JSON_POLICIES.md#examples)
- [OPA Policy Examples](../policies/OPA_POLICIES.md#examples)
- [Integration Guides](../integration/OIDC_INTEGRATION.md)

## License

Copyright © 2025 Stratium Data