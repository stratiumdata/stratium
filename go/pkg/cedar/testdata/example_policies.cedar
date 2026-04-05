// --- Classification-Based Access ---

// Users with sufficient clearance can unwrap DEKs
@id("classification-access")
permit(
    principal is Stratium::User,
    action == Stratium::Action::"UnwrapDEK",
    resource is Stratium::Resource
) when {
    resource.classification in principal.clearance
};

// --- Role-Based Key Management ---

// Key administrators can rotate keys
@id("key-admin-rotate")
permit(
    principal in Stratium::Role::"key-admin",
    action == Stratium::Action::"RotateKey",
    resource is Stratium::Key
);

// --- Context-Aware Access ---

// Deny classified access without MFA
@id("require-mfa-classified")
forbid(
    principal,
    action == Stratium::Action::"UnwrapDEK",
    resource
) when {
    resource.classification in Stratium::Classification::"CONFIDENTIAL"
} unless {
    context.mfa_verified == true
};

// --- Policy Management ---

// Only policy admins can manage policies
@id("policy-admin-crud")
permit(
    principal in Stratium::Role::"policy-admin",
    action in [
        Stratium::Action::"CreatePolicy",
        Stratium::Action::"UpdatePolicy",
        Stratium::Action::"DeletePolicy"
    ],
    resource is Stratium::Policy
);

// --- Audit Access ---

// Security officers can view audit logs
@id("security-audit-access")
permit(
    principal in Stratium::Role::"security-officer",
    action == Stratium::Action::"ViewAuditLogs",
    resource
);
