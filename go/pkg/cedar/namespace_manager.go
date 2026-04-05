package cedar

import (
	"fmt"
	"regexp"
	"strings"

	cedarlib "github.com/cedar-policy/cedar-go"
	"github.com/cedar-policy/cedar-go/types"
)

// validNamespacePattern matches valid Cedar namespace identifiers.
var validNamespacePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)

// NamespaceManager handles tenant-scoped Cedar namespaces.
// Each tenant gets a namespace (e.g., "Acme") that prefixes all entity types
// to prevent cross-tenant entity collisions.
type NamespaceManager struct {
	defaultNS string
}

// NewNamespaceManager creates a new namespace manager.
func NewNamespaceManager(defaultNamespace string) *NamespaceManager {
	if defaultNamespace == "" {
		defaultNamespace = "Stratium"
	}
	return &NamespaceManager{
		defaultNS: defaultNamespace,
	}
}

// DefaultNamespace returns the default namespace.
func (m *NamespaceManager) DefaultNamespace() string {
	return m.defaultNS
}

// ValidateNamespace checks if a namespace identifier is valid.
func (m *NamespaceManager) ValidateNamespace(namespace string) error {
	if namespace == "" {
		return fmt.Errorf("namespace cannot be empty")
	}
	if !validNamespacePattern.MatchString(namespace) {
		return fmt.Errorf("namespace must start with a letter and contain only letters, digits, and underscores: %q", namespace)
	}
	if strings.Contains(namespace, "__cedar") {
		return fmt.Errorf("namespace cannot contain reserved identifier '__cedar': %q", namespace)
	}
	return nil
}

// QualifyEntityType returns a namespace-qualified entity type string.
// e.g., QualifyEntityType("Acme", "User") → "Acme::User"
func (m *NamespaceManager) QualifyEntityType(namespace, entityType string) types.EntityType {
	if namespace == "" {
		namespace = m.defaultNS
	}
	return types.EntityType(fmt.Sprintf("%s::%s", namespace, entityType))
}

// QualifyEntityUID returns a namespace-qualified entity UID.
// e.g., QualifyEntityUID("Acme", "User", "alice") → Acme::User::"alice"
func (m *NamespaceManager) QualifyEntityUID(namespace, entityType, id string) types.EntityUID {
	qualifiedType := m.QualifyEntityType(namespace, entityType)
	return cedarlib.NewEntityUID(qualifiedType, cedarlib.String(id))
}

// ExtractNamespace attempts to extract the namespace from a qualified entity type string.
// e.g., "Acme::User" → "Acme", "User"
func (m *NamespaceManager) ExtractNamespace(qualifiedType string) (namespace, entityType string) {
	parts := strings.SplitN(qualifiedType, "::", 2)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return m.defaultNS, qualifiedType
}

// NamespaceBelongsTo checks if an entity type belongs to a given namespace.
func (m *NamespaceManager) NamespaceBelongsTo(qualifiedType, namespace string) bool {
	ns, _ := m.ExtractNamespace(qualifiedType)
	return ns == namespace
}
