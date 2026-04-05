package cedar

import (
	"encoding/json"
	"fmt"
	"regexp"
)

// entityUIDPattern matches valid Cedar entity UIDs in the forms:
//   - Namespace::Type::"identifier"
//   - Type::"identifier"
var entityUIDPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(::[A-Za-z][A-Za-z0-9_]*)*::"[^"]*"$`)

// ValidateEntityUID checks that a string is a well-formed Cedar entity UID.
// Valid forms: `Namespace::Type::"id"` or `Type::"id"`.
// Rejects anything that could inject arbitrary Cedar syntax.
func ValidateEntityUID(uid string) error {
	if uid == "" {
		return fmt.Errorf("entity UID cannot be empty")
	}
	if !entityUIDPattern.MatchString(uid) {
		return fmt.Errorf("entity UID must match pattern Namespace::Type::\"id\", got %q", uid)
	}
	return nil
}

// ValidateSchemaJSON checks that content is valid JSON and has basic Cedar schema structure.
func ValidateSchemaJSON(content string) error {
	if content == "" {
		return fmt.Errorf("schema content cannot be empty")
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(content), &parsed); err != nil {
		return fmt.Errorf("schema content is not valid JSON: %w", err)
	}
	return nil
}
