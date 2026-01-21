package licensing

import (
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// Claims defines the signed license payload.
type Claims struct {
	CustomerID      string   `json:"customer_id,omitempty"`
	CustomerName    string   `json:"customer_name,omitempty"`
	KeyID           string   `json:"key_id,omitempty"`
	DeploymentID    string   `json:"deployment_id,omitempty"`
	AllowedServices []string `json:"allowed_services,omitempty"`
	Features        []string `json:"features,omitempty"`
	MaxNodes        int      `json:"max_nodes,omitempty"`
	jwt.RegisteredClaims
}

// AllowsService returns true if the license permits access to the service.
func (c *Claims) AllowsService(serviceName string) bool {
	if len(c.AllowedServices) == 0 {
		return true
	}
	for _, allowed := range c.AllowedServices {
		trimmed := strings.TrimSpace(allowed)
		if trimmed == "*" {
			return true
		}
		if strings.EqualFold(trimmed, serviceName) {
			return true
		}
	}
	return false
}

// MatchesDeployment returns true when the license matches the configured deployment ID.
func (c *Claims) MatchesDeployment(deploymentID string) bool {
	licenseID := strings.TrimSpace(c.DeploymentID)
	configID := strings.TrimSpace(deploymentID)

	if licenseID == "" && configID == "" {
		return true
	}
	if licenseID == "" || configID == "" {
		return false
	}
	return strings.EqualFold(licenseID, configID)
}
