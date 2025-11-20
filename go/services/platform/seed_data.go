package platform

import (
	"fmt"
	"os"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
	"sigs.k8s.io/yaml"
)

// SeedData represents bootstrap data for entitlements and policies.
type SeedData struct {
	Entitlements []EntitlementSeed `json:"entitlements" yaml:"entitlements"`
	Policies     []PolicySeed      `json:"policies" yaml:"policies"`
}

// EntitlementSeed describes a single entitlement entry.
type EntitlementSeed struct {
	ID         string            `json:"id" yaml:"id"`
	Subject    string            `json:"subject" yaml:"subject"`
	Resource   string            `json:"resource" yaml:"resource"`
	Actions    []string          `json:"actions" yaml:"actions"`
	Conditions []ConditionSeed   `json:"conditions" yaml:"conditions"`
	Metadata   map[string]string `json:"metadata" yaml:"metadata"`
	Active     *bool             `json:"active" yaml:"active"`
	CreatedAt  string            `json:"created_at" yaml:"created_at"`
	ExpiresAt  string            `json:"expires_at" yaml:"expires_at"`
}

// ConditionSeed describes a condition that must be met for the entitlement.
type ConditionSeed struct {
	Type       string            `json:"type" yaml:"type"`
	Operator   string            `json:"operator" yaml:"operator"`
	Value      string            `json:"value" yaml:"value"`
	Parameters map[string]string `json:"parameters" yaml:"parameters"`
}

// PolicySeed describes a policy definition with one or more rules.
type PolicySeed struct {
	ID          string           `json:"id" yaml:"id"`
	Name        string           `json:"name" yaml:"name"`
	Description string           `json:"description" yaml:"description"`
	Rules       []PolicyRuleSeed `json:"rules" yaml:"rules"`
}

// PolicyRuleSeed mirrors PolicyRule for seed manifests.
type PolicyRuleSeed struct {
	Resource  string `json:"resource" yaml:"resource"`
	Action    string `json:"action" yaml:"action"`
	Subject   string `json:"subject" yaml:"subject"`
	Condition string `json:"condition" yaml:"condition"`
	Effect    string `json:"effect" yaml:"effect"`
}

func loadSeedDataFromFile(path string) (*SeedData, error) {
	if path == "" {
		return nil, fmt.Errorf("seed data path is empty")
	}

	payload, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read seed data file: %w", err)
	}

	var seed SeedData
	if err := yaml.Unmarshal(payload, &seed); err != nil {
		return nil, fmt.Errorf("failed to parse seed data: %w", err)
	}

	return &seed, nil
}

func (s *Server) applySeedData(seed *SeedData) error {
	if seed == nil {
		return nil
	}

	if seed.Entitlements != nil {
		for _, ent := range seed.Entitlements {
			if err := s.addSeedEntitlement(ent); err != nil {
				return err
			}
		}
	}

	if seed.Policies != nil {
		for _, pol := range seed.Policies {
			if err := s.addSeedPolicy(pol); err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *Server) addSeedEntitlement(seed EntitlementSeed) error {
	if seed.Subject == "" || seed.ID == "" {
		return fmt.Errorf("seed entitlement missing id or subject")
	}

	createdAt := timestamppb.Now()
	if seed.CreatedAt != "" {
		if t, err := time.Parse(time.RFC3339, seed.CreatedAt); err == nil {
			createdAt = timestamppb.New(t)
		}
	}

	var expiresAt *timestamppb.Timestamp
	if seed.ExpiresAt != "" {
		if t, err := time.Parse(time.RFC3339, seed.ExpiresAt); err == nil {
			expiresAt = timestamppb.New(t)
		}
	}

	active := true
	if seed.Active != nil {
		active = *seed.Active
	}

	conditions := make([]*Condition, 0, len(seed.Conditions))
	for _, cond := range seed.Conditions {
		conditions = append(conditions, &Condition{
			Type:       cond.Type,
			Operator:   cond.Operator,
			Value:      cond.Value,
			Parameters: cond.Parameters,
		})
	}

	entitlement := &Entitlement{
		Id:         seed.ID,
		Subject:    seed.Subject,
		Resource:   seed.Resource,
		Actions:    seed.Actions,
		Conditions: conditions,
		Metadata:   seed.Metadata,
		CreatedAt:  createdAt,
		ExpiresAt:  expiresAt,
		Active:     active,
	}

	if entitlement.Metadata == nil {
		entitlement.Metadata = map[string]string{}
	}

	s.entitlements[seed.Subject] = append(s.entitlements[seed.Subject], entitlement)
	return nil
}

func (s *Server) addSeedPolicy(seed PolicySeed) error {
	if seed.ID == "" {
		return fmt.Errorf("seed policy missing id")
	}

	rules := make([]PolicyRule, 0, len(seed.Rules))
	for _, rule := range seed.Rules {
		rules = append(rules, PolicyRule{
			Resource:  rule.Resource,
			Action:    rule.Action,
			Subject:   rule.Subject,
			Condition: rule.Condition,
			Effect:    rule.Effect,
		})
	}

	s.policies[seed.ID] = &Policy{
		ID:          seed.ID,
		Name:        seed.Name,
		Description: seed.Description,
		Rules:       rules,
	}

	return nil
}

func defaultSeedData() *SeedData {
	return &SeedData{
		Entitlements: []EntitlementSeed{
			{
				ID:       "ent-1",
				Subject:  "user123",
				Resource: "document-service",
				Actions:  []string{"read", "write"},
				Conditions: []ConditionSeed{
					{
						Type:     "time",
						Operator: "before",
						Value:    "2025-12-31T23:59:59Z",
					},
				},
				Metadata: map[string]string{
					"department": "engineering",
					"level":      "senior",
				},
				ExpiresAt: time.Now().AddDate(1, 0, 0).UTC().Format(time.RFC3339),
			},
			{
				ID:       "ent-2",
				Subject:  "user123",
				Resource: "user-service",
				Actions:  []string{"read"},
				Conditions: []ConditionSeed{
					{
						Type:       "attribute",
						Operator:   "equals",
						Value:      "engineering",
						Parameters: map[string]string{"attribute": "department"},
					},
				},
				Metadata: map[string]string{
					"scope": "department",
				},
			},
			{
				ID:       "ent-admin-1",
				Subject:  "admin456",
				Resource: "*",
				Actions:  []string{"*"},
				Metadata: map[string]string{
					"role": "admin",
				},
			},
		},
		Policies: []PolicySeed{
			{
				ID:          "admin-policy",
				Name:        "Admin Policy",
				Description: "Full access for administrators",
				Rules: []PolicyRuleSeed{
					{
						Resource:  "*",
						Action:    "*",
						Subject:   "*",
						Condition: "role == 'admin'",
						Effect:    "allow",
					},
				},
			},
			{
				ID:          "default-deny-policy",
				Name:        "Default Deny Policy",
				Description: "Default policy that denies access when no other rules match",
				Rules: []PolicyRuleSeed{
					{
						Resource: "*",
						Action:   "*",
						Subject:  "*",
						Effect:   "deny",
					},
				},
			},
		},
	}
}
