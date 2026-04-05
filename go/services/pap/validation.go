package pap

import (
	"fmt"
	"strings"

	"stratium/pkg/models"
)

func validateCreatePolicyRequest(req *models.CreatePolicyRequest) error {
	if err := validateRequiredString("name", req.Name); err != nil {
		return err
	}
	if err := validatePolicyLanguage(req.Language); err != nil {
		return err
	}
	if err := validateRequiredString("policy_content", req.PolicyContent); err != nil {
		return err
	}
	if err := validatePolicyEffect(req.Effect); err != nil {
		return err
	}
	return nil
}

func validateUpdatePolicyRequest(req *models.UpdatePolicyRequest) error {
	if req.Name != nil {
		if err := validateRequiredString("name", *req.Name); err != nil {
			return err
		}
	}
	if req.Language != nil {
		if err := validatePolicyLanguage(*req.Language); err != nil {
			return err
		}
	}
	if req.PolicyContent != nil {
		if err := validateRequiredString("policy_content", *req.PolicyContent); err != nil {
			return err
		}
	}
	if req.Effect != nil {
		if err := validatePolicyEffect(*req.Effect); err != nil {
			return err
		}
	}
	return nil
}

func validatePolicyCheckRequest(language models.PolicyLanguage, policyContent string) error {
	if err := validatePolicyLanguage(language); err != nil {
		return err
	}
	if err := validateRequiredString("policy_content", policyContent); err != nil {
		return err
	}
	return nil
}

func validatePolicyTestRequest(language models.PolicyLanguage, policyContent string, subjectAttributes, resourceAttributes map[string]interface{}, action string) error {
	if err := validatePolicyLanguage(language); err != nil {
		return err
	}
	if err := validateRequiredString("policy_content", policyContent); err != nil {
		return err
	}
	if err := validateRequiredAttributes("subject_attributes", subjectAttributes); err != nil {
		return err
	}
	if err := validateRequiredAttributes("resource_attributes", resourceAttributes); err != nil {
		return err
	}
	if err := validateRequiredString("action", action); err != nil {
		return err
	}
	return nil
}

func validateEntitlementMatchRequest(req *models.EntitlementMatchRequest) error {
	if err := validateRequiredAttributes("subject_attributes", req.SubjectAttributes); err != nil {
		return err
	}
	if err := validateRequiredString("action", req.Action); err != nil {
		return err
	}
	return nil
}

func validatePolicyLanguage(language models.PolicyLanguage) error {
	switch language {
	case models.PolicyLanguageXACML, models.PolicyLanguageOPA, models.PolicyLanguageJSON, models.PolicyLanguageCedar:
		return nil
	default:
		return fmt.Errorf("language must be one of xacml, opa, json, cedar")
	}
}

func validatePolicyEffect(effect models.PolicyEffect) error {
	switch effect {
	case models.PolicyEffectAllow, models.PolicyEffectDeny:
		return nil
	default:
		return fmt.Errorf("effect must be allow or deny")
	}
}

func validateRequiredString(fieldName, value string) error {
	if strings.TrimSpace(value) == "" {
		return fmt.Errorf("%s is required", fieldName)
	}
	return nil
}

func validateRequiredAttributes(fieldName string, attrs map[string]interface{}) error {
	if len(attrs) == 0 {
		return fmt.Errorf("%s is required", fieldName)
	}
	return nil
}
