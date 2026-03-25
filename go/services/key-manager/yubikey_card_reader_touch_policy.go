package key_manager

import (
	"errors"
	"fmt"
	"strings"
)

func (y *YubiKeyPIVCardReader) ensureTouchPolicy() error {
	slot := strings.ToLower(strings.TrimSpace(y.selectedSlot))
	if slot == "" {
		slot = "9d"
	}

	var ykmanLookupErr error
	var ykmanErr error
	var ykmanParseErr error
	if y.lookPath == nil {
		policy, err := y.getTouchPolicyFromYKMan(slot)
		if err == nil {
			return validateTouchPolicy(slot, policy)
		}
		ykmanParseErr = err
	} else if _, err := y.lookPath(y.ykmanPath()); err == nil {
		policy, err := y.getTouchPolicyFromYKMan(slot)
		if err == nil {
			return validateTouchPolicy(slot, policy)
		}
		// Differentiate command failure vs parse failure.
		if strings.Contains(err.Error(), "failed to read") {
			ykmanErr = err
		} else {
			ykmanParseErr = err
		}
	} else {
		ykmanLookupErr = err
	}

	policy, statusErr := y.getTouchPolicyFromPIVStatus(slot)
	if statusErr == nil {
		return validateTouchPolicy(slot, policy)
	}

	return fmt.Errorf(
		"failed to verify touch policy for slot %s (ykman lookup: %v, ykman: %v, ykman parse: %v, piv status: %v)",
		slot, ykmanLookupErr, ykmanErr, ykmanParseErr, statusErr,
	)
}

func (y *YubiKeyPIVCardReader) getTouchPolicyFromYKMan(slot string) (string, error) {
	output, err := y.runner(y.ykmanPath(), "", "piv", "keys", "info", slot)
	if err != nil {
		return "", fmt.Errorf("failed to read YubiKey touch policy from ykman: %w", err)
	}
	policy, err := parseTouchPolicyFromYKManInfo(output)
	if err != nil {
		return "", fmt.Errorf("failed to parse touch policy from ykman output: %w", err)
	}
	return policy, nil
}

func (y *YubiKeyPIVCardReader) getTouchPolicyFromPIVStatus(slot string) (string, error) {
	output, err := y.runner(y.pivToolPath(), "", "-a", "status")
	if err != nil {
		return "", fmt.Errorf("failed to read YubiKey status from yubico-piv-tool: %w", err)
	}
	policy, err := parseTouchPolicyFromPIVStatus(output, slot)
	if err != nil {
		return "", fmt.Errorf("failed to parse touch policy from yubico-piv-tool status output: %w", err)
	}
	return policy, nil
}

func validateTouchPolicy(slot, policy string) error {
	if normalizeTouchPolicy(policy) != "always" {
		return fmt.Errorf("slot %s requires touch policy ALWAYS, got %q", slot, policy)
	}
	return nil
}

func parseTouchPolicyFromYKManInfo(output []byte) (string, error) {
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		if value, ok := extractTouchPolicyFromLine(line); ok {
			return value, nil
		}
	}
	return "", errors.New("touch policy not found in ykman output")
}

func parseTouchPolicyFromPIVStatus(output []byte, slot string) (string, error) {
	normalizedSlot := strings.ToLower(strings.TrimSpace(slot))
	if normalizedSlot == "" {
		normalizedSlot = "9d"
	}
	prefixes := []string{
		"slot " + normalizedSlot + ":",
		"key slot:" + normalizedSlot,
		"key slot: " + normalizedSlot,
		"key slot:\t" + strings.ToUpper(normalizedSlot),
	}

	lines := strings.Split(string(output), "\n")
	inSlot := false
	for _, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		lower := strings.ToLower(line)
		if strings.HasSuffix(lower, ":") {
			inSlot = false
			for _, prefix := range prefixes {
				if strings.HasPrefix(lower, strings.ToLower(prefix)) {
					inSlot = true
					break
				}
			}
		}
		if !inSlot {
			continue
		}
		if value, ok := extractTouchPolicyFromLine(line); ok {
			return value, nil
		}
	}

	// Fallback: some outputs are single-slot and omit explicit slot headers.
	for _, line := range lines {
		if value, ok := extractTouchPolicyFromLine(line); ok {
			return value, nil
		}
	}

	return "", fmt.Errorf("touch policy not found in slot %s section", normalizedSlot)
}

func extractTouchPolicyFromLine(line string) (string, bool) {
	if line == "" {
		return "", false
	}

	collapsed := collapseWhitespace(line)
	lower := strings.ToLower(collapsed)
	if !strings.Contains(lower, "touch") || !strings.Contains(lower, "policy") {
		if !strings.Contains(lower, "touch required for use") {
			return "", false
		}
	}

	// Prefer explicit separators first.
	if idx := strings.IndexAny(collapsed, ":="); idx >= 0 && idx+1 < len(collapsed) {
		value := strings.TrimSpace(collapsed[idx+1:])
		if value != "" {
			return normalizeTouchPolicy(value), true
		}
	}

	fields := strings.Fields(collapsed)
	if len(fields) == 0 {
		return "", false
	}
	return normalizeTouchPolicy(fields[len(fields)-1]), true
}

func normalizeTouchPolicy(value string) string {
	normalized := strings.ToLower(strings.TrimSpace(value))
	normalized = strings.Trim(normalized, ",.;")
	normalized = strings.TrimPrefix(normalized, "for")
	normalized = strings.TrimSpace(normalized)
	if strings.Contains(normalized, " ") {
		normalized = strings.Fields(normalized)[0]
	}
	return normalized
}

func collapseWhitespace(value string) string {
	return strings.Join(strings.Fields(value), " ")
}
