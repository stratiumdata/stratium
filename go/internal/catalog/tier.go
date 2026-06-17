// go/internal/catalog/tier.go
package catalog

import "fmt"

// AssessTier mirrors assessActionTier in services/agent-gateway/server.go so the
// catalog can validate a tool's declared tier at registration time. The gateway
// remains the authoritative assessor at call time; this is defense-in-depth.
func AssessTier(action string) int {
	switch action {
	case "read", "get", "list", "query", "search":
		return 1
	case "write", "create", "update", "modify", "patch":
		return 2
	case "send", "email", "notify", "webhook", "publish":
		return 3
	case "delete", "destroy", "drop", "revoke", "transfer", "execute":
		return 4
	default:
		return 0
	}
}

// GuardTier returns an error if a tool declares a tier LOWER than the tier its
// action assesses to. A tool may declare a higher tier than necessary, but never
// a lower one — that would let it slip a sensitive action under a delegation cap.
func GuardTier(action string, declared int) error {
	assessed := AssessTier(action)
	if assessed == 0 {
		return fmt.Errorf("action %q is not a recognized catalog action", action)
	}
	if declared < assessed {
		return fmt.Errorf("tool declares tier %d but action %q assesses to tier %d", declared, action, assessed)
	}
	return nil
}
