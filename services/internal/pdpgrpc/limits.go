// limits.go checks each request field against the longest it may be
// (config.RequestLimits, which says why they exist).
package pdpgrpc

import (
	"fmt"

	"github.com/stratiumdata/stratium/internal/config"
)

// bounded is one request field and the most bytes it may hold.
type bounded struct {
	name, value string
	max         int
}

// overLong returns an error naming the first field over its limit.
func overLong(fields ...bounded) error {
	for _, f := range fields {
		// Zero is no limit: see config.RequestLimits.
		if f.max > 0 && len(f.value) > f.max {
			return fmt.Errorf("%s is %d bytes; the limit is %d", f.name, len(f.value), f.max)
		}
	}
	return nil
}

// decideFieldLimits checks every DecideRequest field Decide reads as text,
// other than the token (authenticateToken) and raw_input.
func decideFieldLimits(req *DecideRequest, lim config.RequestLimits) error {
	if err := overLong(
		bounded{"tool", req.GetTool(), lim.ToolBytes},
		bounded{"subject", req.GetSubject(), lim.SubjectBytes},
		bounded{"harness", req.GetHarness(), lim.NameBytes},
		bounded{"cwd", req.GetCwd(), lim.PathBytes},
		bounded{"dpop_proof", req.GetDpopProof(), lim.CredentialBytes},
		bounded{"observed_method", req.GetObservedMethod(), lim.NameBytes},
		bounded{"observed_uri", req.GetObservedUri(), lim.URIBytes},
	); err != nil {
		return err
	}
	if n := len(req.GetResource()); lim.ResourceEntries > 0 && n > lim.ResourceEntries {
		return fmt.Errorf("resource has %d entries; the limit is %d", n, lim.ResourceEntries)
	}
	for k, v := range req.GetResource() {
		// The key is not echoed: it is the text that is too long.
		if err := overLong(bounded{"resource key", k, lim.NameBytes}, bounded{"resource value", v, lim.PathBytes}); err != nil {
			return err
		}
	}
	return nil
}

// createDelegationFieldLimits checks every CreateDelegationRequest field
// CreateDelegation reads as text.
func createDelegationFieldLimits(req *CreateDelegationRequest, lim config.RequestLimits) error {
	if err := overLong(
		bounded{"subject", req.GetSubject(), lim.SubjectBytes},
		bounded{"purpose", req.GetPurpose(), lim.PurposeBytes},
		bounded{"parent_token", req.GetParentToken(), lim.CredentialBytes},
		bounded{"principal_token", req.GetPrincipalToken(), lim.CredentialBytes},
		bounded{"dpop_jwk", req.GetDpopJwk(), lim.CredentialBytes},
	); err != nil {
		return err
	}
	tools := req.GetRequestedScope().GetTools()
	if lim.RequestedTools > 0 && len(tools) > lim.RequestedTools {
		return fmt.Errorf("requested_scope.tools has %d entries; the limit is %d", len(tools), lim.RequestedTools)
	}
	for i, tool := range tools {
		if err := overLong(bounded{fmt.Sprintf("requested_scope.tools[%d]", i), tool, lim.ToolBytes}); err != nil {
			return err
		}
	}
	return nil
}
