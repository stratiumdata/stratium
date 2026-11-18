// Package principal answers one question for both planes: given a verified
// OIDC token, which person is this?
//
// The PDP asks it when a root delegation is created (the delegation's
// principal), and the PAP asks it when an approval is decided (the
// approver). An approval is only valid when its approver is the root
// principal, so the two answers have to come from the same rule applied to
// the same claim. Keeping the rule in one place is what stops them drifting.
package principal

// Identity returns the person a verified token's claims name under
// claimName, or "" when they name no one usable.
//
// "" (not an error) for an absent, empty, or non-string claim, and for an
// "email" claim the provider has not verified: some providers let a user
// self-assert an email address, which would let them name themselves anyone.
// email_verified is read as a bool with the zero value on absence or type
// mismatch, so a missing or malformed flag fails closed. Every caller treats
// all of these the same way, by refusing.
func Identity(claims map[string]any, claimName string) string {
	v, ok := claims[claimName].(string)
	if !ok || v == "" {
		return ""
	}
	if claimName == "email" {
		verified, _ := claims["email_verified"].(bool)
		if !verified {
			return ""
		}
	}
	return v
}
