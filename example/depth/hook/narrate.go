// narrate.go prints diagnostic-only output alongside the four probes: the
// delegation tokens decoded to JSON, the built chain summarized, and a
// description of the PDP's own Decide code path. None of this participates
// in the four probes below or their enforcement verdict -- see main.go's own
// doc comment for the three claims this example actually proves. A decode or
// format failure anywhere in here degrades to printing something honest; it
// must never be the reason this example fails (main.go's own constraint).
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/stratiumdata/stratium/example/agent"
)

const (
	ansiYellow  = "\033[33m"
	ansiMagenta = "\033[35m"
	ansiReset   = "\033[0m"
)

// painter returns a function that wraps a line in code and ansiReset when
// colourWanted, or returns the line unchanged otherwise -- so every print
// call below looks identical whether or not colour actually gets emitted.
func painter(colourWanted bool) func(code, line string) string {
	return func(code, line string) string {
		if !colourWanted {
			return line
		}
		return code + line + ansiReset
	}
}

// decodeJWTPart base64url-decodes one dot-separated segment of a compact JWT
// and unmarshals it as a JSON object.
func decodeJWTPart(seg string) (map[string]any, error) {
	raw, err := base64.RawURLEncoding.DecodeString(seg)
	if err != nil {
		return nil, fmt.Errorf("base64url decode: %w", err)
	}
	var v map[string]any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, fmt.Errorf("json decode: %w", err)
	}
	return v, nil
}

// decodeJWT splits token into its three compact-serialization segments and
// decodes the first two (header, claims) -- the signature (segment three) is
// never decoded or checked. This is display, not authentication: nothing
// here verifies the token was actually signed by the PDP, and nothing
// downstream of this function should ever be asked to.
func decodeJWT(token string) (header, claims map[string]any, err error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, fmt.Errorf("not a compact JWT: want 3 dot-separated segments, got %d", len(parts))
	}
	if header, err = decodeJWTPart(parts[0]); err != nil {
		return nil, nil, fmt.Errorf("header: %w", err)
	}
	if claims, err = decodeJWTPart(parts[1]); err != nil {
		return nil, nil, fmt.Errorf("claims: %w", err)
	}
	return header, claims, nil
}

// indent prefixes every line of s with pad, for nesting pretty-printed JSON
// under a label.
func indent(s, pad string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = pad + l
	}
	return strings.Join(lines, "\n")
}

func prettyJSON(v map[string]any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("<could not re-indent: %v>", err)
	}
	return string(b)
}

// expiryOf reads a decoded claim set's "exp" (Unix seconds) and formats it.
// CreateDelegationResponse.token's own doc comment (services/internal/pdpgrpc/pdp.pb.go)
// is explicit that a token's expiry should be read by decoding this claim,
// not from a second copy that could drift -- GrantedScope itself carries no
// expiry field at all. Degrades to an honest "unknown" on a missing or
// malformed claim rather than panicking.
func expiryOf(claims map[string]any) string {
	exp, ok := claims["exp"].(float64)
	if !ok {
		return "unknown (no numeric \"exp\" claim)"
	}
	return time.Unix(int64(exp), 0).UTC().Format(time.RFC3339)
}

// printChainSummary is claim (B) of this example's added output: for each
// link, the delegation id, the granted tools, the max action tier, the
// depth, and the expiry.
func printChainSummary(out io.Writer, paint func(string, string) string, chain *agent.Chain) {
	fmt.Fprintln(out, paint(ansiYellow, "  the two-link chain this example just built:"))
	printOneLink(out, paint, "parent", 0, chain.Parent)
	printOneLink(out, paint, "child ", 1, chain.Child)
	fmt.Fprintln(out, paint(ansiYellow,
		"  the child's TTL is deliberately shorter than the parent's: ScopeNarrows checks expiry"))
	fmt.Fprintln(out, paint(ansiYellow,
		"  alongside tier and tools, and expiry is absolute -- an identical requested TTL would still"))
	fmt.Fprintln(out, paint(ansiYellow,
		"  fail, because the child is minted moments after the parent (agent.BuildChain's own doc"))
	fmt.Fprintln(out, paint(ansiYellow,
		"  comment; see childTTLMargin)."))
}

func printOneLink(out io.Writer, paint func(string, string) string, label string, depth int, link agent.ChainLink) {
	expiry := "unknown (token did not decode)"
	if _, claims, err := decodeJWT(link.Token()); err == nil {
		expiry = expiryOf(claims)
	}
	fmt.Fprintln(out, paint(ansiYellow, fmt.Sprintf(
		"    %s (depth %d): delegation %s, tools %v, max_action_tier %d, expires %s",
		label, depth, link.DelegationID, link.GrantedScope.GetTools(), link.GrantedScope.GetMaxActionTier(), expiry)))
}

// printDelegationTokens is claim (A) of this example's added output: decode
// both links' tokens and print their header and claims as indented JSON.
// The raw compact token is not the point and is not printed for a token
// that decodes cleanly -- the claims are: "sub" is the delegation id, and
// seeing the parent's and child's differ is what makes the two depths
// concrete rather than just two lines of prose. A token that fails to
// decode falls back to printing the raw string, saying so, rather than
// aborting this diagnostic block.
func printDelegationTokens(out io.Writer, paint func(string, string) string, chain *agent.Chain) {
	fmt.Fprintln(out, paint(ansiYellow, "  the delegation tokens, decoded (display only -- never signature-verified):"))
	printOneToken(out, paint, "parent (depth 0)", chain.Parent.Token())
	printOneToken(out, paint, "child  (depth 1)", chain.Child.Token())
}

func printOneToken(out io.Writer, paint func(string, string) string, label, token string) {
	header, claims, err := decodeJWT(token)
	if err != nil {
		fmt.Fprintln(out, paint(ansiYellow, fmt.Sprintf("  %s: could not decode (%v) -- raw token: %s", label, err, token)))
		return
	}
	fmt.Fprintln(out, paint(ansiYellow, fmt.Sprintf("  %s header:", label)))
	fmt.Fprintln(out, paint(ansiYellow, indent(prettyJSON(header), "    ")))
	fmt.Fprintln(out, paint(ansiYellow, fmt.Sprintf("  %s claims:", label)))
	fmt.Fprintln(out, paint(ansiYellow, indent(prettyJSON(claims), "    ")))
}

// printDecisionPath is claim (C): the seventeen-step shape of the PDP's own
// Decide call, per docs/architecture.md's "4. The decision path" and its
// mermaid flowchart, printed ONCE before any probe below runs.
//
// This is a DESCRIPTION of what the code does on every call, NOT a trace of
// what happened on this run's calls: Decide executes inside pdp-pap, a
// separate process this program never instruments, so this block prints
// identically whether the probes below pass or fail -- it is not, and must
// never be read as, evidence that these particular steps executed.
func printDecisionPath(out io.Writer, paint func(string, string) string) {
	lines := []string{
		"the shape of the PDP's Decide call, per docs/architecture.md \"4. The decision path\":",
		"a DESCRIPTION of what the code does on every call, NOT a trace of what happened on THIS",
		"run's calls below -- Decide executes inside pdp-pap, a separate process this program never",
		"instruments. This block prints identically whether the probes below pass or fail.",
		"",
		" 1. DecideRequest                          the incoming call",
		" 2. Validate shape                         agent_id, subject, declared_tier",
		" 3. authenticateToken                      token -> delegation_id + cnf.jkt",
		" 4. matchProof                             DPoP: signature, freshness, jkt, htm/htu",
		"    SKIPPED on this surface: hook presents a plain bearer token from the session file;",
		"    only proxy and extauthz use sender-constrained (DPoP) tokens on this call.",
		" 5. loadEpoch                              FIRST store read, always",
		" 6. spendProof                             first store WRITE -- burns the jti",
		"    SKIPPED on this surface: no DPoP proof was presented to spend (see step 4).",
		" 7. LoadAgent",
		" 8. LoadChain",
		" 9. LoadToolCatalog",
		"10. ExtractFromCatalog + ApplyExtraction   resource id, command, verb",
		"11. LoadResourceLabelRules",
		"12. labelResource                          longest-prefix -> classification",
		"13. BuildTierCatalog + honoredOverrides",
		"14. DeriveTier",
		"15. policy.Evaluate                        cedar / rego / xacml / json",
		"16. authz.Decide                           principal AND agent AND delegation",
		"17. escalation branch                      ESCALATE? yes: resolveEscalation (create or",
		"                                            verify approval); no: straight through",
		"18. appendAudit                            hash-chained",
		"19. DecideResponse",
		"",
		"  -- authentication happens before any store call.",
		"  -- the epoch is the first store read, always.",
		"  -- the jti spend, when it applies, is the first store write, and only after the cheap checks.",
	}
	for _, l := range lines {
		fmt.Fprintln(out, paint(ansiMagenta, l))
	}
}
