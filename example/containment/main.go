// Command containment is the example suite's fifth directory, and the first
// that polices nothing. The other four put Stratium in front of a tool call
// and ask "does this go through?" This one never makes a tool call. It asks
// the admin plane a question no enforcement surface can answer:
//
//	does this CHANGE let an agent do anything it could not do before?
//
// Every other question the PAP can answer is a POINT query. `POST
// /v1/policies/test` evaluates one sample input and tells you what happens to
// that sample. That is useful and it is not the same thing: a sample only ever
// reports on the dimension it happens to touch, so a change that widens a
// dimension your sample does not exercise looks clean. `POST /v1/containment`
// asks the universal question instead, and answers it with a counterexample --
// the first dimension on which the candidate exceeds the baseline, worded
// exactly as a refused delegation would word it.
//
// # Why this example exists, and what it is really demonstrating
//
// Not the endpoint. The endpoint is four lines of curl and the user guide
// already shows them (§5.11). What is worth a runnable program is that TWO
// things about this API are genuinely counter-intuitive, and both were found
// by writing this example and watching it fail against a live server.
//
// FIRST: `contained: false` means two different things.
//
// The endpoint is permset.Contains, and Contains answers the DELEGATION
// question -- "is this candidate a valid CHILD of that baseline?" -- not the
// grant-diff question "did this get wider?". Those differ, and they differ on
// exactly the case an operator is most likely to try. Adding a classification
// cap NARROWS a grant (an absent cap means unrestricted), and Contains still
// refuses it:
//
//	child caps hierarchy nato which parent does not cap
//
// That is not a widening claim. It is a deliberate SHAPE rule -- a child's
// dimensions must be derivable from its parent's fixed set, so it may not
// introduce one its parent lacks (spec §4.3.1). Act 1 puts a genuine widening
// and a shape refusal side by side; the status is identical and the reasons
// are not. Read the reason, never the boolean alone.
//
// Both questions are reachable. Since 2026-09-17 the request takes a
// "question" field: "delegation" (the default) is the above, and "grant"
// runs permset.GrantWidens -- the same computation internal/store records on
// an agent-grant write, so the endpoint and the audit row agree by
// construction rather than by two implementations happening to match. Act 1
// below asks BOTH on one input and shows them disagreeing.
//
// SECOND: the union of two contained siblings is itself contained.
//
// The design note behind /v1/principals/{id}/effective says two root
// delegations "one reaching /secret, one reaching EXTERNAL_COMMS" are
// individually in bounds and jointly an exfiltration path. Both halves are
// true, and it does NOT follow that a containment check catches it. Act 2
// runs that exact shape against the live server: sibling A contained, sibling
// B contained, their union contained. Every time, by construction -- a union
// of sets below a ceiling is below that ceiling.
//
// So the sibling risk is a COMPOSITION property, not a ceiling violation.
// Read-the-secret and reach-the-internet is dangerous as a pair while each
// half is unremarkable, and no ceiling comparison will ever flag it. That is
// why /effective REPORTS rather than enforces, and it is worth knowing that
// the principal ceiling listed as future work would not catch this class
// either.
//
// # What is real here and what is local
//
// Every containment verdict printed below comes from the SERVER -- a real
// POST to a real stratium-pap, authenticated with a real Keycloak token. The
// only thing computed in this process is Act 2's union (permset.Union),
// because /effective unions a principal's LIVE delegations and minting those
// needs a PDP and a session, which is the other four directories' job.
//
// Every expectation in this file is asserted. If the engine's answer ever
// stops matching what the prose claims, this program fails loudly and says
// so rather than printing a story that is no longer true -- which is how the
// first draft of Act 1, written from intuition, was caught.
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/stratiumdata/stratium/example/agent"
	"github.com/stratiumdata/stratium/pkg/models"
	"github.com/stratiumdata/stratium/pkg/permset"
)

const (
	kcEditor     = "pap-editor"
	kcEditorPass = "pap_editor_local_dev_only"
	kcViewer     = "pap-viewer"
	kcViewerPass = "pap_viewer_local_dev_only"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "\n%s\n", err)
		os.Exit(1)
	}
}

func run() error {
	papAddr := os.Getenv("EXAMPLE_CONTAINMENT_PAP_ADDR")
	kcAddr := os.Getenv("EXAMPLE_KC_ADDR")

	// Precheck rather than letting a connection refusal surface as a
	// mysterious failure two calls later. agent.Precheck reports every
	// missing prerequisite at once and says plainly that setup is not a
	// policy denial -- the distinction this suite keeps making.
	if err := agent.Precheck(
		agent.Check{
			Name:  "stratium-pap reachable",
			Probe: agent.AddrProbe(papAddr),
			Fix:   `export EXAMPLE_CONTAINMENT_PAP_ADDR="localhost:$(docker compose -f ../deploy/docker/docker-compose.yml port stratium-pap 8080 | sed -E 's/.*://')"`,
		},
		agent.Check{
			Name:  "keycloak reachable",
			Probe: agent.AddrProbe(kcAddr),
			Fix:   `export EXAMPLE_KC_ADDR="localhost:$(docker compose -f ../deploy/docker/docker-compose.yml port keycloak 8080 | sed -E 's/.*://')"`,
		},
	); err != nil {
		return err
	}

	// POST /v1/containment is RoleEditor. Not because it writes -- it writes
	// nothing -- but because every POST on this admin plane is, and
	// POST /v1/policies/test, the point query this one generalises, is
	// gated the same way.
	editor, err := agent.MintToken(kcAddr, kcEditor, kcEditorPass)
	if err != nil {
		return fmt.Errorf("mint editor token: %w", err)
	}

	// A dial probe cannot tell a serving PAP from one whose database has no
	// schema: both accept the connection. Writing this example, a partial
	// compose stack (pap + keycloak + postgres, no migrations) produced a
	// 500 from /effective that read exactly like a bug in /effective. One
	// cheap read against a route that predates this example distinguishes
	// them, and says which it is.
	if err := papJSON(http.MethodGet, "http://"+papAddr+"/v1/delegations", editor, nil, &[]any{}); err != nil {
		return fmt.Errorf("the PAP is reachable but not serving: %w\n\n"+
			"  This is almost always a partially-started stack. /v1/delegations predates\n"+
			"  this example, so a failure here is not about containment.\n"+
			"  fix: docker compose -f ../deploy/docker/docker-compose.yml up -d --wait", err)
	}

	baseline := permset.Set{
		Tools:               []string{"Read", "Write"},
		MaxTier:             models.ActionTierExternalComms,
		EscalateAt:          tier(models.ActionTierDestructive),
		ClassificationCaps:  map[string]string{},
		ResourceConstraints: map[string]string{models.ResourceIDPrefixKey: "/workspace/"},
		ExpiresAt:           time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC),
	}

	fmt.Println("\n=== Act 1 — `contained: false` means two different things ===")
	fmt.Println("Baseline: tools [Read Write], tier EXTERNAL_COMMS, escalate_at DESTRUCTIVE,")
	fmt.Println("          no classification cap, id_prefix /workspace/")
	fmt.Println("The question the endpoint answers is: may a CHILD delegation hold this?")

	for _, c := range act1(baseline) {
		res, err := containment(papAddr, editor, baseline, c.candidate)
		if err != nil {
			return fmt.Errorf("%s: %w", c.name, err)
		}
		if res.Contained != c.wantContained {
			return fmt.Errorf("%s: server said contained=%v, this example expects %v — "+
				"the example is wrong, or the engine changed; do not paper over this",
				c.name, res.Contained, c.wantContained)
		}
		fmt.Printf("\n  %s\n    contained: %-5v  — %s\n", c.name, res.Contained, c.kind)
		if res.Reason != "" {
			fmt.Printf("    reason:    %s\n", res.Reason)
		}
	}

	fmt.Println("\n  ── the same input, the other question ──")
	capAdded := baseline
	capAdded.ClassificationCaps = map[string]string{"nato": "SECRET"}
	for _, q := range []string{"delegation", "grant"} {
		res, err := containmentAsking(papAddr, editor, q, baseline, capAdded)
		if err != nil {
			return fmt.Errorf("asking the %s question: %w", q, err)
		}
		if res.Question != q {
			return fmt.Errorf("asked %q and the server answered %q", q, res.Question)
		}
		fmt.Printf("  question=%-11s contained: %-5v  %s\n", res.Question, res.Contained, res.Reason)
	}
	fmt.Println()
	fmt.Println("  One input, two questions, opposite answers — and neither is wrong.")
	fmt.Println("  \"delegation\" asks may a CHILD hold this; a child may not invent a dimension")
	fmt.Println("  its parent never had. \"grant\" asks did this get WIDER; an absent cap means")
	fmt.Println("  unrestricted, so adding the first one narrows. An unrecognised question is a")
	fmt.Println("  400, never a silent fallback: guessing between two answers that differ is the")
	fmt.Println("  one thing this endpoint must not do.")

	fmt.Println("\n=== Act 2 — the union of two contained siblings is contained ===")

	ceiling := permset.Set{
		Tools:               []string{"Read", "Write", "Bash"},
		MaxTier:             models.ActionTierExternalComms,
		EscalateAt:          tier(models.ActionTierDestructive),
		ClassificationCaps:  map[string]string{"nato": "SECRET"},
		ResourceConstraints: map[string]string{models.ResourceIDPrefixKey: "/workspace/"},
		ExpiresAt:           time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC),
	}
	// Two sessions one person might legitimately be running at once. The
	// first can read classified material and nothing else. The second can
	// run a shell and reach outside the trust boundary, and is capped at
	// UNCLASSIFIED so it cannot read what the first one reads.
	reader := ceiling
	reader.Tools = []string{"Read"}
	reader.MaxTier = models.ActionTierReadOnly

	reacher := ceiling
	reacher.Tools = []string{"Bash"}
	reacher.ClassificationCaps = map[string]string{"nato": "UNCLASSIFIED"}

	for _, s := range []struct {
		name string
		set  permset.Set
	}{{"sibling A (read, SECRET)", reader}, {"sibling B (bash, tier 3)", reacher}} {
		res, err := containment(papAddr, editor, ceiling, s.set)
		if err != nil {
			return fmt.Errorf("%s vs ceiling: %w", s.name, err)
		}
		if !res.Contained {
			return fmt.Errorf("%s should be inside the ceiling, server says: %s", s.name, res.Reason)
		}
		fmt.Printf("  %-26s vs the principal's ceiling → contained\n", s.name)
	}

	// Computed here, with the same permset.Union /effective uses — see the
	// package doc for why this act does not fetch it from the server.
	union, imprecision := permset.Union(reader, reacher)
	res, err := containment(papAddr, editor, ceiling, union)
	if err != nil {
		return fmt.Errorf("union vs ceiling: %w", err)
	}
	fmt.Printf("  %-26s vs the principal's ceiling → %s\n", "their UNION",
		map[bool]string{true: "contained", false: "NOT CONTAINED"}[res.Contained])
	for _, r := range imprecision {
		fmt.Printf("    union widened: %s\n", r)
	}
	if !res.Contained {
		return fmt.Errorf("the union was expected to be CONTAINED and was not (%s) — "+
			"if that is a real change in the engine, this example's second lesson needs "+
			"rewriting, not its expectation flipping", res.Reason)
	}

	fmt.Println("\n  Contained, and that is the finding. A union of sets below a ceiling is")
	fmt.Println("  below that ceiling — always, by construction. So no containment check")
	fmt.Println("  against any ceiling will ever flag this pair.")
	fmt.Println()
	fmt.Println("  What the union DOES show is the shape of the combination: Read and Bash,")
	fmt.Println("  capped at SECRET, reaching EXTERNAL_COMMS. Reading classified material and")
	fmt.Println("  reaching outside the boundary are each unremarkable alone and are an")
	fmt.Println("  exfiltration path together. That is a COMPOSITION property, not a")
	fmt.Println("  permission one, which is why /effective reports instead of enforcing —")
	fmt.Println("  and why the principal ceiling listed as future work would not catch it.")

	fmt.Println("\n=== Act 3 — the same question against live delegations ===")
	viewer, err := agent.MintToken(kcAddr, kcViewer, kcViewerPass)
	if err != nil {
		return fmt.Errorf("mint viewer token: %w", err)
	}
	eff, err := effective(papAddr, viewer, "nobody@example.com")
	if err != nil {
		return fmt.Errorf("GET /effective: %w", err)
	}
	fmt.Printf("  principal with no live delegations → delegations_counted=%d, approved_tools=%v\n",
		eff.DelegationsCounted, eff.Union.Tools)
	fmt.Println("\n  That empty approved_tools list is the point. An empty tool list means")
	fmt.Println("  UNRESTRICTED everywhere else in Stratium, so a principal holding nothing")
	fmt.Println("  and a principal holding everything serialize identically here.")
	fmt.Println("  delegations_counted is the only thing that tells them apart — which is")
	fmt.Println("  why it is in the response rather than left to the reader to infer.")

	fmt.Println("\nAll verdicts above came from the server. Nothing was enforced; nothing")
	fmt.Println("was written. This is the admin plane answering a question about a change.")
	return nil
}

type change struct {
	name          string
	kind          string // what the verdict MEANS, which the boolean alone does not say
	candidate     permset.Set
	wantContained bool
}

// act1 builds five one-dimension changes. Each mutates exactly ONE dimension
// of the baseline, so the server's reason can only be about the thing being
// demonstrated. Every wantContained value here was read off a live server,
// not reasoned out -- the first draft of this function guessed, and guessed
// wrong on the very first case.
func act1(base permset.Set) []change {
	addCap := base
	addCap.ClassificationCaps = map[string]string{"nato": "SECRET"}

	emptyTools := base
	emptyTools.Tools = []string{}

	lowerEscalate := base
	lowerEscalate.EscalateAt = tier(models.ActionTierInternalModify)

	sideways := base
	sideways.ResourceConstraints = map[string]string{models.ResourceIDPrefixKey: "/workspace-evil/"}

	deeper := base
	deeper.ResourceConstraints = map[string]string{models.ResourceIDPrefixKey: "/workspace/sub/"}

	return []change{
		{
			name:          `add a classification cap  (caps: {} → {"nato":"SECRET"})`,
			kind:          "SHAPE REFUSAL. As a grant diff this NARROWS: an absent cap means unrestricted.\n                       A child still may not introduce a dimension its parent lacks.",
			candidate:     addCap,
			wantContained: false,
		},
		{
			name:          `empty the tool allowlist  ([Read Write] → [])`,
			kind:          "GENUINE WIDENING. An empty list means UNRESTRICTED — the widest change here,\n                       and it is spelled as a deletion.",
			candidate:     emptyTools,
			wantContained: false,
		},
		{
			name:          `lower escalate_at         (DESTRUCTIVE → INTERNAL_MODIFY)`,
			kind:          "NARROWING. A lower threshold escalates SOONER.",
			candidate:     lowerEscalate,
			wantContained: true,
		},
		{
			name:          `move id_prefix sideways   (/workspace/ → /workspace-evil/)`,
			kind:          "GENUINE WIDENING. Not a subtree of the parent's prefix. The trailing slash is\n                       the whole reason this comparison is sound.",
			candidate:     sideways,
			wantContained: false,
		},
		{
			name:          `deepen id_prefix          (/workspace/ → /workspace/sub/)`,
			kind:          "NARROWING. The control for the case above: same dimension, opposite answer.",
			candidate:     deeper,
			wantContained: true,
		},
	}
}

func tier(t models.ActionTier) *models.ActionTier { return &t }

type containmentResponse struct {
	Question  string `json:"question"`
	Contained bool   `json:"contained"`
	Reason    string `json:"reason"`
}

func containment(papAddr, token string, baseline, candidate permset.Set) (containmentResponse, error) {
	return containmentAsking(papAddr, token, "delegation", baseline, candidate)
}

// containmentAsking is containment with the question named explicitly. The
// two answers differ on an introduced key, so which one you asked is part of
// the result, not context a reader is expected to remember.
func containmentAsking(papAddr, token, question string, baseline, candidate permset.Set) (containmentResponse, error) {
	body, err := json.Marshal(map[string]any{
		"question": question, "baseline": baseline, "candidate": candidate,
	})
	if err != nil {
		return containmentResponse{}, err
	}
	var out containmentResponse
	return out, papJSON(http.MethodPost, "http://"+papAddr+"/v1/containment", token, body, &out)
}

type effectiveResponse struct {
	PrincipalID        string      `json:"principal_id"`
	Union              permset.Set `json:"union"`
	DelegationsCounted int         `json:"delegations_counted"`
	Imprecision        []string    `json:"imprecision"`
}

func effective(papAddr, token, principal string) (effectiveResponse, error) {
	var out effectiveResponse
	return out, papJSON(http.MethodGet,
		"http://"+papAddr+"/v1/principals/"+principal+"/effective", token, nil, &out)
}

// papJSON is the whole HTTP client this example needs. It reads the body on
// every path, including failures: a PAP refusal carries its reason in the
// body, and swallowing it is how a role mistake gets misread as an outage.
func papJSON(method, url, token string, body []byte, out any) error {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s %s → %d: %s", method, url, resp.StatusCode, raw)
	}
	return json.Unmarshal(raw, out)
}
