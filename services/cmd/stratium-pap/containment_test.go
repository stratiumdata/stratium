package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stratiumdata/stratium/pkg/models"
	"github.com/stratiumdata/stratium/pkg/permset"
)

func TestContainment_ReportsContainedAndNot(t *testing.T) {
	at := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	baseline := permset.Set{
		Tools: []string{"Read", "Write"}, MaxTier: models.ActionTierExternalComms, ExpiresAt: at,
	}
	narrower := permset.Set{
		Tools: []string{"Read"}, MaxTier: models.ActionTierReadOnly, ExpiresAt: at,
	}
	wider := permset.Set{
		Tools: []string{"Read", "Bash"}, MaxTier: models.ActionTierExternalComms, ExpiresAt: at,
	}

	if got := answerContainment(questionDelegation, baseline, narrower); !got.Contained || got.Reason != "" {
		t.Errorf("narrower candidate must be contained, got %+v", got)
	}
	got := answerContainment(questionDelegation, baseline, wider)
	if got.Contained {
		t.Error("a candidate adding a tool must not be contained")
	}
	if got.Reason != "child tool Bash not in parent approved_tools" {
		t.Errorf("Reason = %q, want the tool reason verbatim", got.Reason)
	}
}

func TestContainment_RouteIsRegisteredAtEditor(t *testing.T) {
	var found bool
	for _, rt := range routeTable {
		if rt.Pattern == "POST /v1/containment" {
			found = true
			if rt.MinRole != RoleEditor {
				t.Errorf("MinRole = %v, want RoleEditor: every POST route here is gated RoleEditor, "+
					"same as its nearest analogue POST /v1/policies/test, even though this handler writes nothing", rt.MinRole)
			}
		}
	}
	if !found {
		t.Error("POST /v1/containment is not in routeTable")
	}
}

// TestCheckContainment_OutOfRangeMaxTier_Refused proves the wire path
// actually calls ParseActionTier: containmentRequest decodes MaxTier as a
// raw JSON int straight into models.ActionTier (the type compiles the
// assignment; nothing about it range-checks), so an out-of-range value must
// be caught by the handler, not merely by containmentOf's callers passing
// good values in every other test in this file.
func TestCheckContainment_OutOfRangeMaxTier_Refused(t *testing.T) {
	f := newTestServerFixture(t)
	body := map[string]any{
		"baseline":  map[string]any{"max_action_tier": 99},
		"candidate": map[string]any{"max_action_tier": 0},
	}
	rec := doJSONRequest(t, f.server, http.MethodPost, "/v1/containment", f.token(t, "org-editors"), body)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d, body = %s", rec.Code, http.StatusBadRequest, rec.Body.String())
	}
}

// TestContainment_TheTwoQuestionsDisagreeOnAnIntroducedKey is the reason the
// `question` field exists. ONE input, both questions, opposite answers:
// adding a classification cap is refused as a child delegation (a deliberate
// shape rule) and is a narrowing as a grant diff (an absent cap means
// unrestricted).
//
// Asserting both on the same input is the point. Two separate tests, each
// checking one question against its own fixture, would pass against an
// implementation that ignored the field entirely.
func TestContainment_TheTwoQuestionsDisagreeOnAnIntroducedKey(t *testing.T) {
	at := time.Date(2026, 9, 16, 12, 0, 0, 0, time.UTC)
	baseline := permset.Set{
		Tools: []string{"Read"}, MaxTier: models.ActionTierReadOnly,
		ClassificationCaps: map[string]string{}, ExpiresAt: at,
	}
	candidate := baseline
	candidate.ClassificationCaps = map[string]string{"nato": "SECRET"}

	asDelegation := answerContainment(questionDelegation, baseline, candidate)
	if asDelegation.Contained {
		t.Error("as a DELEGATION question, introducing a cap must be refused — that shape rule is deliberate")
	}
	if asDelegation.Question != questionDelegation {
		t.Errorf("response question = %q, want %q", asDelegation.Question, questionDelegation)
	}

	asGrant := answerContainment(questionGrant, baseline, candidate)
	if !asGrant.Contained {
		t.Errorf("as a GRANT question, introducing a cap NARROWS; got %q", asGrant.Reason)
	}
	if asGrant.Question != questionGrant {
		t.Errorf("response question = %q, want %q", asGrant.Question, questionGrant)
	}
}

// TestCheckContainment_DefaultsToTheDelegationQuestion keeps every caller
// that predates this field working, and pins which answer they keep getting.
func TestCheckContainment_DefaultsToTheDelegationQuestion(t *testing.T) {
	f := newTestServerFixture(t)
	at := "2026-12-01T00:00:00Z"
	rec := doJSONRequest(t, f.server, http.MethodPost, "/v1/containment", f.token(t, "org-editors"),
		map[string]any{
			"baseline":  map[string]any{"approved_tools": []string{"Read"}, "max_action_tier": 1, "classification_caps": map[string]string{}, "expires_at": at},
			"candidate": map[string]any{"approved_tools": []string{"Read"}, "max_action_tier": 1, "classification_caps": map[string]string{"nato": "SECRET"}, "expires_at": at},
		})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200, body = %s", rec.Code, rec.Body.String())
	}
	var got containmentResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v; body = %s", err, rec.Body.String())
	}
	if got.Question != questionDelegation {
		t.Errorf("an omitted question answered %q, want %q", got.Question, questionDelegation)
	}
	if got.Contained {
		t.Error("the delegation question must still refuse an introduced cap")
	}
}

// TestCheckContainment_RefusesAnUnknownQuestion does not fall back to the
// default. The two answers differ, so guessing which one a caller meant is
// the one thing this endpoint must never do.
func TestCheckContainment_RefusesAnUnknownQuestion(t *testing.T) {
	f := newTestServerFixture(t)
	rec := doJSONRequest(t, f.server, http.MethodPost, "/v1/containment", f.token(t, "org-editors"),
		map[string]any{"question": "widening", "baseline": map[string]any{}, "candidate": map[string]any{}})

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "widening") {
		t.Errorf("body does not name the offending value: %s", rec.Body.String())
	}
}
