// conformance_test.go runs sdk/conformance/cases -- fixtures shared with
// every Stratium SDK, sdk/python included (sdk/python/tests/test_conformance.py
// is the same cases run against Python) -- against THIS binary's own
// cacheEntryUsable and resolveApproval, not a copy of either. It lives in
// package main precisely so it can call both directly: they are unexported
// here, and a separate cmd/conformance binary would have needed them
// exported or lifted into a shared package, either of which risks a runner
// that carries its own copy of the predicates it is supposed to be
// checking. A copy would pass every case while the product drifted --
// invisibly, because the suite would stay green -- which is the exact
// failure sdk/conformance/README.md says this suite exists to prevent.
//
// See that README for the fixture format (including the two documented,
// intentional Go/Python divergences) before changing anything here.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc"

	"github.com/stratiumdata/stratium/internal/pdpgrpc"
)

// The cases live outside the Go module, so a moved directory must fail loudly
// here rather than silently running zero cases.
const conformanceDir = "../../../sdk/conformance/cases"

func TestConformanceCases(t *testing.T) {
	entries, err := os.ReadDir(conformanceDir)
	if err != nil {
		t.Fatalf("read %s: %v -- if sdk/conformance moved, update conformanceDir",
			conformanceDir, err)
	}

	ran := 0
	for _, e := range entries {
		if filepath.Ext(e.Name()) != ".json" {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(conformanceDir, e.Name()))
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		var c conformanceCase
		if err := json.Unmarshal(raw, &c); err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		if got := c.Name + ".json"; got != e.Name() {
			t.Errorf("%s: name field is %q", e.Name(), c.Name)
		}

		t.Run(c.Name, func(t *testing.T) { runConformanceCase(t, c) })
		ran++
	}

	if ran == 0 {
		t.Fatal("zero conformance cases ran")
	}
	t.Logf("%d conformance cases ran against the Go reference", ran)
}

// conformanceCase mirrors one fixture file's top-level JSON object exactly
// as sdk/conformance/README.md documents it.
type conformanceCase struct {
	Name    string            `json:"name"`
	Subject string            `json:"subject"`
	Config  conformanceConfig `json:"config"`
	Steps   []conformanceStep `json:"steps"`
	Expect  conformanceExpect `json:"expect"`
}

// conformanceConfig covers both subjects' config shapes at once -- a cache
// case sets only StalenessWindowSeconds, an escalation case only the other
// two -- rather than two separate case types, since conformanceCase itself
// is not generic over subject and every case still unmarshals through one
// struct either way.
type conformanceConfig struct {
	StalenessWindowSeconds *float64 `json:"staleness_window_seconds"`
	PollIntervalSeconds    *float64 `json:"poll_interval_seconds"`
	TimeoutSeconds         *float64 `json:"timeout_seconds"`
}

// conformanceStep is one entry in "steps". Which of Put/Get/Poll/PollRaises
// is set depends on the case's subject; Expect here is the per-step
// "hit"/"miss" a cache "get" step carries -- a sibling of "get" in the JSON,
// not nested inside it -- and is unrelated to conformanceCase.Expect, the
// case-level assertion escalation cases use instead.
type conformanceStep struct {
	At         float64         `json:"at"`
	Put        *conformancePut `json:"put"`
	Get        *conformanceGet `json:"get"`
	Poll       *string         `json:"poll"`
	PollRaises *string         `json:"poll_raises"`
	Expect     *string         `json:"expect"`
}

type conformancePut struct {
	Effect              string  `json:"effect"`
	Epoch               int64   `json:"epoch"`
	DelegationExpiresAt float64 `json:"delegation_expires_at"`
}

type conformanceGet struct {
	Epoch          int64   `json:"epoch"`
	TokenExpiresAt float64 `json:"token_expires_at"`
}

// conformanceExpect is the case-level "expect" object. EffectSet records
// whether the JSON object actually had an "effect" key at all -- plain
// encoding/json cannot tell "key absent" from "key present with value
// null" via a bare *string field (both decode to a nil pointer), and the
// README requires exactly that distinction: "effect": null means "no
// decision was reached" (a real assertion, e.g. Python's transport-failure
// case), which is a different thing from a case that never mentions effect
// at all and asserts only Allowed. UnmarshalJSON below is what actually
// makes the distinction, by checking key presence on a raw map first.
type conformanceExpect struct {
	EffectSet      bool
	Effect         *string
	Allowed        *bool
	Retried        *bool
	ReasonContains string
}

func (e *conformanceExpect) UnmarshalJSON(data []byte) error {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	if v, ok := raw["effect"]; ok {
		e.EffectSet = true
		if string(v) != "null" {
			var s string
			if err := json.Unmarshal(v, &s); err != nil {
				return fmt.Errorf("expect.effect: %w", err)
			}
			e.Effect = &s
		}
	}
	if v, ok := raw["allowed"]; ok {
		var b bool
		if err := json.Unmarshal(v, &b); err != nil {
			return fmt.Errorf("expect.allowed: %w", err)
		}
		e.Allowed = &b
	}
	if v, ok := raw["retried"]; ok {
		var b bool
		if err := json.Unmarshal(v, &b); err != nil {
			return fmt.Errorf("expect.retried: %w", err)
		}
		e.Retried = &b
	}
	if v, ok := raw["reason_contains"]; ok {
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return fmt.Errorf("expect.reason_contains: %w", err)
		}
		e.ReasonContains = s
	}
	return nil
}

// runConformanceCase dispatches on subject. Neither branch below
// reimplements any of cacheEntryUsable's five conditions or
// resolveApproval's escalation/retry branches -- both call straight into
// stratium-pep's own unexported functions and only translate fixture JSON
// into their parameters.
func runConformanceCase(t *testing.T, c conformanceCase) {
	switch c.Subject {
	case "cache":
		runCacheCase(t, c)
	case "escalation":
		runEscalationCase(t, c)
	default:
		t.Fatalf("%s: unknown subject %q", c.Name, c.Subject)
	}
}

// secondsToDuration turns one of the fixture's plain-seconds numbers (an
// "at", a "delegation_expires_at", a "token_expires_at", a config duration)
// into a time.Duration. 1e9 seconds (the fixtures' own "far future" value)
// is ~1e18ns, comfortably inside int64's range.
func secondsToDuration(s float64) time.Duration {
	return time.Duration(s * float64(time.Second))
}

// conformanceEffect maps a fixture's effect name to stratium-pep's own
// pdpgrpc.Effect enum -- the wire/decision type cacheEntryUsable and
// resolveApproval actually speak, not a runner-invented stand-in for it.
func conformanceEffect(name string) (pdpgrpc.Effect, error) {
	switch name {
	case "ALLOW":
		return pdpgrpc.Effect_EFFECT_ALLOW, nil
	case "DENY":
		return pdpgrpc.Effect_EFFECT_DENY, nil
	case "ESCALATE":
		return pdpgrpc.Effect_EFFECT_ESCALATE, nil
	default:
		return 0, fmt.Errorf("unknown effect %q", name)
	}
}

// conformanceBase anchors every case's fake clock. Its absolute value is
// arbitrary and never compared against a real wall clock -- only against
// other instants derived the same way (base.Add(secondsToDuration(x))) --
// so any fixed instant works; Unix 0 keeps the arithmetic obviously
// unrelated to whatever day this suite happens to run on.
var conformanceBase = time.Unix(0, 0).UTC()

// runCacheCase drives cacheEntryUsable directly, once per "get" step, with
// a cacheEntry built from the fixture's own "put" and a freshly-signed
// token whose "exp" claim is exactly that step's token_expires_at -- both
// on stratium-pep's own fake clock (conformanceBase + the step's "at"), so
// every one of the five usability conditions is the real function's own
// answer, never this file's guess at it.
func runCacheCase(t *testing.T, c conformanceCase) {
	t.Helper()
	if c.Config.StalenessWindowSeconds == nil {
		t.Fatalf("%s: cache case config missing staleness_window_seconds", c.Name)
	}
	staleness := secondsToDuration(*c.Config.StalenessWindowSeconds)

	var entry cacheEntry
	haveEntry := false

	for i, step := range c.Steps {
		now := conformanceBase.Add(secondsToDuration(step.At))
		switch {
		case step.Put != nil:
			effect, err := conformanceEffect(step.Put.Effect)
			if err != nil {
				t.Fatalf("%s: step %d: %v", c.Name, i, err)
			}
			entry = cacheEntry{
				Decision:            effect,
				Epoch:               step.Put.Epoch,
				DelegationExpiresAt: conformanceBase.Add(secondsToDuration(step.Put.DelegationExpiresAt)),
				CachedAt:            now,
			}
			haveEntry = true
		case step.Get != nil:
			if step.Expect == nil {
				t.Fatalf("%s: step %d: get step asserts nothing (no \"expect\")", c.Name, i)
			}
			token := signedTestToken(t, conformanceBase.Add(secondsToDuration(step.Get.TokenExpiresAt)))
			usable := haveEntry && cacheEntryUsable(entry, step.Get.Epoch, token, now, staleness)
			got := "miss"
			if usable {
				got = "hit"
			}
			if got != *step.Expect {
				t.Errorf("%s: at t=%v want %s got %s", c.Name, step.At, *step.Expect, got)
			}
		default:
			t.Fatalf("%s: step %d has neither put nor get", c.Name, i)
		}
	}
}

// conformancePollStep is one scripted GetApproval outcome: a status, or an
// error to raise instead.
type conformancePollStep struct {
	raises bool
	text   string // the status ("pending"/"approved"/"denied"), or the error text if raises
}

// conformanceEscalationClient implements pdpgrpc.PDPServiceClient in
// memory -- resolveApproval takes the interface, not a concrete type, so
// nothing here needs a real gRPC transport -- scripting GetApproval's
// call-ordered responses and recording whether Decide (the post-approval
// retry) was ever called. Embedding the nil interface satisfies
// CreateDelegation/IssueToken, which resolveApproval never calls; invoking
// either here would be a bug in this file, not something to guard against.
//
// The retry, when reached, always answers ALLOW -- matching
// sdk/python/tests/test_conformance.py's own retry() fixture exactly (it
// too hardcodes Effect.ALLOW): no fixture field says what the retry's
// Decide should return, because only escalation-approved-retries-decide
// ever reaches it, and what it means for an approval to be "worth
// retrying" is scripted by the test harness, not read out of the case.
type conformanceEscalationClient struct {
	pdpgrpc.PDPServiceClient

	steps       []conformancePollStep
	pollCalls   int
	decideCalls int
}

func (c *conformanceEscalationClient) GetApproval(_ context.Context, _ *pdpgrpc.GetApprovalRequest, _ ...grpc.CallOption) (*pdpgrpc.GetApprovalResponse, error) {
	i := c.pollCalls
	if i >= len(c.steps) {
		i = len(c.steps) - 1
	}
	c.pollCalls++
	step := c.steps[i]
	if step.raises {
		return nil, errors.New(step.text)
	}
	return &pdpgrpc.GetApprovalResponse{Status: step.text}, nil
}

func (c *conformanceEscalationClient) Decide(_ context.Context, _ *pdpgrpc.DecideRequest, _ ...grpc.CallOption) (*pdpgrpc.DecideResponse, error) {
	c.decideCalls++
	return &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ALLOW}, nil
}

// conformanceApprovalID is the fixture-independent id every escalation case
// polls for -- the README's own examples and the Python harness both use
// "ap-1", and resolveApproval never inspects the id beyond forwarding it to
// GetApproval/Decide, so one fixed value serves every case.
const conformanceApprovalID = "ap-1"

// conformanceConnectTimeout is resolveApproval's connectTimeout parameter --
// the retry Decide call's own budget, independent of pollInterval/timeout.
// conformanceEscalationClient answers every call instantly, so its value
// only has to be positive and larger than a nanosecond.
const conformanceConnectTimeout = 5 * time.Second

// runEscalationCase drives resolveApproval directly with a scripted
// GetApproval/Decide double, never reimplementing the wait, the retry, or
// the fail-closed defaults resolveApproval itself owns. Go's poll loop uses
// real context.WithTimeout/time.Ticker internally (unlike the Python
// harness's injectable fake clock -- resolveApproval takes no clock
// parameter to fake), so this actually sleeps real wall-clock time bounded
// by each case's own poll_interval_seconds/timeout_seconds -- at most a few
// seconds across the whole suite.
func runEscalationCase(t *testing.T, c conformanceCase) {
	t.Helper()
	if c.Config.PollIntervalSeconds == nil || c.Config.TimeoutSeconds == nil {
		t.Fatalf("%s: escalation case config missing poll_interval_seconds or timeout_seconds", c.Name)
	}
	if !c.Expect.EffectSet && c.Expect.Allowed == nil {
		t.Fatalf("%s: expect asserts neither effect nor allowed -- binds nothing", c.Name)
	}
	if c.Expect.Retried == nil {
		t.Fatalf("%s: expect missing retried", c.Name)
	}

	steps := make([]conformancePollStep, 0, len(c.Steps))
	for i, s := range c.Steps {
		switch {
		case s.PollRaises != nil:
			steps = append(steps, conformancePollStep{raises: true, text: *s.PollRaises})
		case s.Poll != nil:
			steps = append(steps, conformancePollStep{text: *s.Poll})
		default:
			t.Fatalf("%s: step %d has neither poll nor poll_raises", c.Name, i)
		}
	}

	client := &conformanceEscalationClient{steps: steps}
	req := &pdpgrpc.DecideRequest{}
	resp := &pdpgrpc.DecideResponse{Effect: pdpgrpc.Effect_EFFECT_ESCALATE, ApprovalId: conformanceApprovalID}

	pollInterval := secondsToDuration(*c.Config.PollIntervalSeconds)
	timeout := secondsToDuration(*c.Config.TimeoutSeconds)

	effect, reason := resolveApproval(context.Background(), client, conformanceConnectTimeout, pollInterval, timeout, req, resp)

	retried := client.decideCalls > 0
	if retried != *c.Expect.Retried {
		t.Errorf("%s: retried = %v, want %v", c.Name, retried, *c.Expect.Retried)
	}

	if c.Expect.Allowed != nil {
		allowed := effect == pdpgrpc.Effect_EFFECT_ALLOW
		if allowed != *c.Expect.Allowed {
			t.Errorf("%s: allowed = %v, want %v", c.Name, allowed, *c.Expect.Allowed)
		}
	}

	if c.Expect.EffectSet {
		if c.Expect.Effect == nil {
			// Go's resolveApproval returns (pdpgrpc.Effect, string) -- a
			// plain value type with no way to say "no decision was
			// reached" (the README's own first documented divergence).
			// A case asserting "effect": null is therefore never
			// satisfiable in Go; report the mismatch honestly rather than
			// skip the assertion.
			t.Errorf("%s: expect.effect is null (no decision reached), but Go always returns a concrete effect (got %v) -- see sdk/conformance/README.md's documented divergence", c.Name, effect)
		} else {
			want, err := conformanceEffect(*c.Expect.Effect)
			if err != nil {
				t.Fatalf("%s: %v", c.Name, err)
			}
			if effect != want {
				t.Errorf("%s: effect = %v, want %v", c.Name, effect, want)
			}
		}
	}

	if c.Expect.ReasonContains != "" && !strings.Contains(reason, c.Expect.ReasonContains) {
		t.Errorf("%s: reason %q does not contain %q", c.Name, reason, c.Expect.ReasonContains)
	}
}
