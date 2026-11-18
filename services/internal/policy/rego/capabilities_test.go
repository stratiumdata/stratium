package rego

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/open-policy-agent/opa/v1/ast"

	"github.com/stratiumdata/stratium/internal/authz"
	"github.com/stratiumdata/stratium/internal/policy"
)

// A policy is evaluated inside the PDP on every decision, and inside the PAP
// when an editor validates or tests one. It must not be able to reach out of
// that process: no network calls, no DNS lookups, no reading the host's
// environment. These built-ins are refused when the policy is compiled, so a
// policy using one can be neither saved nor evaluated.
func TestEngine_RefusesBuiltinsThatReachOutsideTheProcess(t *testing.T) {
	policies := map[string]string{
		"http.send": `package stratium.policy
import rego.v1
allow if { http.send({"method": "GET", "url": "http://127.0.0.1:1/"}).status_code == 200 }`,
		"net.lookup_ip_addr": `package stratium.policy
import rego.v1
allow if { count(net.lookup_ip_addr("example.com")) > 0 }`,
		"opa.runtime": `package stratium.policy
import rego.v1
allow if { count(opa.runtime()) >= 0 }`,
	}
	for builtin, text := range policies {
		t.Run(builtin, func(t *testing.T) {
			err := New().Validate(context.Background(), text)
			if err == nil {
				t.Fatalf("Validate accepted a policy that calls %s", builtin)
			}
			if !strings.Contains(err.Error(), builtin) {
				t.Errorf("Validate error = %q, want it to name %s so the author knows what to remove", err, builtin)
			}
			_, err = New().Prepare(context.Background(),
				[]policy.StoredPolicy{{ID: "p", Name: "p", Language: "rego", Text: text}})
			if err == nil {
				t.Fatalf("Prepare accepted a stored policy that calls %s", builtin)
			}
		})
	}
}

// The property itself, not just the error: with a server standing by to be
// called, a policy that tries to send it decision data makes no request,
// because it never compiles. A regression that re-enabled http.send would
// show up here as a recorded request even if the error wording changed.
func TestEngine_PolicyCannotSendDecisionDataOut(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	text := `package stratium.policy
import rego.v1
allow if {
	resp := http.send({"method": "GET", "url": sprintf("` + srv.URL + `/?tool=%s", [input.action.tool])})
	resp.status_code == 200
}`
	set, err := New().Prepare(context.Background(),
		[]policy.StoredPolicy{{ID: "p", Name: "p", Language: "rego", Text: text}})
	if err == nil {
		// Only reached if the restriction is gone: evaluate, so the request
		// (if any) is actually attempted and counted below.
		_, _ = set.Evaluate(context.Background(), policy.EvaluationInput{Action: authz.Action{Tool: "Bash"}})
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("the policy made %d outbound HTTP request(s)", n)
	}
	if err == nil {
		t.Fatal("Prepare accepted a policy that calls http.send")
	}
}

// The restriction is narrow. Ordinary built-ins, including the in-process
// non-deterministic ones a policy legitimately needs (the current time for a
// time window), keep working.
func TestEngine_OrdinaryBuiltinsStillWork(t *testing.T) {
	text := `package stratium.policy
import rego.v1
allow if {
	startswith(input.action.tool, "Ba")
	time.now_ns() > 0
	regex.match("^B", input.action.tool)
	net.cidr_contains("10.0.0.0/8", "10.1.2.3")
	count(crypto.sha256("x")) == 64
}`
	if err := New().Validate(context.Background(), text); err != nil {
		t.Fatalf("Validate rejected ordinary built-ins: %v", err)
	}
	set, err := New().Prepare(context.Background(),
		[]policy.StoredPolicy{{ID: "p", Name: "p", Language: "rego", Text: text}})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	verdicts, err := set.Evaluate(context.Background(), policy.EvaluationInput{Action: authz.Action{Tool: "Bash"}})
	if err != nil || len(verdicts) != 1 || verdicts[0].Effect != authz.EffectAllow {
		t.Fatalf("verdicts = %+v, err = %v; want one ALLOW", verdicts, err)
	}
}

// deniedBuiltins is a denylist, which is only safe while it is complete. OPA
// marks every built-in whose result depends on something outside its
// arguments as non-deterministic, and anything that leaves the process is
// necessarily one of those. So every non-deterministic built-in must be
// either denied or explicitly reviewed as in-process. An OPA upgrade that
// adds a new one fails here until someone decides which it is.
func TestCapabilities_EveryNondeterministicBuiltinIsClassified(t *testing.T) {
	for _, b := range ast.CapabilitiesForThisVersion().Builtins {
		if !b.Nondeterministic {
			continue
		}
		if !deniedBuiltins[b.Name] && !inProcessNondeterministic[b.Name] {
			t.Errorf("OPA built-in %q is non-deterministic and is neither denied nor reviewed as in-process: "+
				"add it to deniedBuiltins if it can reach outside the process, otherwise to inProcessNondeterministic", b.Name)
		}
	}
	for name := range deniedBuiltins {
		for _, b := range policyCapabilities.Builtins {
			if b.Name == name {
				t.Errorf("denied built-in %q is still in the capabilities policies compile against", name)
			}
		}
	}
	if policyCapabilities.AllowNet == nil || len(policyCapabilities.AllowNet) != 0 {
		t.Errorf("AllowNet = %#v, want an empty non-nil list (no hosts)", policyCapabilities.AllowNet)
	}
}
