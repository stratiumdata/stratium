package main

import (
	"net/http"
	"sort"
)

// listPolicyLanguages answers GET /v1/policy-languages with the languages this
// build can actually evaluate -- s.registry's own keys, not a list maintained
// beside it.
//
// The admin console's language selector reads this. A constant in the
// TypeScript would be a second copy of a value the browser can obtain
// first-hand, which is the reasoning uiConfig.IdPEndpoints already applies to
// the IdP's endpoints (ui.go). The failure a constant produces is silent:
// offer a language nothing is registered for and policies authored in it
// evaluate to Multi's honest deny (D10), with nothing in the UI to predict it.
//
// Sorted so the response is stable -- Go randomises map iteration, and an
// order that changes per request would make the selector reorder itself.
//
// Note this is the REGISTRY, which is not the only authority: policies.language
// carries its own CHECK (migrations/000001_baseline.up.sql) fixing the set the
// database will store. The two agree today. Where they could not, the registry
// is the right one to advertise: a language the database accepts but no engine
// evaluates is worse than one this console never offers.
func listPolicyLanguages(s *Server, w http.ResponseWriter, r *http.Request, _ Operator) {
	languages := make([]string, 0, len(s.registry))
	for name := range s.registry {
		languages = append(languages, name)
	}
	sort.Strings(languages)

	writeJSON(w, http.StatusOK, map[string][]string{"languages": languages})
}
