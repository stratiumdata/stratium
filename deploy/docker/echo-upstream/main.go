// Command echo-upstream is the "trivial upstream" Task 4's plan section asks
// for: it sits behind Envoy, in the cluster ext_authz's ALLOW path routes to,
// and reports back exactly what it received -- method, path, and headers, as
// JSON.
//
// Used by services/internal/store/extauthz_integration_test.go for two
// things: proof 1 ("a permitted action reaches the upstream") needs any 200
// with the right path in it; proof 6 (the audit-digest reconstruction) uses
// it as a secondary, end-to-end sanity check that a non-credential header
// really does survive all the way through -- the reconstruction itself is
// built from what that test's own client sent (see that file's own package
// doc for why the request Envoy hands to ext_authz turned out to need
// nothing measured here). Reporting JSON rather than plain text (the shape a
// tool such as traefik/whoami would return) is what lets that Go test decode
// the answer with encoding/json instead of parsing an ad hoc text format
// whose exact wording could drift between image versions the test does not
// control.
//
// Deliberately not a real HTTP server library, framework, or third-party
// echo image: net/http already does everything this needs in about twenty
// lines, and a Go binary this small can be built and run without a shell or
// package manager in its image -- see ../Dockerfile.echo-upstream.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"strings"
)

// echoResponse is deliberately the same three-field shape as
// requestMetadata in cmd/stratium-pep/extauthz.go: method, path, and a flat
// header map.
type echoResponse struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
}

// canonicalHeaders lower-cases every header name before returning it,
// matching the casing Envoy's own ext_authz CheckRequest uses (see
// extauthz.go's own doc comment on extractBearerToken: "Envoy's own contract
// documents that it normally lower-cases the headers field's keys"), not the
// Title-Case net/http's server itself canonicalizes incoming names to.
// Multi-valued headers take only the first value: nothing this test suite
// ever sends is multi-valued, so there is no second value to lose.
func canonicalHeaders(h http.Header) map[string]string {
	out := make(map[string]string, len(h))
	for name, values := range h {
		if len(values) == 0 {
			continue
		}
		out[strings.ToLower(name)] = values[0]
	}
	return out
}

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(echoResponse{
			Method:  r.Method,
			Path:    r.URL.Path,
			Headers: canonicalHeaders(r.Header),
		})
	})
	log.Fatal(http.ListenAndServe(":8080", nil))
}
