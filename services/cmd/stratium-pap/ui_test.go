// ui_test.go proves the three things about the embedded admin UI that could
// otherwise fail silently in production while every other test in this
// package stayed green:
//
//  1. The embedded filesystem holds a REAL build, not a placeholder (N13).
//     This is the load-bearing test of the whole task's UI half -- see
//     TestUI_EmbeddedFilesystemIsARealBuild.
//  2. Serving the UI at "GET /" did not open a hole in the API's own
//     authorization (TestUI_DoesNotShadowAnyAPIRoute).
//  3. No source file in clients/ui touches a browser storage API (N12,
//     TestUI_SourceNeverTouchesBrowserStorage).
//
// The fourth property N14 names -- "a viewer is refused every write with the
// client bypassed" -- is proven where the writes are, in approvals_test.go's
// TestViewer_CanListButCannotDecide and delegations_test.go's
// TestViewer_CanListButCannotRevoke, both of which issue real HTTP requests
// with no UI involved at all. That is deliberately not in this file: a test
// of "the UI carries no authorization" that lived beside the UI would be one
// more thing to delete along with it.
package main

import (
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// uiSourceDir is the UI's source tree, relative to this package. `go test`
// runs with the package directory as its working directory, so this resolves
// the same way for every caller.
const uiSourceDir = "../../../clients/ui"

// hashedAsset matches the reference a real Vite build writes into
// index.html: /assets/<entry>-<contenthash>.js. The hash is what a
// placeholder cannot fake by accident -- a hand-written stub index.html
// points at a plain filename, and an empty one points at nothing at all.
var hashedAsset = regexp.MustCompile(`/assets/[A-Za-z0-9._-]+-[A-Za-z0-9_-]{8,}\.js`)

// TestUI_EmbeddedFilesystemIsARealBuild is the reason this file exists.
//
// //go:embed dist fails the build outright when dist/ is absent, and the
// reflex fix for that -- committing a placeholder index.html so the compiler
// stops complaining -- would turn a loud build failure into a silent
// deployment of a blank admin plane. Nothing else in this repository would
// notice: the binary builds, the server starts, GET / returns 200, and the
// page is empty.
//
// So this asserts what only a real build produces. index.html must reference
// a content-hashed asset bundle, and that bundle must actually be in the
// embedded filesystem at the path index.html names. A placeholder fails the
// first check; a stale or half-copied dist fails the second.
func TestUI_EmbeddedFilesystemIsARealBuild(t *testing.T) {
	index, err := fs.ReadFile(uiRoot, "index.html")
	if err != nil {
		t.Fatalf("the embedded UI has no index.html: %v\n"+
			"Run `make ui` (or `make build`) -- the UI is built into cmd/stratium-pap/dist, "+
			"which is git-ignored and produced by the Vite build, never committed.", err)
	}

	refs := hashedAsset.FindAllString(string(index), -1)
	if len(refs) == 0 {
		t.Fatalf("the embedded index.html references no content-hashed asset bundle, so it is a "+
			"placeholder rather than a real build. This would deploy a blank admin UI with every "+
			"other gate green -- exactly what this test exists to prevent.\nindex.html:\n%s", index)
	}

	// Named, not merely referenced: an index.html pointing at a bundle that
	// is not in the embedded filesystem serves a page that fetches a 404.
	for _, ref := range refs {
		name := strings.TrimPrefix(ref, "/")
		if _, err := fs.Stat(uiRoot, name); err != nil {
			t.Errorf("index.html references %s, which is not in the embedded filesystem: %v", ref, err)
		}
	}
}

// TestUI_EmbeddedFilesystemHasTheOIDCCallback: callback.html is the redirect
// target the sign-in popup lands on (clients/ui/src/auth.ts). It is a second
// Vite entry point, so a build misconfigured back to a single entry would
// still pass the test above -- index.html would be perfectly real -- while
// making sign-in impossible.
func TestUI_EmbeddedFilesystemHasTheOIDCCallback(t *testing.T) {
	callback, err := fs.ReadFile(uiRoot, "callback.html")
	if err != nil {
		t.Fatalf("the embedded UI has no callback.html, so the OIDC redirect target is missing "+
			"and no operator can sign in: %v", err)
	}
	if !hashedAsset.MatchString(string(callback)) {
		t.Errorf("callback.html references no hashed bundle; it is a placeholder:\n%s", callback)
	}
}

// TestUI_ServesTheIndexWithoutAToken: the page has to load before it can
// authenticate. This is the one document route on this server reachable
// without a bearer token, and it must stay reachable -- an admin plane whose
// login page requires being logged in is not one.
func TestUI_ServesTheIndexWithoutAToken(t *testing.T) {
	f := newTestServerFixture(t)

	rec := doRequest(t, f.server, http.MethodGet, "/", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want %d", rec.Code, http.StatusOK)
	}
	if !strings.Contains(rec.Body.String(), "<div id=\"root\">") {
		t.Errorf("GET / did not serve the admin UI's index.html; body = %s", rec.Body.String())
	}
	for header, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	} {
		if got := rec.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") || !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Errorf("Content-Security-Policy = %q, want a deny-by-default policy that refuses framing", csp)
	}
	// The IdP's own origin has to be reachable or sign-in cannot start; a CSP
	// that forgot it would break login in a way no Go test would otherwise see.
	if !strings.Contains(csp, f.idp.server.URL) {
		t.Errorf("Content-Security-Policy = %q, want connect-src to include the configured issuer %q",
			csp, f.idp.server.URL)
	}
}

// TestUI_ConfigEndpointIsPublicAndCarriesNoSecret: the browser must be told
// which IdP to authenticate against before it holds any token, so this route
// is deliberately outside authorize. The assertion that matters is the
// second one -- everything it returns is public by construction, and this
// fails the moment a field that is not gets added to uiConfig.
func TestUI_ConfigEndpointIsPublicAndCarriesNoSecret(t *testing.T) {
	f := newTestServerFixture(t)

	rec := doRequest(t, f.server, http.MethodGet, "/ui-config", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /ui-config status = %d, want %d (a browser has no token yet)", rec.Code, http.StatusOK)
	}
	got := decodeBody[map[string]any](t, rec)

	want := fixtureUIConfig(f.idp.server.URL)
	if got["issuer"] != want.Issuer || got["client_id"] != want.ClientID ||
		got["audience"] != want.Audience || got["scope"] != want.Scope {
		t.Errorf("/ui-config = %v, want it to mirror the configured %+v", got, want)
	}

	// Every key must be one of the four public values above. A client
	// SECRET, a database URL, or anything else added to uiConfig without
	// thinking about who reads this endpoint fails here.
	allowed := map[string]bool{"issuer": true, "client_id": true, "audience": true, "scope": true}
	for key := range got {
		if !allowed[key] {
			t.Errorf("/ui-config returned an unexpected field %q: this endpoint is served to "+
				"unauthenticated callers and may carry nothing that is not public", key)
		}
	}
}

// TestUI_DoesNotShadowAnyAPIRoute: "GET /" matches every path net/http has no
// more specific pattern for, which is exactly the shape that could quietly
// serve the UI's 404 page in place of an authorization refusal. Go 1.22+
// resolves by pattern specificity rather than registration order, so every
// routeTable GET should still reach authorize -- proven here per route rather
// than assumed from the documented precedence rule.
func TestUI_DoesNotShadowAnyAPIRoute(t *testing.T) {
	f := newTestServerFixture(t)

	for _, rt := range routeTable {
		method, path, ok := strings.Cut(rt.Pattern, " ")
		if !ok || method != http.MethodGet {
			continue // "GET /" can only ever shadow another GET
		}
		// A concrete path for the wildcard routes; any value works, since the
		// request must be refused before a handler ever parses it.
		concrete := strings.ReplaceAll(path, "{id}", "00000000-0000-0000-0000-000000000000")
		rec := doRequest(t, f.server, http.MethodGet, concrete, "")
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("GET %s with no token: status = %d, want %d -- the static file server has "+
				"shadowed an API route and is answering in place of authorize", concrete, rec.Code,
				http.StatusUnauthorized)
		}
	}
	assertExpectationsMet(t, f.mock) // nothing reached the store
}

// TestUI_SourceNeverTouchesBrowserStorage is N12 asserted structurally, which
// the ruling itself asks for: the operator's token can approve any escalation
// and revoke every delegation in the tenant, so a single later edit that
// "just caches it across reloads" is the whole failure. A code review catches
// that once; this catches it every time.
//
// The scan is over the UI's own source, not the built bundle: a dependency
// with its own unrelated use of localStorage would fail a bundle scan for a
// reason that has nothing to do with this token, and the rule being enforced
// is about the code in this repository.
func TestUI_SourceNeverTouchesBrowserStorage(t *testing.T) {
	// The eslint config forbids these too (clients/ui/eslint.config.js), at
	// the moment they are typed. This is the copy that runs in the Go gate,
	// so the rule survives eslint being reconfigured, skipped, or removed.
	forbidden := []string{"localStorage", "sessionStorage", "indexedDB", "document.cookie"}

	root := filepath.Join(uiSourceDir, "src")
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("cannot find the admin UI source at %s: %v\n"+
			"If the UI moved, move this test's uiSourceDir with it -- a silently skipped N12 "+
			"check is worse than none.", root, err)
	}

	var scanned int
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch filepath.Ext(path) {
		case ".ts", ".tsx", ".js", ".jsx", ".html":
		default:
			return nil
		}
		// Test files are exempt, and only test files: clients/ui/src/
		// auth.test.ts asserts that a completed sign-in leaves both storage
		// APIs empty, which it cannot do without naming them. Nothing in a
		// test file is bundled into dist, so nothing in one can put a token
		// anywhere. The eslint config lifts the same rule on the same files
		// for the same reason.
		if strings.Contains(filepath.Base(path), ".test.") {
			return nil
		}
		body, readErr := os.ReadFile(path) //nolint:gosec // G304: path comes from WalkDir over a fixed directory
		if readErr != nil {
			return readErr
		}
		scanned++
		for _, api := range forbidden {
			// The eslint config and the auth.ts header both NAME these APIs
			// in prose to explain why they are absent. Only lines that are
			// not comments count as a use.
			for i, line := range strings.Split(string(body), "\n") {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "*") ||
					strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "<!--") {
					continue
				}
				if strings.Contains(line, api) {
					t.Errorf("%s:%d uses %s: N12 keeps the operator's token in memory only, with no "+
						"storage fallback of any kind. This token can approve any escalation and revoke "+
						"every delegation in the tenant.\n\t%s", path, i+1, api, trimmed)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scanning %s: %v", root, err)
	}
	if scanned == 0 {
		t.Fatalf("scanned no files under %s: this check passed without checking anything", root)
	}
}

// TestContentSecurityPolicy_MalformedIssuerYieldsNoOrigin: loadConfig
// requires the issuer to be present, never that it parses as a URL. A
// garbage value must not produce a directive that a browser parses as
// something permissive -- an empty connect-src addition fails sign-in
// visibly, which is the safe direction.
func TestContentSecurityPolicy_MalformedIssuerYieldsNoOrigin(t *testing.T) {
	csp := contentSecurityPolicy("not a url at all")
	if !strings.Contains(csp, "connect-src 'self';") {
		t.Errorf("contentSecurityPolicy(garbage) = %q, want connect-src limited to 'self'", csp)
	}
	if strings.Contains(csp, "not a url") {
		t.Errorf("contentSecurityPolicy(garbage) = %q, want the unparseable value left out entirely", csp)
	}
}
