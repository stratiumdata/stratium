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
	"net/url"
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

	// Cross-Origin-Opener-Policy must be ABSENT. See secureHeaders' own
	// comment: the OIDC flow is a popup (N12 forbids the storage a redirect
	// would need), and a popup flow depends on window.opener surviving the
	// round trip to the IdP. COOP: same-origin severs it, callback.ts's
	// postMessage silently goes nowhere, and every sign-in fails with an
	// error that names the popup rather than the header. Asserted here so a
	// hardening pass that adds it fails this test instead of production.
	if got := rec.Header().Get("Cross-Origin-Opener-Policy"); got != "" && got != "same-origin-allow-popups" {
		t.Errorf("Cross-Origin-Opener-Policy = %q; this severs window.opener and breaks every "+
			"sign-in. Only \"\" or \"same-origin-allow-popups\" preserve the popup flow.", got)
	}
}

// TestUI_CSPAllowsTheTokenEndpointOriginOffTheIssuer is the header property
// that a CSP derived from the issuer alone gets wrong. The sign-in flow makes
// two cross-origin fetches -- discovery at the issuer, and the code exchange
// at whatever token_endpoint that document names -- and for at least one
// major IdP those are different hosts (Google Workspace: accounts.google.com
// and oauth2.googleapis.com). Missing the second one means discovery
// succeeds, the popup completes, and the token POST dies as an opaque
// "Failed to fetch": fail-closed, and undebuggable from the error text.
//
// Asserted against the SERVED header, not only against
// contentSecurityPolicy's return value, so the whole chain is covered:
// discovery -> Verifier.BrowserEndpoints -> uiConfig.IdPEndpoints -> the
// response. Breaking any link fails this.
func TestUI_CSPAllowsTheTokenEndpointOriginOffTheIssuer(t *testing.T) {
	f := newTestServerFixture(t)

	rec := doRequest(t, f.server, http.MethodGet, "/", "")
	csp := rec.Header().Get("Content-Security-Policy")

	for _, endpoint := range []string{idpAuthorizationEndpoint, idpTokenEndpoint} {
		u, err := url.Parse(endpoint)
		if err != nil {
			t.Fatalf("parse %q: %v", endpoint, err)
		}
		origin := u.Scheme + "://" + u.Host
		if !strings.Contains(csp, origin) {
			t.Errorf("Content-Security-Policy = %q, want connect-src to include %q -- the browser "+
				"fetches %s during sign-in, and it is not on the issuer's origin", csp, origin, endpoint)
		}
	}
	// An origin, never a path: a CSP source with a path in it matches nothing.
	if strings.Contains(csp, "/o/oauth2/v2/auth") || strings.Contains(csp, "/token") {
		t.Errorf("Content-Security-Policy = %q, want bare origins in connect-src, not endpoint paths", csp)
	}
}

// TestUI_DirectoryListingIsRefused: http.FileServerFS indexes any directory
// without an index.html, and Vite's assets/ has none, so without the
// noDirectoryListing wrapper GET /assets/ enumerates every bundle in the
// build. Filenames only -- but this is the one internet-facing binary here,
// and a directory index is a capability nothing needs.
func TestUI_DirectoryListingIsRefused(t *testing.T) {
	f := newTestServerFixture(t)

	rec := doRequest(t, f.server, http.MethodGet, "/assets/", "")
	if rec.Code != http.StatusNotFound {
		t.Errorf("GET /assets/ status = %d, want %d; body = %s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), ".js") {
		t.Errorf("GET /assets/ listed the build's asset filenames:\n%s", rec.Body.String())
	}

	// The root is still the admin UI, not a 404: "/" is a directory too, and
	// a wrapper that refused every trailing slash would take the whole app
	// down with the listing.
	root := doRequest(t, f.server, http.MethodGet, "/", "")
	if root.Code != http.StatusOK {
		t.Fatalf("GET / status = %d, want %d -- the directory-listing guard must not 404 the app itself",
			root.Code, http.StatusOK)
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
//
// It is rooted at clients/ui, NOT clients/ui/src. index.html and
// callback.html -- the two files that actually ship as PAGES, and the two
// most natural places to answer a "reloading signs me out" complaint with an
// inline bootstrap script -- live one directory above src/, and eslint's own
// files: ['**/*.{ts,tsx}'] does not cover HTML at all. Rooted at src/ this
// scan matched zero HTML files despite listing .html among the extensions it
// looks at, so the guard the brief asked for structurally had a hole exactly
// where the structural guard was the only one.
func TestUI_SourceNeverTouchesBrowserStorage(t *testing.T) {
	// The eslint config forbids these too (clients/ui/eslint.config.js), at
	// the moment they are typed. This is the copy that runs in the Go gate,
	// so the rule survives eslint being reconfigured, skipped, or removed --
	// and it is the ONLY one of the two that sees the HTML entry points.
	forbidden := []string{"localStorage", "sessionStorage", "indexedDB", "document.cookie"}

	if _, err := os.Stat(uiSourceDir); err != nil {
		t.Fatalf("cannot find the admin UI at %s: %v\n"+
			"If the UI moved, move this test's uiSourceDir with it -- a silently skipped N12 "+
			"check is worse than none.", uiSourceDir, err)
	}

	scanned := map[string]bool{}
	err := filepath.WalkDir(uiSourceDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// The extension switch below does not stop WalkDir DESCENDING;
			// only SkipDir does. node_modules alone is ~250 packages of
			// third-party code whose own storage use says nothing about this
			// repository's rules, and walking it would make this test slow
			// and noisy at once.
			switch d.Name() {
			case "node_modules", "dist", ".vite":
				return filepath.SkipDir
			}
			return nil
		}
		switch filepath.Ext(path) {
		case ".ts", ".tsx", ".js", ".jsx", ".html":
		default:
			return nil
		}
		// Two exemptions, both narrow and both for files that NAME these APIs
		// in order to forbid or verify them:
		//
		//   - *.test.*: auth.test.ts asserts that a completed sign-in leaves
		//     both storage APIs empty, which it cannot do without naming
		//     them. Nothing in a test file is bundled into dist.
		//   - eslint.config.js: the rule configuration that bans these
		//     identifiers has to spell them out to ban them.
		base := filepath.Base(path)
		if strings.Contains(base, ".test.") || base == "eslint.config.js" {
			return nil
		}
		body, readErr := os.ReadFile(path) //nolint:gosec // G304: path comes from WalkDir over a fixed directory
		if readErr != nil {
			return readErr
		}
		scanned[base] = true
		for _, api := range forbidden {
			// auth.ts's header and index.html's own comments both NAME these
			// APIs in prose to explain why they are absent, so a comment line
			// is not a use. Deliberately line-based and deliberately crude:
			// it under-exempts (a continuation line inside a multi-line HTML
			// comment still counts as a use), which fails loudly and is
			// trivially fixed, rather than over-exempting, which would be
			// silent.
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
		t.Fatalf("scanning %s: %v", uiSourceDir, err)
	}

	// The two HTML entry points specifically. A "scanned > 0" check would
	// still pass with the walk rooted back at src/, which is the exact defect
	// this names -- so the files that must be covered are named.
	for _, must := range []string{"index.html", "callback.html", "auth.ts"} {
		if !scanned[must] {
			t.Errorf("the N12 scan never read %s. index.html and callback.html ship as PAGES and are "+
				"covered by nothing else -- eslint only matches *.{ts,tsx} -- so a scan that misses "+
				"them leaves the structural guard hollow exactly where it is the only guard.", must)
		}
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
