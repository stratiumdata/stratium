// ui.go embeds the admin UI (clients/ui) into this binary and serves it,
// alongside the one public, unauthenticated endpoint that UI needs before it
// can authenticate at all.
//
// N13 -- one artifact. The PDP and PEP ship as single binaries and so does
// this: an operator deploys stratium-pap and has the admin plane, with no
// second static-hosting story, no CDN, and no way for the UI and the API it
// talks to to be different versions of each other.
//
// # The build-order problem, and how it is solved here
//
// //go:embed dist is not a runtime lookup. It is resolved by the compiler,
// and a missing dist/ directory is a hard build failure:
//
//	cmd/stratium-pap/ui.go:NN:12: pattern dist: no matching files found
//
// dist/ is a build output, git-ignored (root .gitignore, the bare `dist/`
// pattern that matches at any depth) and deliberately never committed. So on
// a clean checkout it does not exist, and `go build ./...` cannot succeed
// until something has produced it.
//
// The reflex fix -- commit a placeholder index.html so the compiler is happy
// -- is worse than the failure it silences: the build then succeeds forever,
// and ships an admin plane serving a blank page. Nothing fails; the UI is
// simply gone. That is the specific defect uiIsARealBuild (ui_test.go) exists
// to make impossible: it fails the standard `go test` gate unless the
// embedded index.html references a content-hashed asset bundle, which only a
// real Vite build produces.
//
// So the ordering is owned by the Makefile instead, where it is visible:
// `ui` builds clients/ui into this directory, and build/test/vet/lint all
// depend on it. A clean checkout runs `make build` (or any other gate
// target) and gets a working binary; CI calls the same targets, so there is
// one definition of the ordering and not two. Running `go build ./...`
// directly, before `make ui` has ever run, is the one path that still fails
// -- with the message quoted above, which this comment exists to explain.
package main

import (
	"embed"
	"io/fs"
	"net/http"
	"net/url"
	"strings"
)

// uiFS is the built admin UI. Not `all:dist`: the plain form skips files
// beginning with "." or "_", which is what we want -- Vite writes a .vite/
// metadata directory under some configurations, and nothing in it is served.
//
//go:embed dist
var uiFS embed.FS

// uiRoot is uiFS with the "dist" prefix stripped, so index.html is at "/"
// rather than "/dist/". Resolved once at init: the only way fs.Sub can fail
// here is a dist directory that the embed above already refused to compile
// without, so a failure is a programming error, not a runtime condition, and
// panicking at init is the correct treatment -- exactly the shape
// template.Must has for the same situation.
var uiRoot = func() fs.FS {
	sub, err := fs.Sub(uiFS, "dist")
	if err != nil {
		panic("embedded UI has no dist directory: " + err.Error())
	}
	return sub
}()

// uiConfig is the public, non-secret configuration the browser needs before
// it can sign in: which IdP to authenticate against, as which client, for
// which audience and scopes.
//
// Every field here is public by construction. An OIDC public client's id is
// not a credential -- PKCE is what replaces the client secret a browser
// cannot keep (see clients/ui/src/auth.ts) -- and issuer and audience are
// both visible in any token the IdP issues. There is no secret this endpoint
// could leak, which is why it is the one route on this server reachable
// without a bearer token.
type uiConfig struct {
	Issuer   string `json:"issuer"`
	ClientID string `json:"client_id"`
	Audience string `json:"audience"`
	Scope    string `json:"scope"`
}

// contentSecurityPolicy is served with the UI. This is the only
// internet-facing binary in the system, and N12's whole argument for keeping
// the operator's token out of browser storage is the blast radius of an XSS
// in this page -- so the header that most directly reduces the chance of one
// belongs here rather than being left to a reverse proxy that may not exist.
//
// Each directive, and why it is the value it is:
//
//   - default-src 'none': deny by default, name what is allowed. The same
//     posture every authorization decision in this system takes.
//   - script-src/style-src 'self': Vite emits external module scripts and one
//     external stylesheet -- no inline script and no inline style -- so
//     neither 'unsafe-inline' nor a nonce is needed. If a future dependency
//     needs one, that is a reason to reconsider the dependency.
//   - connect-src 'self' plus the IdP's origin: the UI fetches its own API
//     and the issuer's discovery and token endpoints, and nothing else. The
//     IdP origin is derived from configuration rather than hard-coded, so a
//     deployment against any IdP works with no edit here.
//   - form-action 'none' and frame-ancestors 'none': this page submits no
//     forms, and framing an admin plane is clickjacking with extra steps.
//   - base-uri 'none': a base tag injected into this page could repoint every
//     relative URL, including the API paths the token is sent to.
func contentSecurityPolicy(issuer string) string {
	// A malformed issuer yields no origin rather than a broken directive: the
	// UI's sign-in then fails visibly at the connect-src boundary, which is
	// the fail-closed direction. loadConfig has already required the value to
	// be present; it does not require it to parse.
	idp := ""
	if u, err := url.Parse(issuer); err == nil && u.Scheme != "" && u.Host != "" {
		idp = " " + u.Scheme + "://" + u.Host
	}
	return strings.Join([]string{
		"default-src 'none'",
		"script-src 'self'",
		"style-src 'self'",
		"img-src 'self' data:",
		"font-src 'self'",
		"connect-src 'self'" + idp,
		"form-action 'none'",
		"frame-ancestors 'none'",
		"base-uri 'none'",
	}, "; ")
}

// registerUI wires the two routes the admin UI needs onto mux, both
// deliberately OUTSIDE authorize:
//
//   - GET /ui-config, because a browser cannot present a token before it has
//     been told where to get one. It carries no secret (see uiConfig).
//   - GET /, the static bundle itself, because the page has to load before it
//     can authenticate. These are the compiled assets of a public admin
//     client; they contain no credential and no tenant data.
//
// Nothing else on this server is reachable without a verified token. The two
// routes here return only what an unauthenticated visitor could already learn
// by reading this repository, and every /v1 route stays behind authorize --
// including, by net/http's own longest-pattern-wins precedence (Go 1.22+),
// every one of them despite "/" matching more broadly than any of them.
func registerUI(mux *http.ServeMux, cfg uiConfig) {
	csp := contentSecurityPolicy(cfg.Issuer)

	mux.HandleFunc("GET /ui-config", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, cfg)
	})

	files := http.FileServerFS(uiRoot)
	mux.Handle("GET /", secureHeaders(csp, files))
}

// secureHeaders wraps the static file server with the response headers a
// browser needs to treat this page as carefully as its contents deserve.
// Applied only to the UI, not to the JSON API: an API response is not a
// document a browser renders, and every one of these headers is about
// document handling.
func secureHeaders(csp string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", csp)
		// no-referrer matches index.html's own meta tag. Both, not either:
		// the meta tag covers navigations the header would not apply to if a
		// proxy stripped it, and the header covers a browser that ignores the
		// meta tag.
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		next.ServeHTTP(w, r)
	})
}
