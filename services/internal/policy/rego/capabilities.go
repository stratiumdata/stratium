package rego

import (
	"github.com/open-policy-agent/opa/v1/ast"
)

// deniedBuiltins are the OPA built-ins a policy may not call: the ones that
// reach outside the process evaluating it.
//
// A policy runs inside the PDP on every decision, and inside the PAP whenever
// an editor validates or tests one, with that process's network position and
// environment. http.send would let a policy call any address the process can
// reach and send decision input with the request; net.lookup_ip_addr does the
// same over DNS; opa.runtime exposes the host process's configuration and
// environment. None has a use in deciding whether an action is allowed from
// the request the PDP hands the policy.
//
// This is a denylist on purpose. Of OPA's built-ins these are the only ones
// that leave the process (TestCapabilities_EveryNondeterministicBuiltinIsClassified
// re-derives that from OPA's own metadata, so an OPA upgrade that adds
// another fails a test instead of passing silently). The in-process
// non-deterministic ones stay: a policy legitimately asks what time it is.
var deniedBuiltins = map[string]bool{
	"http.send":          true,
	"net.lookup_ip_addr": true,
	"opa.runtime":        true,
}

// inProcessNondeterministic are the built-ins OPA marks non-deterministic
// that are nevertheless allowed, because their non-determinism is local
// (clock, random source, signing). Listed so the test above can tell "a new
// built-in OPA added" from "one we already looked at".
var inProcessNondeterministic = map[string]bool{
	"io.jwt.decode_verify":   true,
	"io.jwt.encode_sign":     true,
	"io.jwt.encode_sign_raw": true,
	"rand.intn":              true,
	"time.now_ns":            true,
	"uuid.rfc4122":           true,
}

// policyCapabilities is what every Rego policy is compiled against, in both
// Validate and Prepare, so a policy that cannot be evaluated also cannot be
// saved. Built once: the set does not vary by policy or tenant.
//
// Removing a built-in from the capabilities makes a call to it a compile
// error that names it ("undefined function http.send"), which is the message
// a policy author needs. AllowNet is also set to an empty, non-nil list,
// OPA's own switch for "no network hosts", as a second barrier should a
// network built-in ever be reachable again.
var policyCapabilities = restrictedCapabilities()

func restrictedCapabilities() *ast.Capabilities {
	caps := ast.CapabilitiesForThisVersion()
	kept := make([]*ast.Builtin, 0, len(caps.Builtins))
	for _, b := range caps.Builtins {
		if !deniedBuiltins[b.Name] {
			kept = append(kept, b)
		}
	}
	caps.Builtins = kept
	caps.AllowNet = []string{}
	return caps
}
