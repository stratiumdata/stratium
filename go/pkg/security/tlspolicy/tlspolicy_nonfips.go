//go:build !fips

package tlspolicy

import "crypto/tls"

// EnforceConfig is a no-op outside fips builds.
func EnforceConfig(_ *tls.Config, _ bool) error {
	return nil
}
