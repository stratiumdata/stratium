package pdpgrpc

import "time"

// ttlHardCeiling bounds a requested lifetime when the deployment configures
// no maximum (config.Load always does; a Config built by hand may not). It
// exists so that no ttl_seconds, however large, can overflow time.Duration.
const ttlHardCeiling = 100 * 365 * 24 * time.Hour

// boundedTTL turns a caller's ttl_seconds into a duration no longer than the
// deployment's maximum delegation lifetime. The comparison is made in
// seconds, before the multiplication that could overflow.
//
// IssueToken relies on the bound alone: a token is cut down to its
// delegation's expiry anyway, and callers ask for far more than they expect
// to get. CreateDelegation refuses a value above the maximum before it gets
// here.
func (s *Server) boundedTTL(seconds int64) time.Duration {
	max := s.cfg.MaxDelegationTTL
	if max <= 0 {
		max = ttlHardCeiling
	}
	if seconds > int64(max/time.Second) {
		return max
	}
	return time.Duration(seconds) * time.Second
}
