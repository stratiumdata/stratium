package config

import (
	"net/url"
	"strings"
)

// WithApplicationName returns dsn with Postgres's application_name set to
// name, so the connection shows up as name in pg_stat_activity and server
// logs instead of as an anonymous client. A name the operator already set
// wins: the setting is only filled in when absent.
//
// Both lib/pq connection-string forms are handled: the URL form
// (postgres://...) and the key=value form. A URL that does not parse is
// returned unchanged, so sql.Open reports the operator's real mistake rather
// than one introduced here.
func WithApplicationName(dsn, name string) string {
	if strings.Contains(dsn, "://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return dsn
		}
		q := u.Query()
		if q.Get("application_name") != "" {
			return dsn
		}
		q.Set("application_name", name)
		u.RawQuery = q.Encode()
		return u.String()
	}
	for _, field := range strings.Fields(dsn) {
		if strings.HasPrefix(field, "application_name=") {
			return dsn
		}
	}
	if dsn == "" {
		return dsn
	}
	return dsn + " application_name=" + name
}
