package config

import "testing"

func TestWithApplicationName(t *testing.T) {
	tests := []struct {
		name, dsn, want string
	}{
		{"url without query", "postgres://u:p@db:5432/x", "postgres://u:p@db:5432/x?application_name=stratium-pdp"},
		{"url keeps other params", "postgres://u:p@db/x?sslmode=disable", "postgres://u:p@db/x?application_name=stratium-pdp&sslmode=disable"},
		{"url operator name wins", "postgres://db/x?application_name=mine", "postgres://db/x?application_name=mine"},
		{"keyvalue appended", "host=db dbname=x sslmode=disable", "host=db dbname=x sslmode=disable application_name=stratium-pdp"},
		{"keyvalue operator name wins", "host=db application_name=mine", "host=db application_name=mine"},
		{"empty left for sql.Open to reject", "", ""},
		{"unparseable url unchanged", "postgres://db:bad port/x", "postgres://db:bad port/x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := WithApplicationName(tt.dsn, "stratium-pdp"); got != tt.want {
				t.Errorf("WithApplicationName(%q) = %q, want %q", tt.dsn, got, tt.want)
			}
		})
	}
}
