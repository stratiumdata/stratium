package store

import (
	"context"
	"database/sql"
	"errors"
	"regexp"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestCheckServingRole(t *testing.T) {
	for _, tc := range []struct {
		name              string
		superuser, bypass bool
		refused           bool
	}{
		{"an ordinary role", false, false, false},
		{"a superuser", true, false, true},
		{"a BYPASSRLS role", false, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db, mock, err := sqlmock.New()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = db.Close() }()
			mock.ExpectQuery(regexp.QuoteMeta(servingRoleQuery)).
				WillReturnRows(sqlmock.NewRows([]string{"rolsuper", "rolbypassrls"}).AddRow(tc.superuser, tc.bypass))

			err = CheckServingRole(context.Background(), db)
			if got := errors.Is(err, ErrServingRoleBypassesRLS); got != tc.refused {
				t.Errorf("CheckServingRole() = %v, refused = %v, want %v", err, got, tc.refused)
			}
		})
	}
}

// A role whose attributes cannot be read is not passed as safe.
func TestCheckServingRole_UnreadableIsAnError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	mock.ExpectQuery(regexp.QuoteMeta(servingRoleQuery)).WillReturnError(sql.ErrNoRows)

	if err := CheckServingRole(context.Background(), db); err == nil {
		t.Fatal("CheckServingRole() = nil, want an error")
	}
}
