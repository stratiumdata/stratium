// go/internal/catalog/credential_test.go
package catalog

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestStaticToken(t *testing.T) {
	st := StaticToken{Tokens: map[string]string{"github": "ghp_abc"}}

	tok, err := st.GetToken(context.Background(), "ignored-subject", "github")
	require.NoError(t, err)
	assert.Equal(t, "ghp_abc", tok)

	_, err = st.GetToken(context.Background(), "", "slack")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrCredentialUnavailable))
}

func TestKeycloakBrokerGetToken(t *testing.T) {
	t.Run("returns access_token from JSON body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "/broker/github/token", r.URL.Path)
			assert.Equal(t, "Bearer kc-access-token", r.Header.Get("Authorization"))
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"access_token":"gho_live","token":"raw","response":{}}`))
		}))
		defer srv.Close()

		b := &KeycloakBroker{RealmURL: srv.URL, HTTP: srv.Client()}
		tok, err := b.GetToken(context.Background(), "kc-access-token", "github")
		require.NoError(t, err)
		assert.Equal(t, "gho_live", tok)
	})

	t.Run("401 maps to ErrCredentialUnavailable", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer srv.Close()

		b := &KeycloakBroker{RealmURL: srv.URL, HTTP: srv.Client()}
		_, err := b.GetToken(context.Background(), "kc-access-token", "github")
		require.Error(t, err)
		assert.True(t, errors.Is(err, ErrCredentialUnavailable))
	})
}

func TestParseBrokerToken(t *testing.T) {
	t.Run("json access_token preferred", func(t *testing.T) {
		tok, err := parseBrokerToken("application/json", []byte(`{"access_token":"a","token":"b"}`))
		require.NoError(t, err)
		assert.Equal(t, "a", tok)
	})
	t.Run("json token fallback", func(t *testing.T) {
		tok, err := parseBrokerToken("application/json", []byte(`{"token":"b"}`))
		require.NoError(t, err)
		assert.Equal(t, "b", tok)
	})
	t.Run("form-encoded access_token", func(t *testing.T) {
		tok, err := parseBrokerToken("application/x-www-form-urlencoded", []byte(`access_token=c&scope=repo&token_type=bearer`))
		require.NoError(t, err)
		assert.Equal(t, "c", tok)
	})
	t.Run("empty body errors", func(t *testing.T) {
		_, err := parseBrokerToken("application/json", []byte(`{}`))
		require.Error(t, err)
	})
}
