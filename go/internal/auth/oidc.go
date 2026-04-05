package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// TokenResponse holds OAuth2 token data.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	ExpiresAt    int64  `json:"expires_at"`
	UserID       string `json:"user_id,omitempty"`
}

// Config holds OIDC configuration.
type Config struct {
	KeycloakURL string
	ClientID    string
	TokenCache  string
}

// Provider handles OIDC authentication with Keycloak.
type Provider struct {
	cfg    Config
	logger *log.Logger
}

// NewProvider creates a new OIDC provider.
func NewProvider(cfg Config, logger *log.Logger) *Provider {
	if cfg.TokenCache == "" {
		home, _ := os.UserHomeDir()
		cfg.TokenCache = filepath.Join(home, ".stratium", "token.json")
	}
	if cfg.ClientID == "" {
		cfg.ClientID = "stratium-mcp"
	}
	return &Provider{cfg: cfg, logger: logger}
}

// GetToken returns a valid access token, refreshing or re-authenticating as needed.
func (p *Provider) GetToken(ctx context.Context) (*TokenResponse, error) {
	cached, err := p.loadCachedToken()
	if err == nil && cached.ExpiresAt > time.Now().Unix()+30 {
		return cached, nil
	}

	if cached != nil && cached.RefreshToken != "" {
		refreshed, err := p.refreshToken(ctx, cached.RefreshToken)
		if err == nil {
			return refreshed, nil
		}
		p.logger.Printf("token refresh failed: %v, starting new login", err)
	}

	return p.login(ctx)
}

func (p *Provider) loadCachedToken() (*TokenResponse, error) {
	data, err := os.ReadFile(p.cfg.TokenCache)
	if err != nil {
		return nil, err
	}
	var token TokenResponse
	if err := json.Unmarshal(data, &token); err != nil {
		return nil, err
	}
	return &token, nil
}

func (p *Provider) cacheToken(token *TokenResponse) error {
	dir := filepath.Dir(p.cfg.TokenCache)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(token, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p.cfg.TokenCache, data, 0600)
}

func (p *Provider) tokenEndpoint() string {
	return p.cfg.KeycloakURL + "/protocol/openid-connect/token"
}

func (p *Provider) authEndpoint() string {
	return p.cfg.KeycloakURL + "/protocol/openid-connect/auth"
}

func (p *Provider) refreshToken(_ context.Context, refreshToken string) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {p.cfg.ClientID},
		"refresh_token": {refreshToken},
	}

	resp, err := http.PostForm(p.tokenEndpoint(), data)
	if err != nil {
		return nil, fmt.Errorf("refresh request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("refresh failed with status %d", resp.StatusCode)
	}

	var token TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, fmt.Errorf("failed to decode token: %w", err)
	}

	token.ExpiresAt = time.Now().Unix() + int64(token.ExpiresIn)
	token.UserID = extractUserID(token.AccessToken)
	if err := p.cacheToken(&token); err != nil {
		p.logger.Printf("warning: failed to cache token: %v", err)
	}
	return &token, nil
}

func (p *Provider) login(ctx context.Context) (*TokenResponse, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("failed to start callback server: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	codeChan := make(chan string, 1)
	errChan := make(chan error, 1)

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code == "" {
			errMsg := r.URL.Query().Get("error_description")
			if errMsg == "" {
				errMsg = "no authorization code received"
			}
			errChan <- fmt.Errorf("%s", errMsg)
			fmt.Fprintf(w, "<html><body><h2>Authentication failed</h2><p>%s</p></body></html>", errMsg)
			return
		}
		codeChan <- code
		fmt.Fprint(w, `<html><body><h2>Authentication successful!</h2><p>You can close this window and return to Claude.</p><script>window.close()</script></body></html>`)
	})

	server := &http.Server{Handler: mux}
	go func() {
		if serveErr := server.Serve(listener); serveErr != nil && serveErr != http.ErrServerClosed {
			errChan <- serveErr
		}
	}()
	defer server.Shutdown(ctx)

	authURL := fmt.Sprintf("%s?client_id=%s&response_type=code&redirect_uri=%s&scope=profile+email+classification",
		p.authEndpoint(), url.QueryEscape(p.cfg.ClientID), url.QueryEscape(redirectURI))

	p.logger.Printf("opening browser for authentication...")
	if err := openBrowser(authURL); err != nil {
		p.logger.Printf("failed to open browser: %v", err)
		p.logger.Printf("please open this URL manually: %s", authURL)
	}

	select {
	case code := <-codeChan:
		return p.exchangeCode(code, redirectURI)
	case err := <-errChan:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(2 * time.Minute):
		return nil, fmt.Errorf("authentication timed out after 2 minutes")
	}
}

func (p *Provider) exchangeCode(code, redirectURI string) (*TokenResponse, error) {
	data := url.Values{
		"grant_type":   {"authorization_code"},
		"client_id":    {p.cfg.ClientID},
		"code":         {code},
		"redirect_uri": {redirectURI},
	}

	resp, err := http.PostForm(p.tokenEndpoint(), data)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed with status %d", resp.StatusCode)
	}

	var token TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return nil, fmt.Errorf("failed to decode token: %w", err)
	}

	token.ExpiresAt = time.Now().Unix() + int64(token.ExpiresIn)
	token.UserID = extractUserID(token.AccessToken)
	if err := p.cacheToken(&token); err != nil {
		p.logger.Printf("warning: failed to cache token: %v", err)
	}
	return &token, nil
}

// extractUserID decodes the JWT payload to get the preferred_username or sub claim.
func extractUserID(accessToken string) string {
	parts := strings.Split(accessToken, ".")
	if len(parts) != 3 {
		return ""
	}

	data, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}

	var claims struct {
		Sub               string `json:"sub"`
		PreferredUsername string `json:"preferred_username"`
	}
	if err := json.Unmarshal(data, &claims); err != nil {
		return ""
	}

	if claims.PreferredUsername != "" {
		return claims.PreferredUsername
	}
	return claims.Sub
}

func openBrowser(rawURL string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", rawURL)
	case "linux":
		cmd = exec.Command("xdg-open", rawURL)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL)
	default:
		return fmt.Errorf("unsupported platform: %s", runtime.GOOS)
	}
	return cmd.Start()
}
