package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"stratium/internal/auth"
	"stratium/internal/gateway"
	"stratium/internal/mcp"
)

// Registry holds tool definitions and the shared dependencies they need.
type Registry struct {
	gateway      *gateway.Client
	auth         *auth.Provider
	logger       *log.Logger
	session      *Session
	subAgentCfg  *SubAgentConfig
}

// Session holds per-session state (cached tokens, delegation info).
type Session struct {
	Token    *auth.TokenResponse
	AgentID  string
	DelegationToken string
	DelegationID    string
}

// NewRegistry creates a new tool registry.
func NewRegistry(gw *gateway.Client, authProvider *auth.Provider, logger *log.Logger) *Registry {
	return &Registry{
		gateway: gw,
		auth:    authProvider,
		logger:  logger,
		session: &Session{},
	}
}

// ensureAuth ensures we have a valid OIDC token, authenticating if needed.
func (r *Registry) ensureAuth(ctx context.Context) error {
	if r.session.Token != nil && r.session.Token.ExpiresAt > 0 {
		return nil
	}
	token, err := r.auth.GetToken(ctx)
	if err != nil {
		return fmt.Errorf("authentication required: %w", err)
	}
	r.session.Token = token
	return nil
}

func (r *Registry) accessToken() string {
	if r.session.Token == nil {
		return ""
	}
	return r.session.Token.AccessToken
}

func (r *Registry) userID() string {
	if r.session.Token == nil {
		return ""
	}
	return r.session.Token.UserID
}

// RegisterAll registers all tools on the MCP server.
func (r *Registry) RegisterAll(server *mcp.Server) {
	r.registerAgentTools(server)
	r.registerDelegationTools(server)
	r.registerActionTools(server)
	r.registerSubAgentTools(server)
}

// parseArgs is a helper to unmarshal tool arguments into a typed struct.
func parseArgs[T any](args json.RawMessage) (*T, error) {
	var v T
	if err := json.Unmarshal(args, &v); err != nil {
		return nil, fmt.Errorf("invalid arguments: %w", err)
	}
	return &v, nil
}

// persistDelegation writes the current delegation state to ~/.stratium/delegation.json
// so that the PreToolUse hook can read it for enforcement.
func (r *Registry) persistDelegation() {
	home, err := os.UserHomeDir()
	if err != nil {
		r.logger.Printf("warning: could not get home dir for delegation persistence: %v", err)
		return
	}

	dir := filepath.Join(home, ".stratium")
	if err := os.MkdirAll(dir, 0700); err != nil {
		r.logger.Printf("warning: could not create ~/.stratium: %v", err)
		return
	}

	state := map[string]string{
		"delegation_token": r.session.DelegationToken,
		"delegation_id":    r.session.DelegationID,
		"agent_id":         r.session.AgentID,
	}

	data, _ := json.MarshalIndent(state, "", "  ")
	path := filepath.Join(dir, "delegation.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		r.logger.Printf("warning: could not write delegation state: %v", err)
	}
}

// clearDelegation removes the persisted delegation state.
func (r *Registry) clearDelegation() {
	home, _ := os.UserHomeDir()
	if home != "" {
		os.Remove(filepath.Join(home, ".stratium", "delegation.json"))
	}
}
