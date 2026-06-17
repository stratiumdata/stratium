package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"stratium/internal/auth"
	"stratium/internal/gateway"
	"stratium/internal/mcp"
	"stratium/internal/tools"
)

func main() {
	mode := flag.String("mode", "mcp", "Run mode: mcp (default MCP server), check (single-shot authorization check), audit (log post-execution)")
	gatewayAddr := flag.String("gateway", envOrDefault("STRATIUM_GATEWAY_ADDRESS", "localhost:50054"), "Agent Gateway gRPC address")
	keycloakURL := flag.String("keycloak", envOrDefault("STRATIUM_KEYCLOAK_URL", "http://localhost:8080/realms/stratium"), "Keycloak realm URL")
	clientID := flag.String("client-id", envOrDefault("STRATIUM_CLIENT_ID", "stratium-mcp"), "OIDC client ID")
	tokenCache := flag.String("token-cache", envOrDefault("STRATIUM_TOKEN_CACHE", ""), "Token cache file path (default: ~/.stratium/token.json)")
	tlsCA := flag.String("tls-ca", envOrDefault("STRATIUM_TLS_CA", ""), "TLS CA certificate file (empty = insecure)")
	flag.Parse()

	logger := log.New(os.Stderr, "[stratium-mcp] ", log.LstdFlags)

	// Connect to Agent Gateway
	gwClient, err := gateway.NewClient(gateway.ClientConfig{
		Address: *gatewayAddr,
		TLS:     *tlsCA != "",
		CAFile:  *tlsCA,
	})
	if err != nil {
		logger.Fatalf("failed to connect to agent gateway: %v", err)
	}
	defer gwClient.Close()

	switch *mode {
	case "check":
		runCheckMode(gwClient, logger)
	case "audit":
		runAuditMode(gwClient, logger)
	default:
		runMCPMode(gwClient, logger, *keycloakURL, *clientID, *tokenCache, *gatewayAddr)
	}
}

// runMCPMode runs the full interactive MCP server (default mode).
func runMCPMode(gwClient *gateway.Client, logger *log.Logger, keycloakURL, clientID, tokenCache, gatewayAddr string) {
	authProvider := auth.NewProvider(auth.Config{
		KeycloakURL: keycloakURL,
		ClientID:    clientID,
		TokenCache:  tokenCache,
	}, logger)

	server := mcp.NewServer(logger)

	registry := tools.NewRegistry(gwClient, authProvider, logger)
	registry.RegisterAll(server)

	logger.Printf("stratium-mcp ready (gateway=%s, tools=%d)", gatewayAddr, 14)

	if err := server.Run(); err != nil {
		logger.Fatalf("server error: %v", err)
	}
}

// runCheckMode performs a single authorization check and exits.
// Reads a JSON action from stdin, calls the Agent Gateway, writes result to stdout.
// Used by PreToolUse hook scripts in Claude Code and OpenAI Codex.
//
// Required env vars:
//   - STRATIUM_DELEGATION_TOKEN: active delegation JWT
//
// Auth context is loaded from ~/.stratium/token.json (cached OIDC session).
func runCheckMode(gwClient *gateway.Client, logger *log.Logger) {
	delegationToken := os.Getenv("STRATIUM_DELEGATION_TOKEN")
	if delegationToken == "" {
		fmt.Fprintf(os.Stdout, `{"authorized":false,"error":"STRATIUM_DELEGATION_TOKEN not set"}`)
		fmt.Fprintln(os.Stdout)
		os.Exit(1)
	}

	// Load cached OIDC token for the gRPC auth headers
	accessToken, userID := loadCachedToken(logger)

	if err := mcp.RunCheck(gwClient, delegationToken, accessToken, userID); err != nil {
		logger.Fatalf("check mode error: %v", err)
	}
}

// runAuditMode logs a post-execution event to the audit trail.
// Used by PostToolUse hook scripts. Fire-and-forget — errors are logged but not fatal.
func runAuditMode(gwClient *gateway.Client, logger *log.Logger) {
	// Phase 1: minimal implementation — log to stderr for now.
	// Future: call a dedicated audit RPC on the Agent Gateway.
	logger.Println("audit mode: post-execution logging (placeholder)")
}

// loadCachedToken reads the OIDC session from ~/.stratium/token.json.
// Returns empty strings if the file doesn't exist (Gateway will still work
// with just the delegation token for authorization checks).
func loadCachedToken(logger *log.Logger) (accessToken, userID string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", ""
	}

	tokenPath := filepath.Join(home, ".stratium", "token.json")
	data, err := os.ReadFile(tokenPath)
	if err != nil {
		logger.Printf("warning: could not read cached token (%v) — using delegation token only", err)
		return "", ""
	}

	var token struct {
		AccessToken string `json:"access_token"`
		UserID      string `json:"user_id"`
	}
	if err := json.Unmarshal(data, &token); err != nil {
		logger.Printf("warning: could not parse cached token: %v", err)
		return "", ""
	}

	return token.AccessToken, token.UserID
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
