package main

import (
	"flag"
	"log"
	"os"

	"stratium/internal/auth"
	"stratium/internal/gateway"
	"stratium/internal/mcp"
	"stratium/internal/tools"
)

func main() {
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

	// Set up OIDC auth
	authProvider := auth.NewProvider(auth.Config{
		KeycloakURL: *keycloakURL,
		ClientID:    *clientID,
		TokenCache:  *tokenCache,
	}, logger)

	// Create MCP server
	server := mcp.NewServer(logger)

	// Register all tools
	registry := tools.NewRegistry(gwClient, authProvider, logger)
	registry.RegisterAll(server)

	logger.Printf("stratium-mcp ready (gateway=%s, tools=%d)", *gatewayAddr, 14)

	// Run the MCP server (blocks until stdin is closed)
	if err := server.Run(); err != nil {
		logger.Fatalf("server error: %v", err)
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
