package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var (
	// Global flags
	keycloakURL    string
	clientID       string
	clientSecret   string
	username       string
	password       string
	tokenFile      string
	keyManagerAddr string
	keyAccessAddr  string
	resourceName   string
	verbose        bool
	useTLS         bool
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "ztdf-client",
	Short: "ZTDF Client - Create and manage Zero Trust Data Format files",
	Long: `ZTDF Client is a command-line tool for creating and managing
Zero Trust Data Format (ZTDF) files with integrated encryption and
access control using Keycloak authentication and a Key Access Server.`,
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func init() {
	// Get home directory for default token file
	home, err := os.UserHomeDir()
	if err != nil {
		home = "."
	}
	defaultTokenFile := filepath.Join(home, ".ztdf", "token.json")

	// Persistent flags available to all commands
	rootCmd.PersistentFlags().StringVar(&keycloakURL, "keycloak-url", "", "Keycloak issuer URL (e.g., https://keycloak.example.com/realms/myrealm)")
	rootCmd.PersistentFlags().StringVar(&clientID, "client-id", "stratium-ztdf-client", "Keycloak client ID")
	rootCmd.PersistentFlags().StringVar(&clientSecret, "client-secret", "", "Keycloak client secret (optional)")
	rootCmd.PersistentFlags().StringVar(&username, "username", "", "Username for authentication")
	rootCmd.PersistentFlags().StringVar(&password, "password", "", "Password for authentication")
	rootCmd.PersistentFlags().StringVar(&tokenFile, "token-file", defaultTokenFile, "Path to store/load authentication token")
	rootCmd.PersistentFlags().StringVar(&keyManagerAddr, "km-addr", "localhost:50052", "Key Manager Server address (gRPC)")
	rootCmd.PersistentFlags().StringVar(&keyAccessAddr, "kas-addr", "localhost:50053", "Key Access Server address (gRPC)")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().BoolVar(&useTLS, "use-tls", false, "Use TLS for gRPC connections to Key Manager and Key Access servers")

	// Mark required flags
	rootCmd.MarkPersistentFlagRequired("keycloak-url")
}

// getAuthConfig creates an AuthConfig from flags
func getAuthConfig() *AuthConfig {
	return &AuthConfig{
		IssuerURL:    keycloakURL,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Username:     username,
		Password:     password,
		TokenFile:    tokenFile,
	}
}
