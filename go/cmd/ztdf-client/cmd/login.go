package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// loginCmd represents the login command
var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with Keycloak and save token",
	Long: `Authenticate with Keycloak using username and password,
and save the JWT token for future use.`,
	RunE: runLogin,
}

func init() {
	rootCmd.AddCommand(loginCmd)
}

func runLogin(cmd *cobra.Command, args []string) error {
	// Get authentication config
	config := getAuthConfig()

	if config.Username == "" || config.Password == "" {
		return fmt.Errorf("username and password are required for login")
	}

	fmt.Printf("Authenticating with Keycloak at %s...\n", config.IssuerURL)

	// Login to Keycloak
	store, err := LoginToKeycloak(config)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}

	fmt.Printf("✓ Authentication successful!\n")
	fmt.Printf("✓ Token saved to: %s\n", config.TokenFile)
	fmt.Printf("✓ Token expires at: %s\n", store.ExpiresAt.Format("2006-01-02 15:04:05"))

	if verbose {
		fmt.Printf("\nToken Details:\n")
		fmt.Printf("  Access Token: %s...\n", store.AccessToken[:50])
		fmt.Printf("  ID Token: %s...\n", store.IDToken[:50])
	}

	return nil
}