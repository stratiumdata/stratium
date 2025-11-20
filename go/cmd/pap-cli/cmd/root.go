package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	// Global flags
	serverURL string
	token     string
	verbose   bool
	output    string // json, yaml, table
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "pap-cli",
	Short: "Stratium PAP (Policy Administration Point) CLI",
	Long: `A command-line interface for managing policies, entitlements, and audit logs
in the Stratium Policy Administration Point.

The CLI supports CRUD operations for policies and entitlements, policy evaluation,
and audit log retrieval. Authentication is handled via Keycloak access tokens.`,
	Version: "1.0.0",
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	// Global persistent flags
	rootCmd.PersistentFlags().StringVar(&serverURL, "server", getEnvOrDefault("PAP_SERVER_URL", "http://localhost:8090"), "PAP server URL")
	rootCmd.PersistentFlags().StringVar(&token, "token", os.Getenv("PAP_TOKEN"), "Access token for authentication")
	rootCmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")
	rootCmd.PersistentFlags().StringVarP(&output, "output", "o", "table", "Output format (json, yaml, table)")

	// Add subcommands
	rootCmd.AddCommand(policyCmd)
	rootCmd.AddCommand(entitlementCmd)
	rootCmd.AddCommand(auditCmd)
	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(versionCmd)
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the version number",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("Stratium PAP CLI v1.0.0")
	},
}
