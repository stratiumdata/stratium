package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with Keycloak and save access token",
	Long: `Authenticate with Keycloak using username/password and save the access token
to a local file for subsequent CLI commands.

The token is saved to ~/.stratium/pap-token and automatically used by other commands.`,
	RunE: runLogin,
}

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Remove saved authentication token",
	RunE:  runLogout,
}

// Login flags
var (
	keycloakURL    string
	realm          string
	clientID       string
	clientSecret   string
	username       string
	password       string
	saveToken      bool
	tokenFile      string
)

func init() {
	loginCmd.Flags().StringVar(&keycloakURL, "keycloak-url", getEnvOrDefault("KEYCLOAK_URL", "http://localhost:8080"), "Keycloak server URL")
	loginCmd.Flags().StringVar(&realm, "realm", getEnvOrDefault("REALM", "stratium"), "Keycloak realm")
	loginCmd.Flags().StringVar(&clientID, "client-id", getEnvOrDefault("CLIENT_ID", "stratium-pap"), "Keycloak client ID")
	loginCmd.Flags().StringVar(&clientSecret, "client-secret", getEnvOrDefault("CLIENT_SECRET", "stratium-pap-secret"), "Keycloak client secret")
	loginCmd.Flags().StringVarP(&username, "username", "u", "", "Username (required)")
	loginCmd.Flags().StringVarP(&password, "password", "p", "", "Password (required)")
	loginCmd.Flags().BoolVar(&saveToken, "save", true, "Save token to file")
	loginCmd.Flags().StringVar(&tokenFile, "token-file", getDefaultTokenFile(), "Token file path")

	loginCmd.MarkFlagRequired("username")
	loginCmd.MarkFlagRequired("password")

	rootCmd.AddCommand(loginCmd)
	rootCmd.AddCommand(logoutCmd)
}

func runLogin(cmd *cobra.Command, args []string) error {
	// Build token endpoint URL
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", keycloakURL, realm)

	// Prepare form data
	data := url.Values{}
	data.Set("client_id", clientID)
	data.Set("client_secret", clientSecret)
	data.Set("grant_type", "password")
	data.Set("username", username)
	data.Set("password", password)

	if verbose {
		fmt.Fprintf(debugWriter, "→ POST %s\n", tokenURL)
		fmt.Fprintf(debugWriter, "  Username: %s\n", username)
		fmt.Fprintf(debugWriter, "  Client ID: %s\n", clientID)
	}

	// Make request
	req, err := http.NewRequest(http.MethodPost, tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to authenticate: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		var errorResp struct {
			Error            string `json:"error"`
			ErrorDescription string `json:"error_description"`
		}
		json.Unmarshal(body, &errorResp)
		if errorResp.Error != "" {
			return fmt.Errorf("authentication failed: %s - %s", errorResp.Error, errorResp.ErrorDescription)
		}
		return fmt.Errorf("authentication failed: HTTP %d", resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken      string `json:"access_token"`
		ExpiresIn        int    `json:"expires_in"`
		RefreshToken     string `json:"refresh_token"`
		RefreshExpiresIn int    `json:"refresh_expires_in"`
		TokenType        string `json:"token_type"`
	}

	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return fmt.Errorf("failed to parse token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return fmt.Errorf("no access token in response")
	}

	// Save token to file if requested
	if saveToken {
		if err := saveTokenToFile(tokenFile, tokenResp.AccessToken); err != nil {
			PrintWarning(fmt.Sprintf("Failed to save token to file: %v", err))
		} else {
			if verbose {
				fmt.Fprintf(debugWriter, "Token saved to: %s\n", tokenFile)
			}
		}
	}

	PrintSuccess("Authentication successful!")
	fmt.Printf("Access token expires in: %d seconds\n", tokenResp.ExpiresIn)
	fmt.Printf("Token saved to: %s\n", tokenFile)

	if output == "json" || output == "yaml" {
		return OutputData(map[string]interface{}{
			"access_token": tokenResp.AccessToken,
			"expires_in":   tokenResp.ExpiresIn,
			"token_type":   tokenResp.TokenType,
		})
	}

	return nil
}

func runLogout(cmd *cobra.Command, args []string) error {
	tokenPath := getDefaultTokenFile()

	if _, err := os.Stat(tokenPath); os.IsNotExist(err) {
		fmt.Println("No saved token found.")
		return nil
	}

	if err := os.Remove(tokenPath); err != nil {
		return fmt.Errorf("failed to remove token file: %w", err)
	}

	PrintSuccess("Logged out successfully")
	return nil
}

func getDefaultTokenFile() string {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return ".stratium-pap-token"
	}
	return filepath.Join(homeDir, ".stratium", "pap-token")
}

func saveTokenToFile(path, token string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write token to file with restricted permissions
	if err := os.WriteFile(path, []byte(token), 0600); err != nil {
		return fmt.Errorf("failed to write token file: %w", err)
	}

	return nil
}

// LoadTokenFromFile loads a token from the default location
func LoadTokenFromFile() (string, error) {
	tokenPath := getDefaultTokenFile()

	data, err := os.ReadFile(tokenPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil // No token file, not an error
		}
		return "", fmt.Errorf("failed to read token file: %w", err)
	}

	return strings.TrimSpace(string(data)), nil
}

// GetToken returns the token from flag, env, or file (in that order)
func GetToken() (string, error) {
	// 1. Check if token flag was provided
	if token != "" {
		return token, nil
	}

	// 2. Check environment variable
	if envToken := os.Getenv("PAP_TOKEN"); envToken != "" {
		return envToken, nil
	}

	// 3. Try to load from file
	fileToken, err := LoadTokenFromFile()
	if err != nil {
		return "", err
	}

	if fileToken != "" {
		return fileToken, nil
	}

	return "", fmt.Errorf("no authentication token found. Please run 'pap-cli login' first or set PAP_TOKEN environment variable")
}

// init function to override token loading
func init() {
	// Override the global token variable with loaded token before commands run
	cobra.OnInitialize(func() {
		if token == "" {
			if loadedToken, _ := LoadTokenFromFile(); loadedToken != "" {
				token = loadedToken
			}
		}
	})
}
