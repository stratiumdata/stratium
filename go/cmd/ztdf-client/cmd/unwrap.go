package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	printOutput bool
	saveToFile  string
)

// unwrapCmd represents the unwrap command
var unwrapCmd = &cobra.Command{
	Use:   "unwrap <ztdf-file>",
	Short: "Decrypt a ZTDF file and extract plaintext",
	Long: `Decrypt a ZTDF (Zero Trust Data Format) file by unwrapping the DEK
using the Key Access Server with your JWT token as the subject,
then decrypt and extract the plaintext payload.`,
	Args: cobra.ExactArgs(1),
	RunE: runUnwrap,
}

func init() {
	rootCmd.AddCommand(unwrapCmd)

	unwrapCmd.Flags().BoolVarP(&printOutput, "print", "p", true, "Print plaintext to stdout")
	unwrapCmd.Flags().StringVarP(&saveToFile, "save", "s", "", "Save plaintext to file")
	unwrapCmd.Flags().StringVarP(&resourceName, "resource", "r", "ztdf-resource", "Resource name for ABAC policy")
}

func runUnwrap(cmd *cobra.Command, args []string) error {
	ztdfFile := args[0]

	// Check if file exists
	if _, err := os.Stat(ztdfFile); os.IsNotExist(err) {
		return fmt.Errorf("ZTDF file not found: %s", ztdfFile)
	}

	fmt.Printf("Loading ZTDF from %s...\n", ztdfFile)

	// Load ZTDF from zip file
	tdo, err := LoadZTDFFromZip(ztdfFile)
	if err != nil {
		return fmt.Errorf("failed to load ZTDF: %w", err)
	}

	if verbose {
		fmt.Printf("✓ ZTDF loaded successfully\n")
		fmt.Printf("  Encrypted payload: %d bytes\n", len(tdo.Payload.Data))
		if tdo.Manifest != nil && tdo.Manifest.EncryptionInformation != nil {
			fmt.Printf("  Encryption algorithm: %s\n", tdo.Manifest.EncryptionInformation.Method.Algorithm)
		}
	}

	// Get authentication config
	config := getAuthConfig()

	if verbose {
		fmt.Printf("Key Access Server: %s\n", keyAccessAddr)
		fmt.Printf("Keycloak URL: %s\n", config.IssuerURL)
		fmt.Printf("Resource: %s\n", resourceName)
	}

	// Create ZTDF creator (automatically handles auth and key management)
	creator, err := NewZTDFCreator(keyManagerAddr, keyAccessAddr, config.IssuerURL, config.ClientID, config.Username, config.Password, useTLS)
	if err != nil {
		return fmt.Errorf("failed to create ZTDF creator: %w", err)
	}
	defer creator.Close()

	fmt.Printf("Unwrapping DEK and decrypting payload...\n")

	// Unwrap ZTDF
	ctx := context.Background()
	plaintext, err := creator.UnwrapZTDF(ctx, tdo, resourceName)
	if err != nil {
		return fmt.Errorf("failed to unwrap ZTDF: %w", err)
	}

	if verbose {
		fmt.Printf("✓ DEK unwrapped successfully\n")
		fmt.Printf("✓ Payload decrypted successfully\n")
		fmt.Printf("✓ Plaintext size: %d bytes\n", len(plaintext))
	}

	// Save to file if requested
	if saveToFile != "" {
		if err := os.WriteFile(saveToFile, plaintext, 0644); err != nil {
			return fmt.Errorf("failed to save plaintext to file: %w", err)
		}
		fmt.Printf("✓ Plaintext saved to: %s\n", saveToFile)
	}

	// Print to stdout if requested
	if printOutput {
		fmt.Printf("\n╭─────────────────────────────────────────╮\n")
		fmt.Printf("│  ZTDF Decryption Successful!            │\n")
		fmt.Printf("╰─────────────────────────────────────────╯\n")
		fmt.Printf("\nPlaintext Content:\n")
		fmt.Printf("─────────────────────────────────────────\n")
		fmt.Printf("%s\n", string(plaintext))
		fmt.Printf("─────────────────────────────────────────\n")
	} else {
		fmt.Printf("\n✓ ZTDF unwrapped successfully!\n")
	}

	return nil
}
