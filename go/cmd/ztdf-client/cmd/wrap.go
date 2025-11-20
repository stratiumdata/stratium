package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var (
	inputFile  string
	outputFile string
	inputText  string
)

// wrapCmd represents the wrap command
var wrapCmd = &cobra.Command{
	Use:   "wrap",
	Short: "Create a ZTDF file from plaintext",
	Long: `Encrypt plaintext data and create a ZTDF (Zero Trust Data Format) file.
The DEK (Data Encryption Key) will be wrapped using the Key Access Server
with your JWT token as the subject.`,
	RunE: runWrap,
}

func init() {
	rootCmd.AddCommand(wrapCmd)

	wrapCmd.Flags().StringVarP(&inputFile, "input", "i", "", "Input plaintext file")
	wrapCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output ZTDF file (zip format)")
	wrapCmd.Flags().StringVarP(&inputText, "text", "t", "", "Input plaintext as text (alternative to --input)")
	wrapCmd.Flags().StringVarP(&resourceName, "resource", "r", "ztdf-resource", "Resource name for ABAC policy")

	// At least one input method is required
	wrapCmd.MarkFlagRequired("output")
}

func runWrap(cmd *cobra.Command, args []string) error {
	// Validate input
	if inputFile == "" && inputText == "" {
		return fmt.Errorf("either --input or --text must be specified")
	}
	if inputFile != "" && inputText != "" {
		return fmt.Errorf("cannot specify both --input and --text")
	}

	// Read plaintext
	var plaintext []byte
	var err error

	if inputFile != "" {
		plaintext, err = os.ReadFile(inputFile)
		if err != nil {
			return fmt.Errorf("failed to read input file: %w", err)
		}
		fmt.Printf("Read %d bytes from %s\n", len(plaintext), inputFile)
	} else {
		plaintext = []byte(inputText)
		fmt.Printf("Using %d bytes of text input\n", len(plaintext))
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

	fmt.Printf("Encrypting payload and wrapping DEK...\n")

	// Create ZTDF
	ctx := context.Background()
	tdo, err := creator.CreateZTDF(ctx, plaintext, resourceName)
	if err != nil {
		return fmt.Errorf("failed to create ZTDF: %w", err)
	}

	if verbose {
		fmt.Printf("✓ Encrypted payload: %d bytes\n", len(tdo.Payload.Data))
		fmt.Printf("✓ Wrapped DEK with Key Access Server\n")
	}

	// Ensure output directory exists
	outputDir := filepath.Dir(outputFile)
	if outputDir != "" && outputDir != "." {
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	// Save ZTDF to zip file
	fmt.Printf("Saving ZTDF to %s...\n", outputFile)
	if err := SaveZTDFToZip(tdo, outputFile); err != nil {
		return fmt.Errorf("failed to save ZTDF: %w", err)
	}

	// Get file size
	fileInfo, err := os.Stat(outputFile)
	if err == nil {
		fmt.Printf("✓ ZTDF file created successfully! (%d bytes)\n", fileInfo.Size())
	} else {
		fmt.Printf("✓ ZTDF file created successfully!\n")
	}

	fmt.Printf("\n╭─────────────────────────────────────────╮\n")
	fmt.Printf("│  ZTDF Creation Successful!              │\n")
	fmt.Printf("╰─────────────────────────────────────────╯\n")
	fmt.Printf("\nFile: %s\n", outputFile)
	fmt.Printf("Resource: %s\n", resourceName)
	fmt.Printf("Plaintext size: %d bytes\n", len(plaintext))
	fmt.Printf("Encrypted size: %d bytes\n", len(tdo.Payload.Data))

	return nil
}
