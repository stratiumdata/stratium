package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

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
	overallStart := time.Now()

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
	var inputDuration time.Duration

	if inputFile != "" {
		readStart := time.Now()
		plaintext, err = os.ReadFile(inputFile)
		if err != nil {
			return fmt.Errorf("failed to read input file: %w", err)
		}
		inputDuration = time.Since(readStart)
		fmt.Printf("Read %d bytes from %s (%s)\n", len(plaintext), inputFile, formatDuration(inputDuration))
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

	// Create ZTDF
	ctx := context.Background()
	encryptProgress := newSpinner("Encrypting payload and wrapping DEK")
	encryptStart := time.Now()
	tdo, err := creator.CreateZTDF(ctx, plaintext, resourceName)
	if err != nil {
		encryptProgress.Stop("✗ Failed to encrypt payload and wrap DEK")
		return fmt.Errorf("failed to create ZTDF: %w", err)
	}
	encryptProgress.Stop(fmt.Sprintf("✓ Encrypted payload (%d bytes) & wrapped DEK in %s",
		len(tdo.Payload.Data), formatDuration(time.Since(encryptStart))))

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
	saveMsg := fmt.Sprintf("Saving ZTDF to %s", outputFile)
	saveProgress := newProgressTracker(saveMsg)
	saveStart := time.Now()
	if err := SaveZTDFToZip(tdo, outputFile, func(written, total int64) {
		if total == 0 {
			return
		}
		saveProgress.Update(float64(written) / float64(total))
	}); err != nil {
		saveProgress.Stop("✗ Failed to save ZTDF")
		return fmt.Errorf("failed to save ZTDF: %w", err)
	}
	saveProgress.Stop(fmt.Sprintf("✓ Saved ZTDF in %s", formatDuration(time.Since(saveStart))))

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
	fmt.Printf("Total processing time: %s\n", formatDuration(time.Since(overallStart)))

	return nil
}
