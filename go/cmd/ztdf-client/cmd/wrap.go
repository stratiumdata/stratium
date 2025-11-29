package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"stratium/pkg/ztdf"
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

	useStreaming := inputFile != ""
	var plaintext []byte
	var plaintextSize int64
	var encryptedSize int64
	var streamResult *ztdf.WrapStreamResult
	var err error

	if !useStreaming {
		plaintext = []byte(inputText)
		plaintextSize = int64(len(plaintext))
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

	// Ensure output directory exists
	outputDir := filepath.Dir(outputFile)
	if outputDir != "" && outputDir != "." {
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}
	}

	// Create ZTDF
	ctx := context.Background()
	if useStreaming {
		file, err := os.Open(inputFile)
		if err != nil {
			return fmt.Errorf("failed to open input file: %w", err)
		}
		defer file.Close()

		if info, err := file.Stat(); err == nil {
			fmt.Printf("Streaming %d bytes from %s\n", info.Size(), inputFile)
		} else {
			fmt.Printf("Streaming data from %s\n", inputFile)
		}

		encryptProgress := newSpinner("Encrypting payload and streaming to ZTDF")
		encryptStart := time.Now()
		streamResult, err = creator.CreateZTDFStream(ctx, file, resourceName, outputFile)
		if err != nil {
			encryptProgress.Stop("✗ Failed to encrypt payload and wrap DEK")
			return fmt.Errorf("failed to create ZTDF: %w", err)
		}
		encryptProgress.Stop(fmt.Sprintf("✓ Encrypted payload (%d bytes) & wrapped DEK in %s",
			streamResult.CiphertextSize, formatDuration(time.Since(encryptStart))))

		plaintextSize = streamResult.PlaintextSize
		encryptedSize = streamResult.CiphertextSize
	} else {
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

		if plaintextSize == 0 {
			plaintextSize = int64(len(plaintext))
		}
		encryptedSize = int64(len(tdo.Payload.Data))
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
	fmt.Printf("Plaintext size: %d bytes\n", plaintextSize)
	fmt.Printf("Encrypted size: %d bytes\n", encryptedSize)
	fmt.Printf("Total processing time: %s\n", formatDuration(time.Since(overallStart)))

	return nil
}
