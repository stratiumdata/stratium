package main

import (
	"archive/zip"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"stratium/pkg/licensing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func main() {
	privateKeyPath := flag.String("private-key", "", "Path to RSA private key PEM")
	generateKey := flag.Bool("generate-key", false, "Generate a new RSA key pair for signing")
	keySize := flag.Int("key-size", 2048, "RSA key size for generated keys (2048, 3072, 4096)")
	privateKeyOut := flag.String("private-key-out", "", "Output path for generated private key PEM")
	publicKeyOut := flag.String("public-key-out", "", "Output path for public key PEM")
	keyID := flag.String("key-id", "", "License key identifier (default: generated UUID)")
	bundleDir := flag.String("bundle-dir", "", "Directory to write customer bundle (license.jwt + license-public.pem)")
	bundleZip := flag.String("bundle-zip", "", "Zip file path for customer bundle")
	outputPath := flag.String("output", "-", "Output path for license JWT ('-' for stdout)")
	issuer := flag.String("issuer", "stratium", "JWT issuer claim")
	customerID := flag.String("customer-id", "", "Customer identifier")
	customerName := flag.String("customer-name", "", "Customer name")
	deploymentID := flag.String("deployment-id", "", "Deployment identifier")
	allowedServices := flag.String("allowed-services", "", "Comma-separated allowed services (empty = all)")
	features := flag.String("features", "", "Comma-separated feature flags")
	maxNodes := flag.Int("max-nodes", 0, "Maximum licensed nodes (0 = unlimited)")
	expiresAt := flag.String("expires-at", "", "License expiry time (RFC3339, e.g. 2025-01-02T15:04:05Z)")
	expiresIn := flag.Duration("expires-in", 0, "License expiry duration from now (e.g. 720h)")
	notBefore := flag.String("not-before", "", "License not-before time (RFC3339)")

	flag.Parse()

	if err := runSigner(*privateKeyPath, *outputPath, *issuer, *customerID, *customerName, *deploymentID, *allowedServices, *features, *maxNodes, *expiresAt, *expiresIn, *notBefore, *generateKey, *keySize, *privateKeyOut, *publicKeyOut, *keyID, *bundleDir, *bundleZip); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func runSigner(privateKeyPath, outputPath, issuer, customerID, customerName, deploymentID, allowedServices, features string, maxNodes int, expiresAt string, expiresIn time.Duration, notBefore string, generateKey bool, keySize int, privateKeyOut, publicKeyOut, keyID, bundleDir, bundleZip string) error {
	privateKeyPath = strings.TrimSpace(privateKeyPath)
	if generateKey && privateKeyPath != "" {
		return errors.New("--private-key and --generate-key are mutually exclusive")
	}
	if !generateKey && privateKeyPath == "" {
		generateKey = true
	}

	if maxNodes < 0 {
		return errors.New("--max-nodes cannot be negative")
	}

	if expiresAt != "" && expiresIn > 0 {
		return errors.New("--expires-at and --expires-in are mutually exclusive")
	}

	bundleDir = strings.TrimSpace(bundleDir)
	bundleZip = strings.TrimSpace(bundleZip)
	if bundleDir != "" && bundleZip != "" {
		return errors.New("--bundle-dir and --bundle-zip are mutually exclusive")
	}
	bundleRequested := bundleDir != "" || bundleZip != ""
	if bundleRequested && outputPath == "-" {
		return errors.New("--output must be a file path when using --bundle-dir or --bundle-zip")
	}

	var privateKey *rsa.PrivateKey
	if generateKey {
		if err := validateKeySize(keySize); err != nil {
			return err
		}
		createdKey, err := generateKeyPair(keySize)
		if err != nil {
			return err
		}
		privateKey = createdKey

		if strings.TrimSpace(privateKeyOut) == "" {
			privateKeyOut = defaultKeyPath(outputPath, "license-private.pem")
		}
		if strings.TrimSpace(publicKeyOut) == "" {
			publicKeyOut = defaultKeyPath(outputPath, "license-public.pem")
		}

		if err := writePrivateKey(privateKeyOut, privateKey); err != nil {
			return err
		}
		if err := writePublicKey(publicKeyOut, &privateKey.PublicKey); err != nil {
			return err
		}
	} else {
		loadedKey, err := loadPrivateKey(privateKeyPath)
		if err != nil {
			return err
		}
		privateKey = loadedKey
	}

	if bundleRequested && strings.TrimSpace(publicKeyOut) == "" {
		publicKeyOut = defaultKeyPath(outputPath, "license-public.pem")
	}

	resolvedKeyID := strings.TrimSpace(keyID)
	if resolvedKeyID == "" {
		resolvedKeyID = uuid.NewString()
	}
	if outputPath == "-" {
		fmt.Fprintf(os.Stderr, "key id: %s\n", resolvedKeyID)
	} else {
		fmt.Fprintf(os.Stdout, "key id: %s\n", resolvedKeyID)
	}

	issuedAt := time.Now().UTC()
	claims := &licensing.Claims{
		CustomerID:      strings.TrimSpace(customerID),
		CustomerName:    strings.TrimSpace(customerName),
		KeyID:           resolvedKeyID,
		DeploymentID:    strings.TrimSpace(deploymentID),
		AllowedServices: parseCSV(allowedServices),
		Features:        parseCSV(features),
		MaxNodes:        maxNodes,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:   strings.TrimSpace(issuer),
			IssuedAt: jwt.NewNumericDate(issuedAt),
			Subject:  strings.TrimSpace(customerID),
			ID:       resolvedKeyID,
		},
	}

	if expiresAt != "" {
		parsed, err := time.Parse(time.RFC3339, expiresAt)
		if err != nil {
			return fmt.Errorf("invalid --expires-at value: %w", err)
		}
		claims.ExpiresAt = jwt.NewNumericDate(parsed)
	} else if expiresIn > 0 {
		claims.ExpiresAt = jwt.NewNumericDate(issuedAt.Add(expiresIn))
	}

	if notBefore != "" {
		parsed, err := time.Parse(time.RFC3339, notBefore)
		if err != nil {
			return fmt.Errorf("invalid --not-before value: %w", err)
		}
		claims.NotBefore = jwt.NewNumericDate(parsed)
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = resolvedKeyID
	signed, err := token.SignedString(privateKey)
	if err != nil {
		return fmt.Errorf("failed to sign license: %w", err)
	}

	if strings.TrimSpace(publicKeyOut) != "" && !generateKey {
		if err := writePublicKey(publicKeyOut, &privateKey.PublicKey); err != nil {
			return err
		}
	}

	if outputPath == "-" {
		fmt.Fprintln(os.Stdout, signed)
		if generateKey {
			fmt.Fprintf(os.Stderr, "wrote private key to %s\n", privateKeyOut)
			fmt.Fprintf(os.Stderr, "wrote public key to %s\n", publicKeyOut)
		} else if strings.TrimSpace(publicKeyOut) != "" {
			fmt.Fprintf(os.Stderr, "wrote public key to %s\n", publicKeyOut)
		}
		return nil
	}

	if err := os.WriteFile(outputPath, []byte(signed), 0600); err != nil {
		return fmt.Errorf("failed to write license to %s: %w", outputPath, err)
	}

	fmt.Fprintf(os.Stdout, "wrote license to %s\n", outputPath)
	if generateKey {
		fmt.Fprintf(os.Stdout, "wrote private key to %s\n", privateKeyOut)
		fmt.Fprintf(os.Stdout, "wrote public key to %s\n", publicKeyOut)
	} else if strings.TrimSpace(publicKeyOut) != "" {
		fmt.Fprintf(os.Stdout, "wrote public key to %s\n", publicKeyOut)
	}
	if bundleRequested {
		readme := buildBundleReadme(claims)
		if err := writeBundle(bundleDir, bundleZip, outputPath, publicKeyOut, readme); err != nil {
			return err
		}
	}
	return nil
}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	keyBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
	}

	return privateKey, nil
}

func generateKeyPair(keySize int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}
	return privateKey, nil
}

func writePrivateKey(path string, privateKey *rsa.PrivateKey) error {
	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}
	return writePEMFile(path, block, 0600)
}

func writePublicKey(path string, publicKey *rsa.PublicKey) error {
	encoded, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return fmt.Errorf("failed to marshal RSA public key: %w", err)
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: encoded,
	}
	return writePEMFile(path, block, 0644)
}

func writePEMFile(path string, block *pem.Block, perm os.FileMode) error {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return errors.New("missing output path for key")
	}
	pemBytes := pem.EncodeToMemory(block)
	if pemBytes == nil {
		return errors.New("failed to encode PEM block")
	}
	if err := os.WriteFile(trimmed, pemBytes, perm); err != nil {
		return fmt.Errorf("failed to write key to %s: %w", trimmed, err)
	}
	return nil
}

func writeBundle(bundleDir, bundleZip, licensePath, publicKeyPath, readme string) error {
	if strings.TrimSpace(publicKeyPath) == "" {
		return errors.New("public key path is required to build a customer bundle")
	}

	licenseBytes, err := os.ReadFile(licensePath)
	if err != nil {
		return fmt.Errorf("failed to read license for bundle: %w", err)
	}
	publicBytes, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read public key for bundle: %w", err)
	}

	if bundleDir != "" {
		if err := os.MkdirAll(bundleDir, 0755); err != nil {
			return fmt.Errorf("failed to create bundle dir: %w", err)
		}
		if err := os.WriteFile(filepath.Join(bundleDir, "license.jwt"), licenseBytes, 0644); err != nil {
			return fmt.Errorf("failed to write bundle license: %w", err)
		}
		if err := os.WriteFile(filepath.Join(bundleDir, "license-public.pem"), publicBytes, 0644); err != nil {
			return fmt.Errorf("failed to write bundle public key: %w", err)
		}
		if err := os.WriteFile(filepath.Join(bundleDir, "README.txt"), []byte(readme), 0644); err != nil {
			return fmt.Errorf("failed to write bundle README: %w", err)
		}
		fmt.Fprintf(os.Stdout, "wrote customer bundle to %s\n", bundleDir)
		return nil
	}

	if bundleZip != "" {
		if err := writeBundleZip(bundleZip, licenseBytes, publicBytes, []byte(readme)); err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "wrote customer bundle to %s\n", bundleZip)
		return nil
	}

	return nil
}

func writeBundleZip(bundleZip string, licenseBytes, publicBytes, readmeBytes []byte) error {
	if strings.TrimSpace(bundleZip) == "" {
		return errors.New("bundle zip path is required")
	}
	file, err := os.Create(bundleZip)
	if err != nil {
		return fmt.Errorf("failed to create bundle zip: %w", err)
	}
	defer file.Close()

	zipWriter := zip.NewWriter(file)
	if err := writeZipFile(zipWriter, "license.jwt", licenseBytes); err != nil {
		zipWriter.Close()
		return err
	}
	if err := writeZipFile(zipWriter, "license-public.pem", publicBytes); err != nil {
		zipWriter.Close()
		return err
	}
	if err := writeZipFile(zipWriter, "README.txt", readmeBytes); err != nil {
		zipWriter.Close()
		return err
	}
	if err := zipWriter.Close(); err != nil {
		return fmt.Errorf("failed to finalize bundle zip: %w", err)
	}
	return nil
}

func writeZipFile(zipWriter *zip.Writer, name string, content []byte) error {
	writer, err := zipWriter.Create(name)
	if err != nil {
		return fmt.Errorf("failed to add %s to bundle: %w", name, err)
	}
	if _, err := writer.Write(content); err != nil {
		return fmt.Errorf("failed to write %s to bundle: %w", name, err)
	}
	return nil
}

func buildBundleReadme(claims *licensing.Claims) string {
	if claims == nil {
		return "Stratium License Bundle\n\nMissing license claims.\n"
	}

	customer := strings.TrimSpace(claims.CustomerName)
	if customer == "" {
		customer = strings.TrimSpace(claims.CustomerID)
	}
	if customer == "" {
		customer = "unknown"
	}

	allowedServices := "all"
	if len(claims.AllowedServices) > 0 {
		allowedServices = strings.Join(claims.AllowedServices, ", ")
	}

	features := "none"
	if len(claims.Features) > 0 {
		features = strings.Join(claims.Features, ", ")
	}

	maxNodes := "unlimited"
	if claims.MaxNodes > 0 {
		maxNodes = fmt.Sprintf("%d", claims.MaxNodes)
	}

	return fmt.Sprintf(
		"Stratium License Bundle\n\n"+
			"Key ID: %s\n"+
			"Customer: %s\n"+
			"Deployment ID: %s\n"+
			"Allowed Services: %s\n"+
			"Features: %s\n"+
			"Max Nodes: %s\n"+
			"Issuer: %s\n"+
			"Issued At: %s\n"+
			"Not Before: %s\n"+
			"Expires At: %s\n\n"+
			"Installation:\n"+
			"- Copy license.jwt to the host running Stratium services.\n"+
			"- Copy license-public.pem to the same host.\n"+
			"- Configure license.file to the license.jwt path.\n"+
			"- Configure license.public_key_file to the license-public.pem path.\n"+
			"- Restart services to apply the license.\n\n"+
			"Security:\n"+
			"- The private key used to sign the license must remain with the issuer.\n",
		claims.KeyID,
		customer,
		claims.DeploymentID,
		allowedServices,
		features,
		maxNodes,
		claims.Issuer,
		formatNumericDate(claims.IssuedAt),
		formatNumericDate(claims.NotBefore),
		formatNumericDate(claims.ExpiresAt),
	)
}

func formatNumericDate(date *jwt.NumericDate) string {
	if date == nil {
		return "none"
	}
	return date.Time.UTC().Format(time.RFC3339)
}

func validateKeySize(keySize int) error {
	switch keySize {
	case 2048, 3072, 4096:
		return nil
	default:
		return fmt.Errorf("unsupported --key-size %d (use 2048, 3072, or 4096)", keySize)
	}
}

func defaultKeyPath(outputPath, filename string) string {
	if outputPath == "" || outputPath == "-" {
		return filename
	}
	return filepath.Join(filepath.Dir(outputPath), filename)
}

func parseCSV(input string) []string {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return nil
	}

	parts := strings.Split(trimmed, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.TrimSpace(part)
		if item != "" {
			result = append(result, item)
		}
	}

	if len(result) == 0 {
		return nil
	}
	return result
}
