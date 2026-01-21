package licensing

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"stratium/config"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestManagerValidateService_AllowsService(t *testing.T) {
	tmpDir := t.TempDir()
	privateKey := generateKeyPair(t)
	publicKeyPath := writePublicKeyFile(t, tmpDir, &privateKey.PublicKey)
	licensePath := writeLicenseFile(t, tmpDir, privateKey, &Claims{
		CustomerID:      "customer-123",
		CustomerName:    "Acme Corp",
		DeploymentID:    "deploy-1",
		AllowedServices: []string{"platform-server"},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "stratium",
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-1 * time.Minute)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	})

	manager, err := NewManager(config.LicenseConfig{
		Enabled:         true,
		File:            licensePath,
		PublicKeyFile:   publicKeyPath,
		DeploymentID:    "deploy-1",
		RefreshInterval: time.Minute,
	})
	require.NoError(t, err)

	require.NoError(t, manager.ValidateService("platform-server"))
	require.Error(t, manager.ValidateService("key-manager-server"))
}

func TestManagerValidateService_DeploymentMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	privateKey := generateKeyPair(t)
	publicKeyPath := writePublicKeyFile(t, tmpDir, &privateKey.PublicKey)
	licensePath := writeLicenseFile(t, tmpDir, privateKey, &Claims{
		CustomerID:      "customer-456",
		CustomerName:    "Globex",
		DeploymentID:    "deploy-2",
		AllowedServices: []string{"pap-server"},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "stratium",
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-1 * time.Minute)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	})

	manager, err := NewManager(config.LicenseConfig{
		Enabled:         true,
		File:            licensePath,
		PublicKeyFile:   publicKeyPath,
		DeploymentID:    "deploy-1",
		RefreshInterval: time.Minute,
	})
	require.NoError(t, err)
	require.Error(t, manager.ValidateService("pap-server"))
}

func TestNewManager_InvalidSignature(t *testing.T) {
	tmpDir := t.TempDir()
	licenseKey := generateKeyPair(t)
	publicKey := generateKeyPair(t)
	publicKeyPath := writePublicKeyFile(t, tmpDir, &publicKey.PublicKey)
	licensePath := writeLicenseFile(t, tmpDir, licenseKey, &Claims{
		CustomerID:   "customer-789",
		DeploymentID: "deploy-1",
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "stratium",
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-1 * time.Minute)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		},
	})

	_, err := NewManager(config.LicenseConfig{
		Enabled:         true,
		File:            licensePath,
		PublicKeyFile:   publicKeyPath,
		DeploymentID:    "deploy-1",
		RefreshInterval: time.Minute,
	})
	require.Error(t, err)
}

func generateKeyPair(t *testing.T) *rsa.PrivateKey {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

func writePublicKeyFile(t *testing.T, dir string, publicKey *rsa.PublicKey) string {
	encoded, err := x509.MarshalPKIXPublicKey(publicKey)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: encoded})
	path := filepath.Join(dir, "license-public.pem")
	require.NoError(t, os.WriteFile(path, pemBytes, 0600))
	return path
}

func writeLicenseFile(t *testing.T, dir string, privateKey *rsa.PrivateKey, claims *Claims) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	require.NoError(t, err)
	path := filepath.Join(dir, "license.jwt")
	require.NoError(t, os.WriteFile(path, []byte(tokenString), 0600))
	return path
}
