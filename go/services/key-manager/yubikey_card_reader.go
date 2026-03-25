package key_manager

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type commandRunner func(name string, stdin string, args ...string) ([]byte, error)
type lookPathFunc func(file string) (string, error)

type yubiKeySlotBinding struct {
	slot      string
	keyType   KeyType
	publicKey crypto.PublicKey
}

const (
	defaultPIVCommandTimeout = 2 * time.Minute
)

// YubiKeyPIVCardReader implements CardReader through yubico-piv-tool/ykman command invocations.
// This avoids direct cgo PKCS#11 bindings while still using real hardware-backed operations.
type YubiKeyPIVCardReader struct {
	mu             sync.RWMutex
	connected      bool
	authenticated  bool
	requireTouch   bool
	sessionPIN     string
	config         map[string]string
	selectedSlot   string
	selectedDevice string
	keys           map[string]*yubiKeySlotBinding
	runner         commandRunner
	lookPath       lookPathFunc
}

func NewYubiKeyPIVCardReader() *YubiKeyPIVCardReader {
	return &YubiKeyPIVCardReader{
		config:   make(map[string]string),
		keys:     make(map[string]*yubiKeySlotBinding),
		runner:   defaultCommandRunner,
		lookPath: exec.LookPath,
	}
}

func defaultCommandRunner(name string, stdin string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), defaultPIVCommandTimeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	if strings.TrimSpace(stdin) != "" {
		cmd.Stdin = bytes.NewBufferString(stdin + "\n")
	}
	output, err := cmd.CombinedOutput()
	if err != nil {
		trimmed := strings.TrimSpace(string(output))
		if trimmed != "" {
			return output, fmt.Errorf("%w: %s", err, trimmed)
		}
		return output, err
	}
	return output, nil
}

func (y *YubiKeyPIVCardReader) pivToolPath() string {
	if path := strings.TrimSpace(y.config["piv_tool_path"]); path != "" {
		return path
	}
	return "yubico-piv-tool"
}

func (y *YubiKeyPIVCardReader) ykmanPath() string {
	if path := strings.TrimSpace(y.config["ykman_path"]); path != "" {
		return path
	}
	return "ykman"
}

func (y *YubiKeyPIVCardReader) configuredPIN() string {
	if pin := strings.TrimSpace(y.sessionPIN); pin != "" {
		return pin
	}
	return ""
}

func parseBoolConfigValue(value string) bool {
	parsed, err := strconv.ParseBool(strings.TrimSpace(value))
	if err != nil {
		return false
	}
	return parsed
}

func (y *YubiKeyPIVCardReader) resolveSlotFromConfig(config map[string]string) string {
	if slot := strings.TrimSpace(config["slot"]); slot != "" {
		return strings.ToLower(slot)
	}
	if keyID := strings.TrimSpace(config["key_id"]); isPIVSlotIdentifier(keyID) {
		return strings.ToLower(keyID)
	}
	if slot := strings.TrimSpace(y.config["slot"]); slot != "" {
		return strings.ToLower(slot)
	}
	if keyID := strings.TrimSpace(y.config["key_id"]); isPIVSlotIdentifier(keyID) {
		return strings.ToLower(keyID)
	}
	if y.selectedSlot != "" {
		return strings.ToLower(y.selectedSlot)
	}
	return "9d"
}

func (y *YubiKeyPIVCardReader) resolveSlotFromOptions(keyID string, options map[string]interface{}) string {
	if options != nil {
		if raw, ok := options["slot"]; ok {
			if slot, ok := raw.(string); ok && strings.TrimSpace(slot) != "" {
				return strings.ToLower(strings.TrimSpace(slot))
			}
		}
		if raw, ok := options["key_id"]; ok {
			if value, _ := raw.(string); isPIVSlotIdentifier(value) {
				return strings.ToLower(strings.TrimSpace(value))
			}
		}
	}

	if isPIVSlotIdentifier(keyID) {
		return strings.ToLower(keyID)
	}

	return y.resolveSlotFromConfig(nil)
}

func isPIVSlotIdentifier(value string) bool {
	value = strings.TrimSpace(strings.ToLower(value))
	if len(value) != 2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func (y *YubiKeyPIVCardReader) Connect(config map[string]string) error {
	y.mu.Lock()
	defer y.mu.Unlock()

	for key, value := range config {
		if strings.EqualFold(strings.TrimSpace(key), "pin") {
			continue
		}
		y.config[key] = value
	}

	if module := strings.TrimSpace(y.config["pkcs11_library"]); module != "" {
		if _, err := os.Stat(module); err != nil {
			return fmt.Errorf("pkcs11_library path %q is not accessible: %w", module, err)
		}
	}

	if y.lookPath == nil {
		y.lookPath = exec.LookPath
	}
	if y.runner == nil {
		y.runner = defaultCommandRunner
	}

	if _, err := y.lookPath(y.pivToolPath()); err != nil {
		return fmt.Errorf("yubico PIV tool is not available: %w", err)
	}

	y.selectedSlot = y.resolveSlotFromConfig(config)
	if deviceID := strings.TrimSpace(y.config["device_id"]); deviceID != "" {
		y.selectedDevice = deviceID
	}
	y.requireTouch = parseBoolConfigValue(y.config["require_touch"])

	y.connected = true
	return nil
}

func (y *YubiKeyPIVCardReader) Disconnect() error {
	y.mu.Lock()
	defer y.mu.Unlock()

	y.connected = false
	y.authenticated = false
	y.sessionPIN = ""
	return nil
}

func (y *YubiKeyPIVCardReader) IsConnected() bool {
	y.mu.RLock()
	defer y.mu.RUnlock()
	return y.connected
}

func (y *YubiKeyPIVCardReader) ListDevices() ([]string, error) {
	y.mu.RLock()
	connected := y.connected
	ykmanPath := y.ykmanPath()
	selected := y.selectedDevice
	runner := y.runner
	lookPath := y.lookPath
	y.mu.RUnlock()

	if !connected {
		return nil, fmt.Errorf("not connected")
	}

	if lookPath != nil {
		if _, err := lookPath(ykmanPath); err == nil {
			output, err := runner(ykmanPath, "", "list", "--serials")
			if err == nil {
				lines := strings.Split(strings.TrimSpace(string(output)), "\n")
				devices := make([]string, 0, len(lines))
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if line == "" {
						continue
					}
					devices = append(devices, line)
				}
				if len(devices) > 0 {
					return devices, nil
				}
			}
		}
	}

	if selected != "" {
		return []string{selected}, nil
	}

	return []string{"yubikey-default"}, nil
}

func (y *YubiKeyPIVCardReader) SelectDevice(deviceID string) error {
	y.mu.Lock()
	defer y.mu.Unlock()

	if !y.connected {
		return fmt.Errorf("not connected")
	}
	if strings.TrimSpace(deviceID) == "" {
		return fmt.Errorf("device id is required")
	}

	y.selectedDevice = strings.TrimSpace(deviceID)
	return nil
}

func (y *YubiKeyPIVCardReader) GetDeviceInfo() (map[string]string, error) {
	y.mu.RLock()
	defer y.mu.RUnlock()

	if !y.connected {
		return nil, fmt.Errorf("not connected")
	}

	info := map[string]string{
		"id":      y.selectedDevice,
		"name":    "YubiKey PIV",
		"slot":    y.selectedSlot,
		"backend": "pcsc",
	}

	if module := strings.TrimSpace(y.config["pkcs11_library"]); module != "" {
		info["pkcs11_library"] = module
	}

	return info, nil
}

func (y *YubiKeyPIVCardReader) Authenticate(pin string) error {
	y.mu.Lock()
	defer y.mu.Unlock()

	if !y.connected {
		return fmt.Errorf("not connected")
	}
	if strings.TrimSpace(pin) == "" {
		return fmt.Errorf("pin is required")
	}

	if _, err := y.runner(y.pivToolPath(), pin, "-a", "verify-pin"); err != nil {
		return fmt.Errorf("yubikey PIN verification failed: %w", err)
	}
	if y.requireTouch {
		if err := y.ensureTouchPolicy(); err != nil {
			return err
		}
	}

	y.authenticated = true
	y.sessionPIN = pin
	delete(y.config, "pin")
	return nil
}

func (y *YubiKeyPIVCardReader) IsAuthenticated() bool {
	y.mu.RLock()
	defer y.mu.RUnlock()
	return y.authenticated
}

func (y *YubiKeyPIVCardReader) GenerateKey(keyType KeyType, keyID string, options map[string]interface{}) error {
	y.mu.Lock()
	defer y.mu.Unlock()

	if !y.connected || !y.authenticated {
		return fmt.Errorf("not connected or authenticated")
	}
	if strings.TrimSpace(keyID) == "" {
		return fmt.Errorf("key id is required")
	}

	slot := y.resolveSlotFromOptions(keyID, options)
	publicKey, readErr := y.readPublicKeyFromSlot(slot)
	if readErr != nil {
		generated, genErr := y.generateKeyAndReadPublicKey(slot, keyType)
		if genErr != nil {
			return fmt.Errorf("failed to load public key from slot %s: %v; key generation fallback failed: %w", slot, readErr, genErr)
		}
		publicKey = generated
	}

	y.keys[keyID] = &yubiKeySlotBinding{
		slot:      slot,
		keyType:   keyType,
		publicKey: publicKey,
	}

	return nil
}

func (y *YubiKeyPIVCardReader) GetPublicKey(keyID string) (crypto.PublicKey, error) {
	y.mu.RLock()
	binding, exists := y.keys[keyID]
	y.mu.RUnlock()
	if exists && binding.publicKey != nil {
		return binding.publicKey, nil
	}

	y.mu.Lock()
	defer y.mu.Unlock()

	if binding, exists = y.keys[keyID]; exists && binding.publicKey != nil {
		return binding.publicKey, nil
	}

	slot := y.resolveSlotFromOptions(keyID, nil)
	publicKey, err := y.readPublicKeyFromSlot(slot)
	if err != nil {
		return nil, err
	}

	y.keys[keyID] = &yubiKeySlotBinding{
		slot:      slot,
		keyType:   keyTypeFromPublicKey(publicKey),
		publicKey: publicKey,
	}

	return publicKey, nil
}

func keyTypeFromPublicKey(publicKey crypto.PublicKey) KeyType {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		switch key.N.BitLen() {
		case 2048:
			return KeyType_KEY_TYPE_RSA_2048
		case 3072:
			return KeyType_KEY_TYPE_RSA_3072
		case 4096:
			return KeyType_KEY_TYPE_RSA_4096
		default:
			return KeyType_KEY_TYPE_UNSPECIFIED
		}
	case *ecdsa.PublicKey:
		switch key.Curve.Params().Name {
		case "P-256":
			return KeyType_KEY_TYPE_ECC_P256
		case "P-384":
			return KeyType_KEY_TYPE_ECC_P384
		case "P-521":
			return KeyType_KEY_TYPE_ECC_P521
		default:
			return KeyType_KEY_TYPE_UNSPECIFIED
		}
	default:
		return KeyType_KEY_TYPE_UNSPECIFIED
	}
}

func (y *YubiKeyPIVCardReader) DeleteKey(keyID string) error {
	y.mu.Lock()
	defer y.mu.Unlock()

	if !y.connected || !y.authenticated {
		return fmt.Errorf("not connected or authenticated")
	}

	delete(y.keys, keyID)
	return nil
}

func (y *YubiKeyPIVCardReader) ListKeys() ([]string, error) {
	y.mu.RLock()
	defer y.mu.RUnlock()

	if !y.connected || !y.authenticated {
		return nil, fmt.Errorf("not connected or authenticated")
	}

	keys := make([]string, 0, len(y.keys))
	for keyID := range y.keys {
		keys = append(keys, keyID)
	}
	sort.Strings(keys)
	return keys, nil
}

func (y *YubiKeyPIVCardReader) Sign(keyID string, data []byte) ([]byte, error) {
	y.mu.RLock()
	if !y.connected || !y.authenticated {
		y.mu.RUnlock()
		return nil, fmt.Errorf("not connected or authenticated")
	}
	binding, exists := y.keys[keyID]
	if !exists {
		y.mu.RUnlock()
		return nil, fmt.Errorf("key not found")
	}
	slot := binding.slot
	pin := y.configuredPIN()
	tool := y.pivToolPath()
	runner := y.runner
	y.mu.RUnlock()
	defer y.clearCachedPIN()
	if strings.TrimSpace(pin) == "" {
		return nil, fmt.Errorf("pin is not available; authenticate before signing")
	}

	tmpDir, err := os.MkdirTemp("", "stratium-yubikey-sign-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	inPath := filepath.Join(tmpDir, "input.bin")
	outPath := filepath.Join(tmpDir, "signature.bin")
	if err := os.WriteFile(inPath, data, 0600); err != nil {
		return nil, fmt.Errorf("failed to write signing payload: %w", err)
	}

	primaryArgs := []string{"-a", "verify-pin", "-s", slot, "--sign", "-H", "SHA256", "-i", inPath, "-o", outPath}
	if _, err := runner(tool, pin, primaryArgs...); err != nil {
		testSignatureArgs := []string{"-a", "verify-pin", "-a", "test-signature", "-s", slot, "-H", "SHA256", "-i", inPath, "-o", outPath}
		if _, testErr := runner(tool, pin, testSignatureArgs...); testErr != nil {
			// Backward compatibility: some builds expose signing as explicit action.
			legacyArgs := []string{"-a", "sign", "-s", slot, "-A", "SHA256", "-i", inPath, "-o", outPath}
			if _, legacyErr := runner(tool, pin, legacyArgs...); legacyErr != nil {
				return nil, fmt.Errorf("YubiKey sign failed (verify-pin+--sign: %v; verify-pin+test-signature: %v; -a sign: %v)", err, testErr, legacyErr)
			}
		}
	}

	signature, err := os.ReadFile(outPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read signature: %w", err)
	}

	return signature, nil
}

func (y *YubiKeyPIVCardReader) Decrypt(keyID string, ciphertext []byte) ([]byte, error) {
	y.mu.RLock()
	if !y.connected || !y.authenticated {
		y.mu.RUnlock()
		return nil, fmt.Errorf("not connected or authenticated")
	}
	binding, exists := y.keys[keyID]
	if !exists {
		y.mu.RUnlock()
		return nil, fmt.Errorf("key not found")
	}
	slot := binding.slot
	pin := y.configuredPIN()
	tool := y.pivToolPath()
	runner := y.runner
	y.mu.RUnlock()
	defer y.clearCachedPIN()
	if strings.TrimSpace(pin) == "" {
		return nil, fmt.Errorf("pin is not available; authenticate before decrypting")
	}

	tmpDir, err := os.MkdirTemp("", "stratium-yubikey-decrypt-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	inPath := filepath.Join(tmpDir, "ciphertext.bin")
	outPath := filepath.Join(tmpDir, "plaintext.bin")
	if err := os.WriteFile(inPath, ciphertext, 0600); err != nil {
		return nil, fmt.Errorf("failed to write ciphertext: %w", err)
	}

	primaryArgs := []string{"-a", "verify-pin", "-a", "test-decipher", "-s", slot, "-i", inPath, "-o", outPath}
	if _, err := runner(tool, pin, primaryArgs...); err != nil {
		legacyArgs := []string{"-a", "test-decipher", "-s", slot, "-i", inPath, "-o", outPath}
		if _, legacyErr := runner(tool, pin, legacyArgs...); legacyErr != nil {
			return nil, fmt.Errorf("YubiKey decrypt failed (verify-pin+test-decipher: %v; test-decipher: %v)", err, legacyErr)
		}
	}

	plaintext, err := os.ReadFile(outPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read decrypted payload: %w", err)
	}

	return plaintext, nil
}

func (y *YubiKeyPIVCardReader) Encrypt(keyID string, plaintext []byte) ([]byte, error) {
	y.mu.RLock()
	binding, exists := y.keys[keyID]
	y.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("key not found")
	}

	switch publicKey := binding.publicKey.(type) {
	case *rsa.PublicKey:
		ciphertext, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, publicKey, plaintext, nil)
		if err != nil {
			return nil, fmt.Errorf("RSA encrypt failed: %w", err)
		}
		return ciphertext, nil
	case *ecdsa.PublicKey:
		ciphertext, err := encryptDEKWithECCPublicKey(publicKey, plaintext)
		if err != nil {
			return nil, fmt.Errorf("ECC encrypt failed: %w", err)
		}
		return ciphertext, nil
	default:
		return nil, fmt.Errorf("unsupported public key type %T", binding.publicKey)
	}
}

func (y *YubiKeyPIVCardReader) GetKeyInfo(keyID string) (map[string]interface{}, error) {
	y.mu.RLock()
	defer y.mu.RUnlock()

	if !y.connected {
		return nil, fmt.Errorf("not connected")
	}

	binding, exists := y.keys[keyID]
	if !exists {
		return nil, fmt.Errorf("key not found")
	}

	return map[string]interface{}{
		"slot":          binding.slot,
		"key_type":      binding.keyType.String(),
		"backend":       "pcsc",
		"device_id":     y.selectedDevice,
		"authenticated": y.authenticated,
	}, nil
}

func (y *YubiKeyPIVCardReader) readPublicKeyFromSlot(slot string) (crypto.PublicKey, error) {
	tmpDir, err := os.MkdirTemp("", "stratium-yubikey-readcert-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	certPath := filepath.Join(tmpDir, "cert.pem")
	if _, err := y.runner(y.pivToolPath(), "", "-a", "read-certificate", "-s", slot, "-o", certPath); err != nil {
		return nil, err
	}

	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate from slot %s: %w", slot, err)
	}

	publicKey, err := parsePublicKeyFromPEMBlob(certPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate/public key from slot %s: %w", slot, err)
	}

	return publicKey, nil
}

func (y *YubiKeyPIVCardReader) generateKeyAndReadPublicKey(slot string, keyType KeyType) (crypto.PublicKey, error) {
	algorithm := ""
	switch keyType {
	case KeyType_KEY_TYPE_RSA_2048:
		algorithm = "RSA2048"
	case KeyType_KEY_TYPE_ECC_P256:
		algorithm = "ECCP256"
	case KeyType_KEY_TYPE_ECC_P384:
		algorithm = "ECCP384"
	default:
		return nil, fmt.Errorf("unsupported key type %s for yubikey generation", keyType)
	}

	tmpDir, err := os.MkdirTemp("", "stratium-yubikey-generate-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create temporary directory: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	publicPath := filepath.Join(tmpDir, "public.pem")
	args := []string{"-a", "generate", "-s", slot, "-A", algorithm, "-o", publicPath}
	if _, err := y.runner(y.pivToolPath(), y.configuredPIN(), args...); err != nil {
		return nil, err
	}

	publicPEM, err := os.ReadFile(publicPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read generated public key: %w", err)
	}

	publicKey, err := parsePublicKeyFromPEMBlob(publicPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse generated public key: %w", err)
	}

	return publicKey, nil
}

func (y *YubiKeyPIVCardReader) clearCachedPIN() {
	y.mu.Lock()
	defer y.mu.Unlock()
	y.sessionPIN = ""
	delete(y.config, "pin")
}

func parsePublicKeyFromPEMBlob(data []byte) (crypto.PublicKey, error) {
	remaining := data
	for {
		block, rest := pem.Decode(remaining)
		if block == nil {
			return nil, fmt.Errorf("failed to decode PEM")
		}

		switch block.Type {
		case "CERTIFICATE":
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}
			return cert.PublicKey, nil
		case "PUBLIC KEY", "RSA PUBLIC KEY", "EC PUBLIC KEY":
			if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
				return pub, nil
			}
			if pub, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
				return pub, nil
			}
		}

		if len(rest) == 0 {
			break
		}
		remaining = rest
	}

	return nil, fmt.Errorf("no parseable public key in PEM data")
}
