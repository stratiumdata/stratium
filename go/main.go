// main.go
package _go

import (
	"bytes"
	"fmt"
	"stratium/pkg/security/encryption"
	"stratium/pkg/security/encryption/factory"
)

// EncryptionProvider executes encryption/decryption using the specified algorithm.
// This function handles KEM-based algorithms (like Kyber) differently from direct
// encryption algorithms (like RSA and ECC).
func EncryptionProvider(algorithm encryption.Algorithm) error {
	// Create the encryption provider using the unified factory
	provider, err := factory.NewEncryptionProvider(algorithm)
	if err != nil {
		return fmt.Errorf("error initializing encryption provider: %w", err)
	}

	algorithmType := factory.GetAlgorithmType(algorithm)

	switch algorithmType {
	case "KEM":
		return handleKEMAlgorithm(provider, algorithm)
	case "RSA", "ECC":
		return handleDirectEncryption(provider, algorithm)
	default:
		return fmt.Errorf("unsupported algorithm type: %s", algorithmType)
	}
}

// handleKEMAlgorithm handles KEM-based algorithms (Kyber)
func handleKEMAlgorithm(provider factory.EncryptionProvider, algorithm encryption.Algorithm) error {
	// For KEM algorithms, we need to access the KEM-specific methods
	kemProvider, ok := provider.(*factory.KEMProvider)
	if !ok {
		return fmt.Errorf("provider is not a KEM provider")
	}

	fmt.Println("Encapsulating a shared secret with the public key...")
	ciphertext, senderSecret := kemProvider.EncapsulateTo(nil)
	fmt.Println("Shared secret encapsulated. Ciphertext and secret generated.")

	fmt.Println("Decapsulating the shared secret with the private key...")
	recipientSecret := kemProvider.DecapsulateTo(ciphertext)
	fmt.Println("Shared secret decapsulated successfully.")

	// Verify that the two secrets are identical
	if !bytes.Equal(senderSecret, recipientSecret) {
		return fmt.Errorf("failure! the shared secrets do not match. KEM failure detected")
	}

	fmt.Println("\nSuccess! The sender's and recipient's shared secrets match.")
	fmt.Printf("Shared Secret Size: %d bytes\n", len(senderSecret))

	// Use the shared secret for encrypting a message
	message := "The secure session has been established using " + string(algorithm) + " PQC KEM!"
	fmt.Printf("\nOriginal message: %s\n", message)

	// Encrypt the message with AES-256 GCM using the sender's shared secret
	encryptedMessage, err := kemProvider.Encrypt(senderSecret, []byte(message))
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}
	fmt.Println("Message encrypted successfully.")

	// Decrypt the message with AES-256 GCM using the recipient's shared secret
	decryptedMessage, err := kemProvider.Decrypt(recipientSecret, encryptedMessage)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}
	fmt.Println("Message decrypted successfully.")

	// Verify that the original and decrypted messages are identical
	if string(decryptedMessage) != message {
		return fmt.Errorf("message integrity check FAILED: decrypted message does not match the original")
	}

	fmt.Println("Message integrity check: The decrypted message is identical to the original.")
	fmt.Printf("Decrypted message: %s\n", decryptedMessage)
	return nil
}

// handleDirectEncryption handles direct encryption algorithms (RSA, ECC)
func handleDirectEncryption(provider factory.EncryptionProvider, algorithm encryption.Algorithm) error {
	message := "The secure session has been established using " + string(algorithm) + " encryption!"
	fmt.Printf("\nOriginal message: %s\n", message)

	// For RSA and ECC, we encrypt directly with the provider
	// The key parameter is ignored for these algorithms as they use their own key pairs
	encryptedMessage, err := provider.Encrypt(nil, []byte(message))
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}
	fmt.Println("Message encrypted successfully.")

	// Decrypt the message
	decryptedMessage, err := provider.Decrypt(nil, encryptedMessage)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}
	fmt.Println("Message decrypted successfully.")

	// Verify that the original and decrypted messages are identical
	if string(decryptedMessage) != message {
		return fmt.Errorf("message integrity check FAILED: decrypted message does not match the original")
	}

	fmt.Println("Message integrity check: The decrypted message is identical to the original.")
	fmt.Printf("Decrypted message: %s\n", decryptedMessage)
	return nil
}
