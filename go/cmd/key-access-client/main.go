// Key Access Service Client Example
//
// This client demonstrates how to interact with the Key Access Service,
// which provides DEK (Data Encryption Key) wrapping and unwrapping with ABAC.
//
// Authentication:
// The service requires a JWT token in the Authorization header.
// For testing, use mock tokens:
//   - "user-token"  : Regular user (user123) with limited access
//   - "admin-token" : Admin user (admin456) with full access
//
// Usage:
//
//	go run main.go -addr=localhost:50053 -token=user-token
//	go run main.go -addr=localhost:50053 -token=admin-token
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"stratium/pkg/ztdf"
	keyAccess "stratium/services/key-access"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

var (
	addr         = flag.String("addr", "localhost:50053", "the address to connect to")
	token        = flag.String("token", "user-token", "JWT token for authentication (use 'user-token' or 'admin-token' for testing)")
	clientKeyID  = flag.String("client-key-id", "", "client key ID registered with the key manager")
	clientKeyPEM = flag.String("client-key-file", "", "path to the client's RSA private key PEM file")
	policyB64    = flag.String("policy", "", "base64-encoded ZTDF policy (optional)")
)

func main() {
	flag.Parse()

	if *clientKeyID == "" || *clientKeyPEM == "" {
		log.Fatalf("client-key-id and client-key-file must be provided")
	}

	privateKey, err := loadRSAPrivateKey(*clientKeyPEM)
	if err != nil {
		log.Fatalf("failed to load client private key: %v", err)
	}

	// Set up a connection to the server
	conn, err := grpc.NewClient(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	// Create client
	client := keyAccess.NewKeyAccessServiceClient(conn)

	// Set up context with timeout and authentication token
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Add JWT token to context metadata
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+*token)
	log.Printf("Using authentication token: %s", *token)

	// Example 1: Test WrapDEK
	log.Println("=== Testing WrapDEK ===")

	// Generate a mock DEK (32 bytes for AES-256)
	mockDEK := make([]byte, 32)
	_, err = rand.Read(mockDEK)
	if err != nil {
		log.Fatalf("Failed to generate mock DEK: %v", err)
	}

	clientWrapped, err := ztdf.WrapDEKWithPrivateKey(privateKey, mockDEK)
	if err != nil {
		log.Fatalf("failed to wrap DEK with client key: %v", err)
	}

	wrapReq := &keyAccess.WrapDEKRequest{
		Resource:    "test-resource",
		Dek:         clientWrapped,
		Action:      "wrap_dek",
		ClientKeyId: *clientKeyID,
		Policy:      *policyB64,
		Context: map[string]string{
			"department":  "engineering",
			"environment": "development",
		},
	}

	wrapResp, err := client.WrapDEK(ctx, wrapReq)
	if err != nil {
		log.Fatalf("WrapDEK failed: %v", err)
	}

	log.Printf("Wrap Access Granted: %t", wrapResp.AccessGranted)
	log.Printf("Wrap Access Reason: %s", wrapResp.AccessReason)
	log.Printf("Applied Rules: %v", wrapResp.AppliedRules)
	log.Printf("Key ID Used: %s", wrapResp.KeyId)

	if wrapResp.AccessGranted {
		log.Printf("Wrapped DEK length: %d bytes", len(wrapResp.WrappedDek))
	}

	// Example 2: Test UnwrapDEK (only if wrap succeeded)
	if wrapResp.AccessGranted && len(wrapResp.WrappedDek) > 0 {
		log.Println("=== Testing UnwrapDEK ===")

		unwrapReq := &keyAccess.UnwrapDEKRequest{
			Resource:   "test-resource",
			WrappedDek: wrapResp.WrappedDek,
			KeyId:      wrapResp.KeyId,
			Policy:     *policyB64,
			Action:     "unwrap_dek",
			Context: map[string]string{
				"department":  "engineering",
				"environment": "development",
			},
		}

		unwrapResp, err := client.UnwrapDEK(ctx, unwrapReq)
		if err != nil {
			log.Fatalf("UnwrapDEK failed: %v", err)
		}

		log.Printf("Unwrap Access Granted: %t", unwrapResp.AccessGranted)
		log.Printf("Unwrap Access Reason: %s", unwrapResp.AccessReason)
		log.Printf("Applied Rules: %v", unwrapResp.AppliedRules)

		if unwrapResp.AccessGranted {
			log.Printf("DEK for Subject length: %d bytes", len(unwrapResp.DekForSubject))
		}
	}

	// Example 3: Test with unauthorized resource
	log.Println("=== Testing WrapDEK with Unauthorized Resource ===")

	unauthorizedWrapped, err := ztdf.WrapDEKWithPrivateKey(privateKey, mockDEK)
	if err != nil {
		log.Fatalf("failed to wrap DEK for unauthorized request: %v", err)
	}

	unauthorizedReq := &keyAccess.WrapDEKRequest{
		Resource:    "secret-resource",
		Dek:         unauthorizedWrapped,
		Action:      "wrap_dek",
		ClientKeyId: *clientKeyID,
		Policy:      *policyB64,
		Context: map[string]string{
			"department": "unknown",
		},
	}

	unauthorizedResp, err := client.WrapDEK(ctx, unauthorizedReq)
	if err != nil {
		log.Fatalf("Unauthorized WrapDEK failed: %v", err)
	}

	log.Printf("Unauthorized Access Granted: %t", unauthorizedResp.AccessGranted)
	log.Printf("Unauthorized Access Reason: %s", unauthorizedResp.AccessReason)

	// Example 4: Test with admin user (requires using -token=admin-token flag)
	log.Println("=== Admin User Testing ===")
	if *token == "admin-token" {
		log.Println("Running as admin user (admin456)")

		adminWrapped, err := ztdf.WrapDEKWithPrivateKey(privateKey, mockDEK)
		if err != nil {
			log.Fatalf("failed to wrap DEK for admin request: %v", err)
		}

		adminWrapReq := &keyAccess.WrapDEKRequest{
			Resource:    "admin-resource",
			Dek:         adminWrapped,
			Action:      "wrap_dek",
			ClientKeyId: *clientKeyID,
			Policy:      *policyB64,
			Context: map[string]string{
				"role":        "admin",
				"environment": "production",
			},
		}

		adminWrapResp, err := client.WrapDEK(ctx, adminWrapReq)
		if err != nil {
			log.Fatalf("Admin WrapDEK failed: %v", err)
		}

		log.Printf("Admin Wrap Access Granted: %t", adminWrapResp.AccessGranted)
		log.Printf("Admin Wrap Access Reason: %s", adminWrapResp.AccessReason)
		log.Printf("Admin Applied Rules: %v", adminWrapResp.AppliedRules)
	} else {
		log.Println("Skipping admin tests (use -token=admin-token to run as admin)")
	}

	log.Println("=== Key Access Client Example Completed Successfully ===")
	log.Println("NOTE: To test different users, use the -token flag:")
	log.Println("  -token=user-token   : Regular user (user123)")
	log.Println("  -token=admin-token  : Admin user (admin456)")
	log.Println("  -token=<custom>     : Custom user with ID matching the token")
}

func loadRSAPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM file")
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("parsed PKCS#8 key is %T, want *rsa.PrivateKey", parsed)
	}
	return rsaKey, nil
}
