package main

import (
	"context"
	"flag"
	"log"
	"time"

	keyManager "stratium/services/key-manager"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	addr = flag.String("addr", "localhost:50052", "the address to connect to")
)

func main() {
	flag.Parse()

	// Set up a connection to the server
	conn, err := grpc.NewClient(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()

	// Create client
	client := keyManager.NewKeyManagerServiceClient(conn)

	// Set up context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Example 1: List available providers
	log.Println("=== Testing ListProviders ===")
	providersResp, err := client.ListProviders(ctx, &keyManager.ListProvidersRequest{})
	if err != nil {
		log.Fatalf("ListProviders failed: %v", err)
	}

	log.Printf("Available providers: %d", len(providersResp.Providers))
	for i, provider := range providersResp.Providers {
		log.Printf("Provider %d:", i+1)
		log.Printf("  Type: %s", provider.Type.String())
		log.Printf("  Name: %s", provider.Name)
		log.Printf("  Available: %t", provider.Available)
		log.Printf("  Supports Hardware Security: %t", provider.SupportsHardwareSecurity)
		log.Printf("  Supported Key Types: %v", provider.SupportedKeyTypes)
	}

	// Example 2: Create a software key
	log.Println("\n=== Testing CreateKey ===")
	createKeyReq := &keyManager.CreateKeyRequest{
		Name:                 "example-client-key",
		KeyType:              keyManager.KeyType_KEY_TYPE_RSA_2048,
		ProviderType:         keyManager.KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		RotationPolicy:       keyManager.RotationPolicy_ROTATION_POLICY_TIME_BASED,
		RotationIntervalDays: 90,
		AuthorizedSubjects:   []string{"client-example", "user123"},
		AuthorizedResources:  []string{"example-resource", "test-data"},
		Metadata: map[string]string{
			"environment": "development",
			"client":      "example-client",
		},
	}

	createKeyResp, err := client.CreateKey(ctx, createKeyReq)
	if err != nil {
		log.Fatalf("CreateKey failed: %v", err)
	}

	keyID := createKeyResp.Key.KeyId
	log.Printf("Created key with ID: %s", keyID)
	log.Printf("Key Type: %s", createKeyResp.Key.KeyType.String())
	log.Printf("Provider Type: %s", createKeyResp.Key.ProviderType.String())
	log.Printf("Status: %s", createKeyResp.Key.Status.String())

	// Example 3: Get the created key
	log.Println("\n=== Testing GetKey ===")
	getKeyReq := &keyManager.GetKeyRequest{
		KeyId:            keyID,
		IncludePublicKey: true,
	}

	getKeyResp, err := client.GetKey(ctx, getKeyReq)
	if err != nil {
		log.Fatalf("GetKey failed: %v", err)
	}

	log.Printf("Retrieved key: %s", getKeyResp.Key.Name)
	log.Printf("Public Key (first 100 chars): %.100s...", getKeyResp.Key.PublicKeyPem)
	log.Printf("Usage Count: %d", getKeyResp.Key.UsageCount)

	// Example 4: List keys
	log.Println("\n=== Testing ListKeys ===")
	listKeysReq := &keyManager.ListKeysRequest{
		PageSize: 10,
	}

	listKeysResp, err := client.ListKeys(ctx, listKeysReq)
	if err != nil {
		log.Fatalf("ListKeys failed: %v", err)
	}

	log.Printf("Total keys: %d", listKeysResp.TotalCount)
	log.Printf("Returned keys: %d", len(listKeysResp.Keys))

	for i, key := range listKeysResp.Keys {
		log.Printf("Key %d:", i+1)
		log.Printf("  ID: %s", key.KeyId)
		log.Printf("  Name: %s", key.Name)
		log.Printf("  Type: %s", key.KeyType.String())
		log.Printf("  Provider: %s", key.ProviderType.String())
		log.Printf("  Status: %s", key.Status.String())
	}

	// Example 5: Test DEK unwrapping (will likely fail due to ABAC rules)
	log.Println("\n=== Testing UnwrapDEK ===")

	// Mock encrypted DEK
	mockEncryptedDEK := []byte("mock-encrypted-dek-for-testing")

	unwrapDEKReq := &keyManager.UnwrapDEKRequest{
		Subject:      "client-example",
		Resource:     "example-resource",
		EncryptedDek: mockEncryptedDEK,
		KeyId:        keyID,
		Action:       "unwrap_dek",
		Context: map[string]string{
			"client_ip":   "127.0.0.1",
			"user_agent":  "key-manager-client/1.0",
			"environment": "development",
		},
	}

	unwrapDEKResp, err := client.UnwrapDEK(ctx, unwrapDEKReq)
	if err != nil {
		log.Fatalf("UnwrapDEK failed: %v", err)
	}

	log.Printf("DEK Unwrap Access Granted: %t", unwrapDEKResp.AccessGranted)
	log.Printf("Access Reason: %s", unwrapDEKResp.AccessReason)
	log.Printf("Applied Rules: %v", unwrapDEKResp.AppliedRules)

	if unwrapDEKResp.AccessGranted {
		log.Printf("Subject Key ID: %s", unwrapDEKResp.SubjectKeyId)
		log.Printf("Encrypted DEK for Subject length: %d bytes", len(unwrapDEKResp.EncryptedDekForSubject))
	}

	// Example 6: Test key rotation
	log.Println("\n=== Testing RotateKey ===")
	rotateKeyReq := &keyManager.RotateKeyRequest{
		KeyId: keyID,
		Force: true,
	}

	rotateKeyResp, err := client.RotateKey(ctx, rotateKeyReq)
	if err != nil {
		log.Fatalf("RotateKey failed: %v", err)
	}

	log.Printf("Key rotation successful")
	log.Printf("Old key created: %s", rotateKeyResp.OldKey.CreatedAt.AsTime().Format(time.RFC3339))
	log.Printf("New key created: %s", rotateKeyResp.NewKey.CreatedAt.AsTime().Format(time.RFC3339))
	log.Printf("New key last rotated: %s", rotateKeyResp.NewKey.LastRotated.AsTime().Format(time.RFC3339))

	// Example 7: Test with different provider (HSM)
	log.Println("\n=== Testing CreateKey with HSM Provider ===")
	createHSMKeyReq := &keyManager.CreateKeyRequest{
		Name:               "example-hsm-key",
		KeyType:            keyManager.KeyType_KEY_TYPE_RSA_2048,
		ProviderType:       keyManager.KeyProviderType_KEY_PROVIDER_TYPE_HSM,
		AuthorizedSubjects: []string{"hsm-user"},
		Metadata: map[string]string{
			"environment": "production",
			"compliance":  "fips-140-2",
		},
	}

	createHSMKeyResp, err := client.CreateKey(ctx, createHSMKeyReq)
	if err != nil {
		log.Printf("CreateKey with HSM failed (expected in demo): %v", err)
	} else {
		log.Printf("Created HSM key with ID: %s", createHSMKeyResp.Key.KeyId)
	}

	// Example 8: List keys with filters
	log.Println("\n=== Testing ListKeys with Subject Filter ===")
	listFilteredKeysReq := &keyManager.ListKeysRequest{
		SubjectFilter: "client-example",
		PageSize:      5,
	}

	listFilteredKeysResp, err := client.ListKeys(ctx, listFilteredKeysReq)
	if err != nil {
		log.Fatalf("ListKeys with filter failed: %v", err)
	}

	log.Printf("Filtered keys count: %d", len(listFilteredKeysResp.Keys))
	for _, key := range listFilteredKeysResp.Keys {
		log.Printf("  - %s (%s)", key.Name, key.KeyId)
	}

	// Example 9: Clean up - delete the created key
	log.Println("\n=== Testing DeleteKey ===")
	deleteKeyReq := &keyManager.DeleteKeyRequest{
		KeyId: keyID,
		Force: true,
	}

	deleteKeyResp, err := client.DeleteKey(ctx, deleteKeyReq)
	if err != nil {
		log.Fatalf("DeleteKey failed: %v", err)
	}

	log.Printf("Delete key success: %t", deleteKeyResp.Success)
	log.Printf("Delete message: %s", deleteKeyResp.Message)

	log.Println("\n=== Key Manager Client Example Completed Successfully ===")
}
