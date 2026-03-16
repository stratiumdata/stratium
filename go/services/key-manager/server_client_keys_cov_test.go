//go:build !fips

package key_manager

import (
	"context"
	"testing"
)

func TestCoverageFinal80_ServerClientKeys_RegisterAndList(t *testing.T) {
	srv := newTestKeyManagerServer(t, "RSA2048")
	ctx := ctxWithUser("test-user-final80")

	pubPEM := generateRSAPEM(t)

	// Register a client key
	resp, err := srv.RegisterClientKey(ctx, &RegisterClientKeyRequest{
		PublicKeyPem: pubPEM,
		ClientId:     "test-app",
	})
	if err != nil {
		t.Fatalf("RegisterClientKey: %v", err)
	}
	if !resp.Success {
		t.Fatalf("RegisterClientKey not successful: %s", resp.ErrorMessage)
	}

	// List client keys
	listResp, err := srv.ListClientKeys(ctx, &ListClientKeysRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(listResp.Keys) == 0 {
		t.Fatal("expected at least one key")
	}

	// Revoke the key
	revokeResp, err := srv.RevokeClientKey(ctx, &RevokeClientKeyRequest{
		KeyId:  resp.Key.KeyId,
		Reason: "test revocation",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !revokeResp.Success {
		t.Fatalf("RevokeClientKey not successful: %s", revokeResp.ErrorMessage)
	}

	// ListClients
	clientsResp, err := srv.ListClients(ctx, &ListClientsRequest{})
	if err != nil {
		t.Fatal(err)
	}
	if len(clientsResp.Clients) == 0 {
		t.Fatal("expected at least one client")
	}
}

func TestCoverageFinal80_ServerClientKeys_NoAuth(t *testing.T) {
	srv := newTestKeyManagerServer(t, "RSA2048")
	ctx := context.Background() // no user claims

	resp, err := srv.RegisterClientKey(ctx, &RegisterClientKeyRequest{
		PublicKeyPem: "fake",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Success {
		t.Fatal("expected failure with no auth")
	}
}
