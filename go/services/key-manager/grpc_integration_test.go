package key_manager

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"stratium/pkg/security/encryption"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestKeyManagerGRPC_RewrapAndUnwrap(t *testing.T) {
	algorithms := []struct {
		name    string
		alg     encryption.Algorithm
		keyType KeyType
	}{
		{"RSA2048", encryption.RSA2048, KeyType_KEY_TYPE_RSA_2048},
		{"ECC_P256", encryption.ECC_P256, KeyType_KEY_TYPE_ECC_P256},
	}

	for _, tc := range algorithms {
		t.Run(tc.name, func(t *testing.T) {
			server := newTestKeyManagerServer(t, tc.alg)

			clientPriv, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("failed to generate client key: %v", err)
			}
			clientKeyID := seedClientKey(t, server, "sdk-client", clientPriv)

			lis := bufconn.Listen(1 << 20)
			grpcServer := grpc.NewServer()
			RegisterKeyManagerServiceServer(grpcServer, server)
			go func() {
				if err := grpcServer.Serve(lis); err != nil {
					t.Logf("grpc server exited: %v", err)
				}
			}()
			t.Cleanup(func() {
				grpcServer.Stop()
				lis.Close()
			})

			dialCtx := context.Background()
			conn, err := grpc.DialContext(dialCtx, "bufnet", grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) {
				return lis.Dial()
			}), grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				t.Fatalf("failed to dial bufconn: %v", err)
			}
			defer conn.Close()

			client := NewKeyManagerServiceClient(conn)

			createResp, err := client.CreateKey(context.Background(), &CreateKeyRequest{
				Name:         "service-key-" + tc.name,
				KeyType:      tc.keyType,
				ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
			})
			if err != nil {
				t.Fatalf("CreateKey failed: %v", err)
			}
			serviceKeyID := createResp.Key.KeyId

			dek := make([]byte, 32)
			if _, err := rand.Read(dek); err != nil {
				t.Fatalf("failed to generate DEK: %v", err)
			}

			clientWrapped, err := wrapClientDEK(clientPriv, dek)
			if err != nil {
				t.Fatalf("failed to wrap DEK with client key: %v", err)
			}

			rewrapResp, err := client.RewrapClientDEK(context.Background(), &RewrapClientDEKRequest{
				Subject:          "user123",
				ClientKeyId:      clientKeyID,
				ClientWrappedDek: clientWrapped,
				ServiceKeyId:     serviceKeyID,
				Resource:         "resource-" + tc.name,
			})
			if err != nil {
				t.Fatalf("RewrapClientDEK failed: %v", err)
			}
			if len(rewrapResp.ServiceWrappedDek) == 0 {
				t.Fatalf("expected service wrapped DEK to be returned")
			}

			unwrapResp, err := client.UnwrapDEK(context.Background(), &UnwrapDEKRequest{
				Subject:      "user123",
				Resource:     "resource-" + tc.name,
				EncryptedDek: rewrapResp.ServiceWrappedDek,
				ClientKeyId:  clientKeyID,
				KeyId:        serviceKeyID,
				Action:       "unwrap_dek",
				Context:      map[string]string{},
			})
			if err != nil {
				t.Fatalf("UnwrapDEK failed: %v", err)
			}
			if !unwrapResp.AccessGranted {
				t.Fatalf("expected unwrap access granted, got %v", unwrapResp.AccessReason)
			}
			if len(unwrapResp.EncryptedDekForSubject) == 0 {
				t.Fatalf("expected DEK for subject to be returned")
			}

			recoveredDEK, err := decryptClientDEK(clientPriv, unwrapResp.EncryptedDekForSubject)
			if err != nil {
				t.Fatalf("failed to decrypt DEK for subject: %v", err)
			}
			if !bytes.Equal(recoveredDEK, dek) {
				t.Fatalf("recovered DEK mismatch for %s", tc.name)
			}
		})
	}
}

func seedClientKey(t *testing.T, server *Server, clientID string, priv *rsa.PrivateKey) string {
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal client public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	keyID := fmt.Sprintf("client-key-%d", time.Now().UnixNano())
	key := &Key{
		KeyId:        keyID,
		ClientId:     clientID,
		PublicKeyPem: string(pubPEM),
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		Status:       KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:    timestamppb.Now(),
	}

	if err := server.clientKeyStore.RegisterKey(context.Background(), key); err != nil {
		t.Fatalf("failed to seed client key: %v", err)
	}

	return keyID
}

func wrapClientDEK(privateKey *rsa.PrivateKey, dek []byte) ([]byte, error) {
	k := (privateKey.N.BitLen() + 7) / 8
	if len(dek) > k-11 {
		return nil, fmt.Errorf("DEK too large for client key")
	}

	em := make([]byte, k)
	em[0] = 0x00
	em[1] = 0x01
	psLen := k - len(dek) - 3
	for i := 0; i < psLen; i++ {
		em[2+i] = 0xff
	}
	em[2+psLen] = 0x00
	copy(em[3+psLen:], dek)

	m := new(big.Int).SetBytes(em)
	if m.Cmp(privateKey.N) >= 0 {
		return nil, fmt.Errorf("message representative out of range")
	}

	c := new(big.Int).Exp(m, privateKey.D, privateKey.N)
	out := c.Bytes()
	if len(out) < k {
		padded := make([]byte, k)
		copy(padded[k-len(out):], out)
		out = padded
	}
	return out, nil
}

func decryptClientDEK(privateKey *rsa.PrivateKey, encrypted []byte) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, privateKey, encrypted, nil)
}
