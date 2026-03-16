package key_access

import (
	"context"
	"net"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// fakeKeyAccessServer is a minimal KeyAccessServiceServer for wire testing.
type fakeKeyAccessServer struct {
	UnimplementedKeyAccessServiceServer
}

func (f *fakeKeyAccessServer) WrapDEK(_ context.Context, _ *WrapDEKRequest) (*WrapDEKResponse, error) {
	return &WrapDEKResponse{
		WrappedDek:    []byte("test"),
		KeyId:         "k1",
		AccessGranted: true,
	}, nil
}

func (f *fakeKeyAccessServer) UnwrapDEK(_ context.Context, _ *UnwrapDEKRequest) (*UnwrapDEKResponse, error) {
	return &UnwrapDEKResponse{
		DekForSubject: []byte("plaintext"),
		AccessGranted: true,
	}, nil
}

// newBufconnKeyAccessClient starts a bufconn-backed KeyAccessService gRPC server
// and returns a client connected to it plus a cleanup function.
func newBufconnKeyAccessClient(t *testing.T) (KeyAccessServiceClient, func()) {
	t.Helper()

	lis := bufconn.Listen(1 << 20)
	grpcServer := grpc.NewServer()
	RegisterKeyAccessServiceServer(grpcServer, &fakeKeyAccessServer{})

	go func() {
		if err := grpcServer.Serve(lis); err != nil {
			t.Logf("bufconn grpc server exited: %v", err)
		}
	}()

	conn, err := grpc.DialContext(context.Background(), "bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}

	cleanup := func() {
		conn.Close()
		grpcServer.Stop()
		lis.Close()
	}

	return NewKeyAccessServiceClient(conn), cleanup
}

// TestWire_WrapDEK_ClientStub exercises the gRPC client stub, RegisterKeyAccessServiceServer,
// and the _KeyAccessService_WrapDEK_Handler dispatch code.
func TestWire_WrapDEK_ClientStub(t *testing.T) {
	client, cleanup := newBufconnKeyAccessClient(t)
	defer cleanup()

	resp, err := client.WrapDEK(context.Background(), &WrapDEKRequest{
		Resource:    "test-resource",
		Dek:         []byte("plaintext-dek"),
		KeyId:       "k1",
		Action:      "wrap_dek",
		ClientKeyId: "client-k1",
		Policy:      "base64policy",
		Context:     map[string]string{"env": "test"},
	})
	if err != nil {
		t.Fatalf("WrapDEK via gRPC wire: %v", err)
	}
	if !resp.AccessGranted {
		t.Errorf("expected AccessGranted=true, got false")
	}
	if resp.KeyId != "k1" {
		t.Errorf("expected KeyId=k1, got %s", resp.KeyId)
	}
	if string(resp.WrappedDek) != "test" {
		t.Errorf("unexpected WrappedDek: %q", resp.WrappedDek)
	}
}

// TestWire_UnwrapDEK_ClientStub exercises the gRPC client stub and
// the _KeyAccessService_UnwrapDEK_Handler dispatch code.
func TestWire_UnwrapDEK_ClientStub(t *testing.T) {
	client, cleanup := newBufconnKeyAccessClient(t)
	defer cleanup()

	resp, err := client.UnwrapDEK(context.Background(), &UnwrapDEKRequest{
		Resource:    "test-resource",
		WrappedDek:  []byte("wrapped-dek"),
		KeyId:       "k1",
		ClientKeyId: "client-k1",
		Action:      "unwrap_dek",
		Policy:      "base64policy",
		Context:     map[string]string{"env": "test"},
	})
	if err != nil {
		t.Fatalf("UnwrapDEK via gRPC wire: %v", err)
	}
	if !resp.AccessGranted {
		t.Errorf("expected AccessGranted=true, got false")
	}
	if string(resp.DekForSubject) != "plaintext" {
		t.Errorf("unexpected DekForSubject: %q", resp.DekForSubject)
	}
}

// TestProtoMessageGetters exercises the generated getter methods and lifecycle
// methods (Reset, String, ProtoMessage) on all four proto message types to
// drive up coverage of key-access.pb.go.
func TestProtoMessageGetters(t *testing.T) {
	ts := timestamppb.Now()

	// --- WrapDEKRequest ---
	wrapReq := &WrapDEKRequest{
		Resource:    "my-resource",
		Dek:         []byte("dek-bytes"),
		KeyId:       "key-1",
		Action:      "wrap_dek",
		Context:     map[string]string{"k": "v"},
		Policy:      "policy-b64",
		ClientKeyId: "client-key-1",
	}

	if wrapReq.GetResource() != "my-resource" {
		t.Errorf("GetResource mismatch")
	}
	if string(wrapReq.GetDek()) != "dek-bytes" {
		t.Errorf("GetDek mismatch")
	}
	if wrapReq.GetKeyId() != "key-1" {
		t.Errorf("GetKeyId mismatch")
	}
	if wrapReq.GetAction() != "wrap_dek" {
		t.Errorf("GetAction mismatch")
	}
	if wrapReq.GetContext()["k"] != "v" {
		t.Errorf("GetContext mismatch")
	}
	if wrapReq.GetPolicy() != "policy-b64" {
		t.Errorf("GetPolicy mismatch")
	}
	if wrapReq.GetClientKeyId() != "client-key-1" {
		t.Errorf("GetClientKeyId mismatch")
	}
	wrapReq.ProtoMessage()
	_ = wrapReq.String()
	wrapReq.Reset()

	// Getters on zero-value / nil
	var nilWrapReq *WrapDEKRequest
	_ = nilWrapReq.GetResource()
	_ = nilWrapReq.GetDek()
	_ = nilWrapReq.GetKeyId()
	_ = nilWrapReq.GetAction()
	_ = nilWrapReq.GetContext()
	_ = nilWrapReq.GetPolicy()
	_ = nilWrapReq.GetClientKeyId()

	// --- WrapDEKResponse ---
	wrapResp := &WrapDEKResponse{
		WrappedDek:    []byte("wrapped"),
		KeyId:         "key-2",
		AccessGranted: true,
		AccessReason:  "allowed",
		AppliedRules:  []string{"rule-1"},
		Timestamp:     ts,
	}

	if string(wrapResp.GetWrappedDek()) != "wrapped" {
		t.Errorf("GetWrappedDek mismatch")
	}
	if wrapResp.GetKeyId() != "key-2" {
		t.Errorf("GetKeyId mismatch")
	}
	if !wrapResp.GetAccessGranted() {
		t.Errorf("GetAccessGranted mismatch")
	}
	if wrapResp.GetAccessReason() != "allowed" {
		t.Errorf("GetAccessReason mismatch")
	}
	if len(wrapResp.GetAppliedRules()) != 1 || wrapResp.GetAppliedRules()[0] != "rule-1" {
		t.Errorf("GetAppliedRules mismatch")
	}
	if wrapResp.GetTimestamp() != ts {
		t.Errorf("GetTimestamp mismatch")
	}
	wrapResp.ProtoMessage()
	_ = wrapResp.String()
	wrapResp.Reset()

	// Getters on nil
	var nilWrapResp *WrapDEKResponse
	_ = nilWrapResp.GetWrappedDek()
	_ = nilWrapResp.GetKeyId()
	_ = nilWrapResp.GetAccessGranted()
	_ = nilWrapResp.GetAccessReason()
	_ = nilWrapResp.GetAppliedRules()
	_ = nilWrapResp.GetTimestamp()

	// --- UnwrapDEKRequest ---
	unwrapReq := &UnwrapDEKRequest{
		Resource:    "res",
		WrappedDek:  []byte("wd"),
		KeyId:       "key-3",
		ClientKeyId: "client-key-3",
		Action:      "unwrap_dek",
		Context:     map[string]string{"env": "prod"},
		Policy:      "policy-b64-2",
	}

	if unwrapReq.GetResource() != "res" {
		t.Errorf("GetResource mismatch")
	}
	if string(unwrapReq.GetWrappedDek()) != "wd" {
		t.Errorf("GetWrappedDek mismatch")
	}
	if unwrapReq.GetKeyId() != "key-3" {
		t.Errorf("GetKeyId mismatch")
	}
	if unwrapReq.GetClientKeyId() != "client-key-3" {
		t.Errorf("GetClientKeyId mismatch")
	}
	if unwrapReq.GetAction() != "unwrap_dek" {
		t.Errorf("GetAction mismatch")
	}
	if unwrapReq.GetContext()["env"] != "prod" {
		t.Errorf("GetContext mismatch")
	}
	if unwrapReq.GetPolicy() != "policy-b64-2" {
		t.Errorf("GetPolicy mismatch")
	}
	unwrapReq.ProtoMessage()
	_ = unwrapReq.String()
	unwrapReq.Reset()

	// Getters on nil
	var nilUnwrapReq *UnwrapDEKRequest
	_ = nilUnwrapReq.GetResource()
	_ = nilUnwrapReq.GetWrappedDek()
	_ = nilUnwrapReq.GetKeyId()
	_ = nilUnwrapReq.GetClientKeyId()
	_ = nilUnwrapReq.GetAction()
	_ = nilUnwrapReq.GetContext()
	_ = nilUnwrapReq.GetPolicy()

	// --- UnwrapDEKResponse ---
	unwrapResp := &UnwrapDEKResponse{
		DekForSubject: []byte("plaintext-dek"),
		AccessGranted: true,
		AccessReason:  "granted",
		AppliedRules:  []string{"rule-2", "rule-3"},
		Timestamp:     ts,
	}

	if string(unwrapResp.GetDekForSubject()) != "plaintext-dek" {
		t.Errorf("GetDekForSubject mismatch")
	}
	if !unwrapResp.GetAccessGranted() {
		t.Errorf("GetAccessGranted mismatch")
	}
	if unwrapResp.GetAccessReason() != "granted" {
		t.Errorf("GetAccessReason mismatch")
	}
	if len(unwrapResp.GetAppliedRules()) != 2 {
		t.Errorf("GetAppliedRules mismatch")
	}
	if unwrapResp.GetTimestamp() != ts {
		t.Errorf("GetTimestamp mismatch")
	}
	unwrapResp.ProtoMessage()
	_ = unwrapResp.String()
	unwrapResp.Reset()

	// Getters on nil
	var nilUnwrapResp *UnwrapDEKResponse
	_ = nilUnwrapResp.GetDekForSubject()
	_ = nilUnwrapResp.GetAccessGranted()
	_ = nilUnwrapResp.GetAccessReason()
	_ = nilUnwrapResp.GetAppliedRules()
	_ = nilUnwrapResp.GetTimestamp()
}
