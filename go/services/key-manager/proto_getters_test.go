package key_manager

import (
	"testing"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// TestProtoEnums exercises enum methods on KeyProviderType, KeyType, KeyStatus, RotationPolicy.
func TestProtoEnums(t *testing.T) {
	// KeyProviderType
	for _, v := range []KeyProviderType{
		KeyProviderType_KEY_PROVIDER_TYPE_UNSPECIFIED,
		KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		KeyProviderType_KEY_PROVIDER_TYPE_HSM,
		KeyProviderType_KEY_PROVIDER_TYPE_SMART_CARD,
		KeyProviderType_KEY_PROVIDER_TYPE_USB_TOKEN,
	} {
		_ = v.String()
		_ = v.Enum()
		_ = v.Number()
		_ = v.Descriptor()
		_ = v.Type()
		_, _ = v.EnumDescriptor()
	}

	// KeyType
	for _, v := range []KeyType{
		KeyType_KEY_TYPE_UNSPECIFIED,
		KeyType_KEY_TYPE_RSA_2048,
		KeyType_KEY_TYPE_RSA_3072,
		KeyType_KEY_TYPE_RSA_4096,
		KeyType_KEY_TYPE_ECC_P256,
		KeyType_KEY_TYPE_ECC_P384,
		KeyType_KEY_TYPE_ECC_P521,
		KeyType_KEY_TYPE_KYBER_512,
		KeyType_KEY_TYPE_KYBER_768,
		KeyType_KEY_TYPE_KYBER_1024,
	} {
		_ = v.String()
		_ = v.Enum()
		_ = v.Number()
		_ = v.Descriptor()
		_ = v.Type()
		_, _ = v.EnumDescriptor()
	}

	// KeyStatus
	for _, v := range []KeyStatus{
		KeyStatus_KEY_STATUS_UNSPECIFIED,
		KeyStatus_KEY_STATUS_ACTIVE,
		KeyStatus_KEY_STATUS_INACTIVE,
		KeyStatus_KEY_STATUS_PENDING_ROTATION,
		KeyStatus_KEY_STATUS_DEPRECATED,
		KeyStatus_KEY_STATUS_COMPROMISED,
		KeyStatus_KEY_STATUS_REVOKED,
	} {
		_ = v.String()
		_ = v.Enum()
		_ = v.Number()
		_ = v.Descriptor()
		_ = v.Type()
		_, _ = v.EnumDescriptor()
	}

	// RotationPolicy
	for _, v := range []RotationPolicy{
		RotationPolicy_ROTATION_POLICY_UNSPECIFIED,
		RotationPolicy_ROTATION_POLICY_MANUAL,
		RotationPolicy_ROTATION_POLICY_TIME_BASED,
		RotationPolicy_ROTATION_POLICY_USAGE_BASED,
		RotationPolicy_ROTATION_POLICY_COMBINED,
	} {
		_ = v.String()
		_ = v.Enum()
		_ = v.Number()
		_ = v.Descriptor()
		_ = v.Type()
		_, _ = v.EnumDescriptor()
	}
}

// TestProto_KeyGetters exercises all getter methods on the Key message.
func TestProto_KeyGetters(t *testing.T) {
	ts := timestamppb.Now()
	k := &Key{
		KeyId:                "key-id-1",
		ClientId:             "client-1",
		Name:                 "my-key",
		KeyType:              KeyType_KEY_TYPE_RSA_2048,
		ProviderType:         KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		Status:               KeyStatus_KEY_STATUS_ACTIVE,
		PublicKeyPem:         "-----BEGIN PUBLIC KEY-----",
		CreatedAt:            ts,
		ExpiresAt:            ts,
		LastRotated:          ts,
		KeyIntegrityHash:     "abc123",
		RotationPolicy:       RotationPolicy_ROTATION_POLICY_TIME_BASED,
		RotationIntervalDays: 30,
		UsageCount:           5,
		MaxUsageCount:        100,
		Metadata:             map[string]string{"k": "v"},
		ExternallyManaged:    true,
		ExternalSource:       "vault",
		ExternalManifestPath: "/path/to/manifest",
		PrivateKeySource:     "encrypted-blob",
		ExternalLoadedAt:     ts,
	}

	_ = k.GetKeyId()
	_ = k.GetClientId()
	_ = k.GetName()
	_ = k.GetKeyType()
	_ = k.GetProviderType()
	_ = k.GetStatus()
	_ = k.GetPublicKeyPem()
	_ = k.GetCreatedAt()
	_ = k.GetExpiresAt()
	_ = k.GetLastRotated()
	_ = k.GetKeyIntegrityHash()
	_ = k.GetRotationPolicy()
	_ = k.GetRotationIntervalDays()
	_ = k.GetUsageCount()
	_ = k.GetMaxUsageCount()
	_ = k.GetMetadata()
	_ = k.GetExternallyManaged()
	_ = k.GetExternalSource()
	_ = k.GetExternalManifestPath()
	_ = k.GetPrivateKeySource()
	_ = k.GetExternalLoadedAt()
	_ = k.String()
	_ = k.ProtoReflect()
	k.ProtoMessage()
	_, _ = k.Descriptor()
	k.Reset()

	// nil receiver paths
	var nilKey *Key
	_ = nilKey.GetKeyId()
	_ = nilKey.GetClientId()
	_ = nilKey.GetName()
	_ = nilKey.GetKeyType()
	_ = nilKey.GetProviderType()
	_ = nilKey.GetStatus()
	_ = nilKey.GetPublicKeyPem()
	_ = nilKey.GetCreatedAt()
	_ = nilKey.GetExpiresAt()
	_ = nilKey.GetLastRotated()
	_ = nilKey.GetKeyIntegrityHash()
	_ = nilKey.GetRotationPolicy()
	_ = nilKey.GetRotationIntervalDays()
	_ = nilKey.GetUsageCount()
	_ = nilKey.GetMaxUsageCount()
	_ = nilKey.GetMetadata()
	_ = nilKey.GetExternallyManaged()
	_ = nilKey.GetExternalSource()
	_ = nilKey.GetExternalManifestPath()
	_ = nilKey.GetPrivateKeySource()
	_ = nilKey.GetExternalLoadedAt()
}

// TestProto_KeyProviderGetters exercises all getter methods on KeyProvider.
func TestProto_KeyProviderGetters(t *testing.T) {
	kp := &KeyProvider{
		Type:                     KeyProviderType_KEY_PROVIDER_TYPE_HSM,
		Name:                     "my-hsm",
		Description:              "Hardware Security Module",
		Available:                true,
		Configuration:            map[string]string{"slot": "1"},
		SupportedKeyTypes:        []KeyType{KeyType_KEY_TYPE_RSA_2048, KeyType_KEY_TYPE_ECC_P256},
		SupportsRotation:         true,
		SupportsHardwareSecurity: true,
	}

	_ = kp.GetType()
	_ = kp.GetName()
	_ = kp.GetDescription()
	_ = kp.GetAvailable()
	_ = kp.GetConfiguration()
	_ = kp.GetSupportedKeyTypes()
	_ = kp.GetSupportsRotation()
	_ = kp.GetSupportsHardwareSecurity()
	_ = kp.String()
	_ = kp.ProtoReflect()
	kp.ProtoMessage()
	_, _ = kp.Descriptor()
	kp.Reset()

	var nilKP *KeyProvider
	_ = nilKP.GetType()
	_ = nilKP.GetName()
	_ = nilKP.GetDescription()
	_ = nilKP.GetAvailable()
	_ = nilKP.GetConfiguration()
	_ = nilKP.GetSupportedKeyTypes()
	_ = nilKP.GetSupportsRotation()
	_ = nilKP.GetSupportsHardwareSecurity()
}

// TestProto_ABACRuleGetters exercises ABACRule getter methods.
func TestProto_ABACRuleGetters(t *testing.T) {
	cond := &Condition{
		Type:       "time",
		Operator:   "before",
		Value:      "2026-01-01",
		Parameters: map[string]string{"tz": "UTC"},
	}
	rule := &ABACRule{
		RuleId:             "rule-1",
		Name:               "test-rule",
		RequiredAttributes: []string{"attr1", "attr2"},
		Conditions:         []*Condition{cond},
		AllowedActions:     []string{"read", "write"},
		Enabled:            true,
	}

	_ = rule.GetRuleId()
	_ = rule.GetName()
	_ = rule.GetRequiredAttributes()
	_ = rule.GetConditions()
	_ = rule.GetAllowedActions()
	_ = rule.GetEnabled()
	_ = rule.String()
	_ = rule.ProtoReflect()
	rule.ProtoMessage()
	_, _ = rule.Descriptor()
	rule.Reset()

	var nilRule *ABACRule
	_ = nilRule.GetRuleId()
	_ = nilRule.GetName()
	_ = nilRule.GetRequiredAttributes()
	_ = nilRule.GetConditions()
	_ = nilRule.GetAllowedActions()
	_ = nilRule.GetEnabled()
}

// TestProto_ConditionGetters exercises Condition getter methods.
func TestProto_ConditionGetters(t *testing.T) {
	c := &Condition{
		Type:       "attribute",
		Operator:   "equals",
		Value:      "admin",
		Parameters: map[string]string{"key": "value"},
	}

	_ = c.GetType()
	_ = c.GetOperator()
	_ = c.GetValue()
	_ = c.GetParameters()
	_ = c.String()
	_ = c.ProtoReflect()
	c.ProtoMessage()
	_, _ = c.Descriptor()
	c.Reset()

	var nilC *Condition
	_ = nilC.GetType()
	_ = nilC.GetOperator()
	_ = nilC.GetValue()
	_ = nilC.GetParameters()
}

// TestProto_CreateKeyRequestGetters exercises CreateKeyRequest getter methods.
func TestProto_CreateKeyRequestGetters(t *testing.T) {
	ts := timestamppb.Now()
	req := &CreateKeyRequest{
		Name:                 "new-key",
		KeyType:              KeyType_KEY_TYPE_ECC_P256,
		ProviderType:         KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		RotationPolicy:       RotationPolicy_ROTATION_POLICY_TIME_BASED,
		RotationIntervalDays: 90,
		MaxUsageCount:        1000,
		ExpiresAt:            ts,
		Metadata:             map[string]string{"env": "prod"},
		AuthorizedSubjects:   []string{"sub1"},
		AuthorizedResources:  []string{"res1"},
		ProviderConfig:       map[string]string{"config": "value"},
	}

	_ = req.GetName()
	_ = req.GetKeyType()
	_ = req.GetProviderType()
	_ = req.GetRotationPolicy()
	_ = req.GetRotationIntervalDays()
	_ = req.GetMaxUsageCount()
	_ = req.GetExpiresAt()
	_ = req.GetMetadata()
	_ = req.GetAuthorizedSubjects()
	_ = req.GetAuthorizedResources()
	_ = req.GetProviderConfig()
	_ = req.String()
	_ = req.ProtoReflect()
	req.ProtoMessage()
	_, _ = req.Descriptor()
	req.Reset()

	var nilReq *CreateKeyRequest
	_ = nilReq.GetName()
	_ = nilReq.GetKeyType()
	_ = nilReq.GetProviderType()
	_ = nilReq.GetRotationPolicy()
	_ = nilReq.GetRotationIntervalDays()
	_ = nilReq.GetMaxUsageCount()
	_ = nilReq.GetExpiresAt()
	_ = nilReq.GetMetadata()
	_ = nilReq.GetAuthorizedSubjects()
	_ = nilReq.GetAuthorizedResources()
	_ = nilReq.GetProviderConfig()
}

// TestProto_CreateKeyResponseGetters exercises CreateKeyResponse getter methods.
func TestProto_CreateKeyResponseGetters(t *testing.T) {
	resp := &CreateKeyResponse{
		Key:       &Key{KeyId: "k1"},
		Timestamp: timestamppb.Now(),
	}

	_ = resp.GetKey()
	_ = resp.GetTimestamp()
	_ = resp.String()
	_ = resp.ProtoReflect()
	resp.ProtoMessage()
	_, _ = resp.Descriptor()
	resp.Reset()

	var nilResp *CreateKeyResponse
	_ = nilResp.GetKey()
	_ = nilResp.GetTimestamp()
}

// TestProto_GetKeyRequestGetters exercises GetKeyRequest getter methods.
func TestProto_GetKeyRequestGetters(t *testing.T) {
	req := &GetKeyRequest{
		KeyId:            "key-123",
		IncludePublicKey: true,
	}

	_ = req.GetKeyId()
	_ = req.GetIncludePublicKey()
	_ = req.String()
	_ = req.ProtoReflect()
	req.ProtoMessage()
	_, _ = req.Descriptor()
	req.Reset()

	var nilReq *GetKeyRequest
	_ = nilReq.GetKeyId()
	_ = nilReq.GetIncludePublicKey()
}

// TestProto_GetKeyResponseGetters exercises GetKeyResponse getter methods.
func TestProto_GetKeyResponseGetters(t *testing.T) {
	resp := &GetKeyResponse{
		Key:       &Key{KeyId: "k1"},
		Timestamp: timestamppb.Now(),
	}

	_ = resp.GetKey()
	_ = resp.GetTimestamp()
	_ = resp.String()
	_ = resp.ProtoReflect()
	resp.ProtoMessage()
	_, _ = resp.Descriptor()
	resp.Reset()

	var nilResp *GetKeyResponse
	_ = nilResp.GetKey()
	_ = nilResp.GetTimestamp()
}

// TestProto_ListKeysRequestGetters exercises ListKeysRequest getter methods.
func TestProto_ListKeysRequestGetters(t *testing.T) {
	req := &ListKeysRequest{
		SubjectFilter:      "sub1",
		ResourceFilter:     "res1",
		ProviderTypeFilter: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE,
		StatusFilter:       KeyStatus_KEY_STATUS_ACTIVE,
		PageSize:           10,
		PageToken:          "token123",
	}

	_ = req.GetSubjectFilter()
	_ = req.GetResourceFilter()
	_ = req.GetProviderTypeFilter()
	_ = req.GetStatusFilter()
	_ = req.GetPageSize()
	_ = req.GetPageToken()
	_ = req.String()
	_ = req.ProtoReflect()
	req.ProtoMessage()
	_, _ = req.Descriptor()
	req.Reset()

	var nilReq *ListKeysRequest
	_ = nilReq.GetSubjectFilter()
	_ = nilReq.GetResourceFilter()
	_ = nilReq.GetProviderTypeFilter()
	_ = nilReq.GetStatusFilter()
	_ = nilReq.GetPageSize()
	_ = nilReq.GetPageToken()
}

// TestProto_ListKeysResponseGetters exercises ListKeysResponse getter methods.
func TestProto_ListKeysResponseGetters(t *testing.T) {
	resp := &ListKeysResponse{
		Keys:          []*Key{{KeyId: "k1"}, {KeyId: "k2"}},
		NextPageToken: "next-token",
		TotalCount:    2,
		Timestamp:     timestamppb.Now(),
	}

	_ = resp.GetKeys()
	_ = resp.GetNextPageToken()
	_ = resp.GetTotalCount()
	_ = resp.GetTimestamp()
	_ = resp.String()
	_ = resp.ProtoReflect()
	resp.ProtoMessage()
	_, _ = resp.Descriptor()
	resp.Reset()

	var nilResp *ListKeysResponse
	_ = nilResp.GetKeys()
	_ = nilResp.GetNextPageToken()
	_ = nilResp.GetTotalCount()
	_ = nilResp.GetTimestamp()
}

// TestProto_DeleteKeyRequestGetters exercises DeleteKeyRequest getter methods.
func TestProto_DeleteKeyRequestGetters(t *testing.T) {
	req := &DeleteKeyRequest{
		KeyId: "key-to-delete",
		Force: true,
	}

	_ = req.GetKeyId()
	_ = req.GetForce()
	_ = req.String()
	_ = req.ProtoReflect()
	req.ProtoMessage()
	_, _ = req.Descriptor()
	req.Reset()

	var nilReq *DeleteKeyRequest
	_ = nilReq.GetKeyId()
	_ = nilReq.GetForce()
}

// TestProto_DeleteKeyResponseGetters exercises DeleteKeyResponse getter methods.
func TestProto_DeleteKeyResponseGetters(t *testing.T) {
	resp := &DeleteKeyResponse{
		Success:   true,
		Message:   "key deleted",
		Timestamp: timestamppb.Now(),
	}

	_ = resp.GetSuccess()
	_ = resp.GetMessage()
	_ = resp.GetTimestamp()
	_ = resp.String()
	_ = resp.ProtoReflect()
	resp.ProtoMessage()
	_, _ = resp.Descriptor()
	resp.Reset()

	var nilResp *DeleteKeyResponse
	_ = nilResp.GetSuccess()
	_ = nilResp.GetMessage()
	_ = nilResp.GetTimestamp()
}

// TestProto_RotateKeyRequestGetters exercises RotateKeyRequest getter methods.
func TestProto_RotateKeyRequestGetters(t *testing.T) {
	req := &RotateKeyRequest{
		KeyId:       "key-to-rotate",
		Force:       true,
		EffectiveAt: timestamppb.Now(),
	}

	_ = req.GetKeyId()
	_ = req.GetForce()
	_ = req.GetEffectiveAt()
	_ = req.String()
	_ = req.ProtoReflect()
	req.ProtoMessage()
	_, _ = req.Descriptor()
	req.Reset()

	var nilReq *RotateKeyRequest
	_ = nilReq.GetKeyId()
	_ = nilReq.GetForce()
	_ = nilReq.GetEffectiveAt()
}

// TestProto_RotateKeyResponseGetters exercises RotateKeyResponse getter methods.
func TestProto_RotateKeyResponseGetters(t *testing.T) {
	resp := &RotateKeyResponse{
		OldKey:    &Key{KeyId: "old-key"},
		NewKey:    &Key{KeyId: "new-key"},
		Timestamp: timestamppb.Now(),
	}

	_ = resp.GetOldKey()
	_ = resp.GetNewKey()
	_ = resp.GetTimestamp()
	_ = resp.String()
	_ = resp.ProtoReflect()
	resp.ProtoMessage()
	_, _ = resp.Descriptor()
	resp.Reset()

	var nilResp *RotateKeyResponse
	_ = nilResp.GetOldKey()
	_ = nilResp.GetNewKey()
	_ = nilResp.GetTimestamp()
}

// TestProto_UnwrapDEKRequestGetters exercises UnwrapDEKRequest getter methods.
func TestProto_UnwrapDEKRequestGetters(t *testing.T) {
	req := &UnwrapDEKRequest{
		Subject:      "user@example.com",
		Resource:     "/docs/secret.pdf",
		EncryptedDek: []byte{0x01, 0x02, 0x03},
		KeyId:        "service-key-1",
		ClientKeyId:  "client-key-1",
		Context:      map[string]string{"purpose": "decrypt"},
		Action:       "read",
	}

	_ = req.GetSubject()
	_ = req.GetResource()
	_ = req.GetEncryptedDek()
	_ = req.GetKeyId()
	_ = req.GetClientKeyId()
	_ = req.GetContext()
	_ = req.GetAction()
	_ = req.String()
	_ = req.ProtoReflect()
	req.ProtoMessage()
	_, _ = req.Descriptor()
	req.Reset()

	var nilReq *UnwrapDEKRequest
	_ = nilReq.GetSubject()
	_ = nilReq.GetResource()
	_ = nilReq.GetEncryptedDek()
	_ = nilReq.GetKeyId()
	_ = nilReq.GetClientKeyId()
	_ = nilReq.GetContext()
	_ = nilReq.GetAction()
}

// TestProto_UnwrapDEKResponseGetters exercises UnwrapDEKResponse getter methods.
func TestProto_UnwrapDEKResponseGetters(t *testing.T) {
	resp := &UnwrapDEKResponse{
		EncryptedDekForSubject: []byte{0x04, 0x05, 0x06},
		SubjectKeyId:           "subject-key-1",
		AccessGranted:          true,
		AccessReason:           "Policy allows access",
		AppliedRules:           []string{"rule-1", "rule-2"},
		Timestamp:              timestamppb.Now(),
	}

	_ = resp.GetEncryptedDekForSubject()
	_ = resp.GetSubjectKeyId()
	_ = resp.GetAccessGranted()
	_ = resp.GetAccessReason()
	_ = resp.GetAppliedRules()
	_ = resp.GetTimestamp()
	_ = resp.String()
	_ = resp.ProtoReflect()
	resp.ProtoMessage()
	_, _ = resp.Descriptor()
	resp.Reset()

	var nilResp *UnwrapDEKResponse
	_ = nilResp.GetEncryptedDekForSubject()
	_ = nilResp.GetSubjectKeyId()
	_ = nilResp.GetAccessGranted()
	_ = nilResp.GetAccessReason()
	_ = nilResp.GetAppliedRules()
	_ = nilResp.GetTimestamp()
}

// TestProto_ListProvidersRequestGetters exercises ListProvidersRequest getter methods.
func TestProto_ListProvidersRequestGetters(t *testing.T) {
	req := &ListProvidersRequest{
		AvailableOnly: true,
	}

	_ = req.GetAvailableOnly()
	_ = req.String()
	_ = req.ProtoReflect()
	req.ProtoMessage()
	_, _ = req.Descriptor()
	req.Reset()

	var nilReq *ListProvidersRequest
	_ = nilReq.GetAvailableOnly()
}

// TestProto_ListProvidersResponseGetters exercises ListProvidersResponse getter methods.
func TestProto_ListProvidersResponseGetters(t *testing.T) {
	resp := &ListProvidersResponse{
		Providers: []*KeyProvider{
			{Name: "software", Type: KeyProviderType_KEY_PROVIDER_TYPE_SOFTWARE},
		},
		Timestamp: timestamppb.Now(),
	}

	_ = resp.GetProviders()
	_ = resp.GetTimestamp()
	_ = resp.String()
	_ = resp.ProtoReflect()
	resp.ProtoMessage()
	_, _ = resp.Descriptor()
	resp.Reset()

	var nilResp *ListProvidersResponse
	_ = nilResp.GetProviders()
	_ = nilResp.GetTimestamp()
}

// TestProto_GetProviderInfoRequestGetters exercises GetProviderInfoRequest getter methods.
func TestProto_GetProviderInfoRequestGetters(t *testing.T) {
	req := &GetProviderInfoRequest{
		ProviderType: KeyProviderType_KEY_PROVIDER_TYPE_HSM,
	}

	_ = req.GetProviderType()
	_ = req.String()
	_ = req.ProtoReflect()
	req.ProtoMessage()
	_, _ = req.Descriptor()
	req.Reset()

	var nilReq *GetProviderInfoRequest
	_ = nilReq.GetProviderType()
}

// TestProto_GetProviderInfoResponseGetters exercises GetProviderInfoResponse getter methods.
func TestProto_GetProviderInfoResponseGetters(t *testing.T) {
	resp := &GetProviderInfoResponse{
		Provider:  &KeyProvider{Name: "hsm"},
		Timestamp: timestamppb.Now(),
	}

	_ = resp.GetProvider()
	_ = resp.GetTimestamp()
	_ = resp.String()
	_ = resp.ProtoReflect()
	resp.ProtoMessage()
	_, _ = resp.Descriptor()
	resp.Reset()

	var nilResp *GetProviderInfoResponse
	_ = nilResp.GetProvider()
	_ = nilResp.GetTimestamp()
}

// TestProto_RegisterClientKeyRequestGetters exercises RegisterClientKeyRequest getter methods.
func TestProto_RegisterClientKeyRequestGetters(t *testing.T) {
	req := &RegisterClientKeyRequest{
		ClientId:     "client-abc",
		PublicKeyPem: "-----BEGIN PUBLIC KEY-----",
		KeyType:      KeyType_KEY_TYPE_RSA_2048,
		ExpiresAt:    timestamppb.Now(),
		Metadata:     map[string]string{"purpose": "encryption"},
	}

	_ = req.GetClientId()
	_ = req.GetPublicKeyPem()
	_ = req.GetKeyType()
	_ = req.GetExpiresAt()
	_ = req.GetMetadata()
	_ = req.String()
	_ = req.ProtoReflect()
	req.ProtoMessage()
	_, _ = req.Descriptor()
	req.Reset()

	var nilReq *RegisterClientKeyRequest
	_ = nilReq.GetClientId()
	_ = nilReq.GetPublicKeyPem()
	_ = nilReq.GetKeyType()
	_ = nilReq.GetExpiresAt()
	_ = nilReq.GetMetadata()
}

// TestProto_RegisterClientKeyResponseGetters exercises RegisterClientKeyResponse getter methods.
func TestProto_RegisterClientKeyResponseGetters(t *testing.T) {
	resp := &RegisterClientKeyResponse{
		Key:          &Key{KeyId: "k1"},
		Success:      true,
		ErrorMessage: "",
		Timestamp:    timestamppb.Now(),
	}

	_ = resp.GetKey()
	_ = resp.GetSuccess()
	_ = resp.GetErrorMessage()
	_ = resp.GetTimestamp()
	_ = resp.String()
	_ = resp.ProtoReflect()
	resp.ProtoMessage()
	_, _ = resp.Descriptor()
	resp.Reset()

	var nilResp *RegisterClientKeyResponse
	_ = nilResp.GetKey()
	_ = nilResp.GetSuccess()
	_ = nilResp.GetErrorMessage()
	_ = nilResp.GetTimestamp()
}

// TestProto_GetClientKeyRequestGetters exercises GetClientKeyRequest getter methods.
func TestProto_GetClientKeyRequestGetters(t *testing.T) {
	req := &GetClientKeyRequest{
		ClientId: "client-abc",
		KeyId:    "key-456",
	}

	_ = req.GetClientId()
	_ = req.GetKeyId()
	_ = req.String()
	_ = req.ProtoReflect()
	req.ProtoMessage()
	_, _ = req.Descriptor()
	req.Reset()

	var nilReq *GetClientKeyRequest
	_ = nilReq.GetClientId()
	_ = nilReq.GetKeyId()
}

// TestProto_GetClientKeyResponseGetters exercises GetClientKeyResponse getter methods.
func TestProto_GetClientKeyResponseGetters(t *testing.T) {
	resp := &GetClientKeyResponse{
		Key:          &Key{KeyId: "k1"},
		Found:        true,
		ErrorMessage: "",
		Timestamp:    timestamppb.Now(),
	}

	_ = resp.GetKey()
	_ = resp.GetFound()
	_ = resp.GetErrorMessage()
	_ = resp.GetTimestamp()
	_ = resp.String()
	_ = resp.ProtoReflect()
	resp.ProtoMessage()
	_, _ = resp.Descriptor()
	resp.Reset()

	var nilResp *GetClientKeyResponse
	_ = nilResp.GetKey()
	_ = nilResp.GetFound()
	_ = nilResp.GetErrorMessage()
	_ = nilResp.GetTimestamp()
}

// TestProto_ListClientKeysRequestGetters exercises ListClientKeysRequest getter methods.
func TestProto_ListClientKeysRequestGetters(t *testing.T) {
	req := &ListClientKeysRequest{
		ClientId:       "client-abc",
		PageSize:       20,
		PageToken:      "page-token-1",
		IncludeRevoked: true,
	}

	_ = req.GetClientId()
	_ = req.GetPageSize()
	_ = req.GetPageToken()
	_ = req.GetIncludeRevoked()
	_ = req.String()
	_ = req.ProtoReflect()
	req.ProtoMessage()
	_, _ = req.Descriptor()
	req.Reset()

	var nilReq *ListClientKeysRequest
	_ = nilReq.GetClientId()
	_ = nilReq.GetPageSize()
	_ = nilReq.GetPageToken()
	_ = nilReq.GetIncludeRevoked()
}

// TestProto_ListClientKeysResponseGetters exercises ListClientKeysResponse getter methods.
func TestProto_ListClientKeysResponseGetters(t *testing.T) {
	resp := &ListClientKeysResponse{
		Keys:          []*Key{{KeyId: "k1"}},
		NextPageToken: "next-page",
		TotalCount:    1,
		Timestamp:     timestamppb.Now(),
	}

	_ = resp.GetKeys()
	_ = resp.GetNextPageToken()
	_ = resp.GetTotalCount()
	_ = resp.GetTimestamp()
	_ = resp.String()
	_ = resp.ProtoReflect()
	resp.ProtoMessage()
	_, _ = resp.Descriptor()
	resp.Reset()

	var nilResp *ListClientKeysResponse
	_ = nilResp.GetKeys()
	_ = nilResp.GetNextPageToken()
	_ = nilResp.GetTotalCount()
	_ = nilResp.GetTimestamp()
}

// TestProto_RevokeClientKeyRequestGetters exercises RevokeClientKeyRequest getter methods.
func TestProto_RevokeClientKeyRequestGetters(t *testing.T) {
	req := &RevokeClientKeyRequest{
		ClientId: "client-abc",
		KeyId:    "key-to-revoke",
		Reason:   "compromised",
	}

	_ = req.GetClientId()
	_ = req.GetKeyId()
	_ = req.GetReason()
	_ = req.String()
	_ = req.ProtoReflect()
	req.ProtoMessage()
	_, _ = req.Descriptor()
	req.Reset()

	var nilReq *RevokeClientKeyRequest
	_ = nilReq.GetClientId()
	_ = nilReq.GetKeyId()
	_ = nilReq.GetReason()
}

// TestProto_RevokeClientKeyResponseGetters exercises RevokeClientKeyResponse getter methods.
func TestProto_RevokeClientKeyResponseGetters(t *testing.T) {
	resp := &RevokeClientKeyResponse{
		Success:      true,
		ErrorMessage: "",
		Timestamp:    timestamppb.Now(),
	}

	_ = resp.GetSuccess()
	_ = resp.GetErrorMessage()
	_ = resp.GetTimestamp()
	_ = resp.String()
	_ = resp.ProtoReflect()
	resp.ProtoMessage()
	_, _ = resp.Descriptor()
	resp.Reset()

	var nilResp *RevokeClientKeyResponse
	_ = nilResp.GetSuccess()
	_ = nilResp.GetErrorMessage()
	_ = nilResp.GetTimestamp()
}

// TestProto_ListClientsRequestGetters exercises ListClientsRequest getter methods.
func TestProto_ListClientsRequestGetters(t *testing.T) {
	req := &ListClientsRequest{
		PageSize:  50,
		PageToken: "token-abc",
	}

	_ = req.GetPageSize()
	_ = req.GetPageToken()
	_ = req.String()
	_ = req.ProtoReflect()
	req.ProtoMessage()
	_, _ = req.Descriptor()
	req.Reset()

	var nilReq *ListClientsRequest
	_ = nilReq.GetPageSize()
	_ = nilReq.GetPageToken()
}

// TestProto_ListClientsResponseGetters exercises ListClientsResponse getter methods.
func TestProto_ListClientsResponseGetters(t *testing.T) {
	resp := &ListClientsResponse{
		Clients:       []string{"client-1", "client-2"},
		NextPageToken: "next-page",
		TotalCount:    2,
		Timestamp:     timestamppb.Now(),
	}

	_ = resp.GetClients()
	_ = resp.GetNextPageToken()
	_ = resp.GetTotalCount()
	_ = resp.GetTimestamp()
	_ = resp.String()
	_ = resp.ProtoReflect()
	resp.ProtoMessage()
	_, _ = resp.Descriptor()
	resp.Reset()

	var nilResp *ListClientsResponse
	_ = nilResp.GetClients()
	_ = nilResp.GetNextPageToken()
	_ = nilResp.GetTotalCount()
	_ = nilResp.GetTimestamp()
}

// TestProto_RewrapClientDEKRequestGetters exercises RewrapClientDEKRequest getter methods.
func TestProto_RewrapClientDEKRequestGetters(t *testing.T) {
	req := &RewrapClientDEKRequest{
		Subject:          "user@example.com",
		ClientKeyId:      "client-key-1",
		ClientWrappedDek: []byte{0x01, 0x02},
		ServiceKeyId:     "service-key-1",
		Resource:         "/resource/path",
	}

	_ = req.GetSubject()
	_ = req.GetClientKeyId()
	_ = req.GetClientWrappedDek()
	_ = req.GetServiceKeyId()
	_ = req.GetResource()
	_ = req.String()
	_ = req.ProtoReflect()
	req.ProtoMessage()
	_, _ = req.Descriptor()
	req.Reset()

	var nilReq *RewrapClientDEKRequest
	_ = nilReq.GetSubject()
	_ = nilReq.GetClientKeyId()
	_ = nilReq.GetClientWrappedDek()
	_ = nilReq.GetServiceKeyId()
	_ = nilReq.GetResource()
}

// TestProto_RewrapClientDEKResponseGetters exercises RewrapClientDEKResponse getter methods.
func TestProto_RewrapClientDEKResponseGetters(t *testing.T) {
	resp := &RewrapClientDEKResponse{
		ServiceWrappedDek: []byte{0x07, 0x08, 0x09},
		ServiceKeyId:      "service-key-1",
		Timestamp:         timestamppb.Now(),
	}

	_ = resp.GetServiceWrappedDek()
	_ = resp.GetServiceKeyId()
	_ = resp.GetTimestamp()
	_ = resp.String()
	_ = resp.ProtoReflect()
	resp.ProtoMessage()
	_, _ = resp.Descriptor()
	resp.Reset()

	var nilResp *RewrapClientDEKResponse
	_ = nilResp.GetServiceWrappedDek()
	_ = nilResp.GetServiceKeyId()
	_ = nilResp.GetTimestamp()
}

// TestProto_FileDescriptor exercises the file descriptor to improve raw init coverage.
func TestProto_FileDescriptor(t *testing.T) {
	fd := File_proto_services_key_manager_key_manager_proto
	if fd == nil {
		t.Fatal("File_proto_services_key_manager_key_manager_proto should not be nil")
	}
}
