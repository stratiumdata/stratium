package key_manager

import (
	"context"
	"fmt"
	"stratium/pkg/auth"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// RegisterClientKey registers a client's public key for DEK unwrapping
func (s *Server) RegisterClientKey(ctx context.Context, req *RegisterClientKeyRequest) (*RegisterClientKeyResponse, error) {
	// Extract user claims from OIDC token
	userClaims, err := auth.GetUserFromContext(ctx)
	if err != nil {
		// For testing, try mock token validation
		return &RegisterClientKeyResponse{
			Success:      false,
			ErrorMessage: fmt.Sprintf("Authentication required: %v", err),
			Timestamp:    timestamppb.Now(),
		}, nil
	}

	logger.Info("RegisterClientKey called - User: %s, ClientID: %s", userClaims.Sub, req.ClientId)

	if userClaims.Sub == "" {
		return &RegisterClientKeyResponse{
			Success:      false,
			ErrorMessage: "User ID (sub claim) is required",
			Timestamp:    timestamppb.Now(),
		}, nil
	}

	if req.PublicKeyPem == "" {
		return &RegisterClientKeyResponse{
			Success:      false,
			ErrorMessage: "Public key PEM is required",
			Timestamp:    timestamppb.Now(),
		}, nil
	}

	keyType := req.KeyType
	if keyType == KeyType_KEY_TYPE_UNSPECIFIED {
		inferred, err := inferKeyTypeFromPEM(req.PublicKeyPem)
		if err != nil {
			return &RegisterClientKeyResponse{
				Success:      false,
				ErrorMessage: fmt.Sprintf("Unable to infer key type: %v", err),
				Timestamp:    timestamppb.Now(),
			}, nil
		}
		keyType = inferred
	} else {
		if inferred, err := inferKeyTypeFromPEM(req.PublicKeyPem); err == nil && inferred != KeyType_KEY_TYPE_UNSPECIFIED && inferred != keyType {
			logger.Warn("Key type mismatch for client %s: request=%s, inferred=%s. Using inferred type.", userClaims.Sub, keyType, inferred)
			keyType = inferred
		}
	}

	if s.fipsEnabled && !isFIPSKeyTypeAllowed(keyType) {
		return &RegisterClientKeyResponse{
			Success:      false,
			ErrorMessage: fmt.Sprintf("key type %s is not allowed in FIPS mode", keyType),
			Timestamp:    timestamppb.Now(),
		}, nil
	}

	// Generate unique key ID
	keyID := fmt.Sprintf("client-key-%s-%d", userClaims.Sub, time.Now().UnixNano())

	// Preserve metadata and capture the calling client ID for auditing
	metadata := make(map[string]string)
	for k, v := range req.Metadata {
		metadata[k] = v
	}
	if req.ClientId != "" {
		metadata["client_application_id"] = req.ClientId
	}

	// Create integrity hashes using the server's integrity manager
	keyHash := s.integrityMgr.CreateKeyIntegrityHash(req.PublicKeyPem, keyType, userClaims)

	// Create user public key record
	userKey := &Key{
		KeyId:            keyID,
		ClientId:         userClaims.Sub,
		PublicKeyPem:     req.PublicKeyPem,
		KeyType:          keyType,
		Status:           KeyStatus_KEY_STATUS_ACTIVE,
		CreatedAt:        timestamppb.Now(),
		ExpiresAt:        req.ExpiresAt,
		KeyIntegrityHash: keyHash,
		Metadata:         metadata,
	}

	// Register the key
	err = s.clientKeyStore.RegisterKey(ctx, userKey)
	if err != nil {
		logger.Error("failed to register client key: %v", err)
		return &RegisterClientKeyResponse{
			Success:      false,
			ErrorMessage: fmt.Sprintf("Failed to register key: %v", err),
			Timestamp:    timestamppb.Now(),
		}, nil
	}

	logger.Info("Registered client key %s for user %s", keyID, userClaims.Sub)

	return &RegisterClientKeyResponse{
		Key:       userKey,
		Success:   true,
		Timestamp: timestamppb.Now(),
	}, nil
}

// GetClientKey retrieves a specific client key
func (s *Server) GetClientKey(ctx context.Context, req *GetClientKeyRequest) (*GetClientKeyResponse, error) {
	// Extract user claims from OIDC token
	userClaims, err := auth.GetUserFromContext(ctx)
	if err != nil {
		// For testing, try mock token validation
		return &GetClientKeyResponse{
			Found:        false,
			ErrorMessage: fmt.Sprintf("Authentication required: %v", err),
			Timestamp:    timestamppb.Now(),
		}, nil
	}

	logger.Info("GetClientKey called - User: %s, Requested ClientID: %s, KeyID: %s", userClaims.Sub, req.ClientId, req.KeyId)

	// Validate request
	if userClaims.Sub == "" {
		return &GetClientKeyResponse{
			Found:        false,
			ErrorMessage: "User claims are required",
			Timestamp:    timestamppb.Now(),
		}, nil
	}

	var key *Key

	// If key ID is specified, get that specific key
	if req.KeyId != "" {
		key, err = s.clientKeyStore.GetKey(ctx, req.KeyId)
		if err != nil {
			return &GetClientKeyResponse{
				Found:        false,
				ErrorMessage: fmt.Sprintf("Key not found: %v", err),
				Timestamp:    timestamppb.Now(),
			}, nil
		}

		// Verify the key belongs to the requesting user
		if key.ClientId != userClaims.Sub {
			return &GetClientKeyResponse{
				Found:        false,
				ErrorMessage: "Key does not belong to authenticated user",
				Timestamp:    timestamppb.Now(),
			}, nil
		}
	} else {
		// Get the active key for the user
		key, err = s.clientKeyStore.GetActiveKeyForClient(ctx, userClaims.Sub)
		if err != nil {
			return &GetClientKeyResponse{
				Found:        false,
				ErrorMessage: fmt.Sprintf("No active key found: %v", err),
				Timestamp:    timestamppb.Now(),
			}, nil
		}
	}

	// Verify key integrity using the server's integrity manager
	if err := s.integrityMgr.VerifyKeyIntegrity(key, userClaims); err != nil {
		logger.Error("key integrity verification failed: %v", err)
		return &GetClientKeyResponse{
			Found:        false,
			ErrorMessage: "Key integrity verification failed",
			Timestamp:    timestamppb.Now(),
		}, nil
	}

	logger.Info("Retrieved key %s for user %s", key.KeyId, userClaims.Sub)

	return &GetClientKeyResponse{
		Key:       key,
		Found:     true,
		Timestamp: timestamppb.Now(),
	}, nil
}

// ListClientKeys lists all keys for a user
func (s *Server) ListClientKeys(ctx context.Context, req *ListClientKeysRequest) (*ListClientKeysResponse, error) {
	// Extract user claims from OIDC token
	userClaims, err := auth.GetUserFromContext(ctx)
	if err != nil {
		// For testing, try mock token validation
		return &ListClientKeysResponse{
			Keys:      []*Key{},
			Timestamp: timestamppb.Now(),
		}, nil
	}

	logger.Info("ListClientKeys called - User: %s, IncludeRevoked: %t", userClaims.Sub, req.IncludeRevoked)

	// Validate request
	if userClaims == nil || userClaims.Sub == "" {
		return &ListClientKeysResponse{
			Keys:      []*Key{},
			Timestamp: timestamppb.Now(),
		}, nil
	}

	// Get keys for the user
	keys, err := s.clientKeyStore.ListKeysForClient(ctx, userClaims.Sub, req.IncludeRevoked)
	if err != nil {
		logger.Error("failed to list keys: %v", err)
		return &ListClientKeysResponse{
			Keys:      []*Key{},
			Timestamp: timestamppb.Now(),
		}, nil
	}

	// Apply pagination
	pageSize := int(req.PageSize)
	if pageSize == 0 {
		pageSize = 50 // Default page size
	}

	totalCount := len(keys)
	startIndex := 0
	// Simple pagination - in production, use proper token encoding
	if req.PageToken != "" {
		// For simplicity, using index as token
		fmt.Sscanf(req.PageToken, "%d", &startIndex)
	}

	endIndex := startIndex + pageSize
	if endIndex > totalCount {
		endIndex = totalCount
	}

	var paginatedKeys []*Key
	var nextPageToken string

	if startIndex < totalCount {
		paginatedKeys = keys[startIndex:endIndex]
		if endIndex < totalCount {
			nextPageToken = fmt.Sprintf("%d", endIndex)
		}
	}

	logger.Info("Returning %d keys for user %s (total: %d)", len(paginatedKeys), userClaims.Sub, totalCount)

	return &ListClientKeysResponse{
		Keys:          paginatedKeys,
		NextPageToken: nextPageToken,
		TotalCount:    int32(totalCount),
		Timestamp:     timestamppb.Now(),
	}, nil
}

// RevokeClientKey revokes a client key
func (s *Server) RevokeClientKey(ctx context.Context, req *RevokeClientKeyRequest) (*RevokeClientKeyResponse, error) {
	// Extract user claims from OIDC token
	userClaims, err := auth.GetUserFromContext(ctx)
	if err != nil {
		// For testing, try mock token validation
		return &RevokeClientKeyResponse{
			Success:      false,
			ErrorMessage: fmt.Sprintf("Authentication required: %v", err),
			Timestamp:    timestamppb.Now(),
		}, nil
	}

	logger.Info("RevokeClientKey called - User: %s, KeyID: %s, Reason: %s",
		userClaims.Sub, req.KeyId, req.Reason)

	// Validate request
	if userClaims == nil || userClaims.Sub == "" {
		return &RevokeClientKeyResponse{
			Success:      false,
			ErrorMessage: "User claims are required",
			Timestamp:    timestamppb.Now(),
		}, nil
	}

	if req.KeyId == "" {
		return &RevokeClientKeyResponse{
			Success:      false,
			ErrorMessage: "Key ID is required",
			Timestamp:    timestamppb.Now(),
		}, nil
	}

	// Get the key to verify ownership
	key, err := s.clientKeyStore.GetKey(ctx, req.KeyId)
	if err != nil {
		return &RevokeClientKeyResponse{
			Success:      false,
			ErrorMessage: fmt.Sprintf("Key not found: %v", err),
			Timestamp:    timestamppb.Now(),
		}, nil
	}

	// Verify the key belongs to the requesting user
	if key.ClientId != userClaims.Sub {
		return &RevokeClientKeyResponse{
			Success:      false,
			ErrorMessage: "Key does not belong to authenticated user",
			Timestamp:    timestamppb.Now(),
		}, nil
	}

	// Revoke the key
	err = s.clientKeyStore.RevokeKey(ctx, req.KeyId, req.Reason)
	if err != nil {
		logger.Error("failed to revoke key: %v", err)
		return &RevokeClientKeyResponse{
			Success:      false,
			ErrorMessage: fmt.Sprintf("Failed to revoke key: %v", err),
			Timestamp:    timestamppb.Now(),
		}, nil
	}

	logger.Info("Revoked key %s for user %s", req.KeyId, userClaims.Sub)

	return &RevokeClientKeyResponse{
		Success:   true,
		Timestamp: timestamppb.Now(),
	}, nil
}

// ListClients lists all subjects that have registered keys (admin operation)
func (s *Server) ListClients(ctx context.Context, req *ListClientsRequest) (*ListClientsResponse, error) {
	logger.Debug("ListClients called")

	// Get all clients
	clients, err := s.clientKeyStore.ListClients(ctx)
	if err != nil {
		logger.Info("Failed to list subjects: %v", err)
		return &ListClientsResponse{
			Clients:   []string{},
			Timestamp: timestamppb.Now(),
		}, nil
	}

	// Apply pagination
	pageSize := int(req.PageSize)
	if pageSize == 0 {
		pageSize = 100 // Default page size
	}

	totalCount := len(clients)
	startIndex := 0
	// Simple pagination
	if req.PageToken != "" {
		fmt.Sscanf(req.PageToken, "%d", &startIndex)
	}

	endIndex := startIndex + pageSize
	if endIndex > totalCount {
		endIndex = totalCount
	}

	var paginatedClients []string
	var nextPageToken string

	if startIndex < totalCount {
		paginatedClients = clients[startIndex:endIndex]
		if endIndex < totalCount {
			nextPageToken = fmt.Sprintf("%d", endIndex)
		}
	}

	logger.Info("Returning %d subjects (total: %d)", len(paginatedClients), totalCount)

	return &ListClientsResponse{
		Clients:       paginatedClients,
		NextPageToken: nextPageToken,
		TotalCount:    int32(totalCount),
		Timestamp:     timestamppb.Now(),
	}, nil
}
