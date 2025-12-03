package key_manager

import (
	"context"
	"fmt"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
)

// DefaultKeyRotationManager implements automated key rotation
type DefaultKeyRotationManager struct {
	mu              sync.RWMutex
	keyStore        KeyStore
	providerFactory ProviderFactory
	rotationJobs    map[string]*RotationJob
	stopChan        chan struct{}
	running         bool
}

// RotationJob represents a scheduled key rotation
type RotationJob struct {
	KeyID          string
	Policy         RotationPolicy
	Interval       time.Duration
	LastRotation   time.Time
	NextRotation   time.Time
	MaxUsageCount  int64
	Enabled        bool
	RetryCount     int
	MaxRetries     int
	NotifyChannels []chan<- RotationEvent
}

// RotationEvent represents a rotation event
type RotationEvent struct {
	Type      RotationEventType
	KeyID     string
	Timestamp time.Time
	Message   string
	Error     error
	OldKey    *Key
	NewKey    *Key
}

// RotationEventType defines the type of rotation event
type RotationEventType int

const (
	RotationEventTypeScheduled RotationEventType = iota
	RotationEventTypeStarted
	RotationEventTypeCompleted
	RotationEventTypeFailed
	RotationEventTypeCancelled
)

// NewDefaultKeyRotationManager creates a new rotation manager
func NewDefaultKeyRotationManager(keyStore KeyStore, providerFactory ProviderFactory) *DefaultKeyRotationManager {
	return &DefaultKeyRotationManager{
		keyStore:        keyStore,
		providerFactory: providerFactory,
		rotationJobs:    make(map[string]*RotationJob),
		stopChan:        make(chan struct{}),
		running:         false,
	}
}

// Start begins the rotation manager
func (rm *DefaultKeyRotationManager) Start() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.running {
		return fmt.Errorf("rotation manager is already running")
	}

	rm.running = true
	go rm.rotationLoop()

	logger.Startup("Key rotation manager started")
	return nil
}

// Stop stops the rotation manager
func (rm *DefaultKeyRotationManager) Stop() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if !rm.running {
		return fmt.Errorf("rotation manager is not running")
	}

	rm.running = false
	close(rm.stopChan)

	logger.Info("Key rotation manager stopped")
	return nil
}

// ScheduleRotation schedules a key for rotation
func (rm *DefaultKeyRotationManager) ScheduleRotation(keyID string, policy RotationPolicy, interval time.Duration) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	// Check if already scheduled
	if _, exists := rm.rotationJobs[keyID]; exists {
		return fmt.Errorf("rotation already scheduled for key %s", keyID)
	}

	// Get key information
	key, err := rm.keyStore.GetKey(context.Background(), keyID)
	if err != nil {
		return fmt.Errorf("failed to get key %s: %w", keyID, err)
	}
	if key.ExternallyManaged {
		return fmt.Errorf("key %s is externally managed and cannot be scheduled for rotation", keyID)
	}

	// Calculate next rotation time
	var nextRotation time.Time
	lastRotation := key.CreatedAt.AsTime()
	if key.LastRotated != nil {
		lastRotation = key.LastRotated.AsTime()
	}

	switch policy {
	case RotationPolicy_ROTATION_POLICY_TIME_BASED:
		nextRotation = lastRotation.Add(interval)
	case RotationPolicy_ROTATION_POLICY_USAGE_BASED:
		// For usage-based, check immediately and then every hour
		nextRotation = time.Now().Add(time.Hour)
	case RotationPolicy_ROTATION_POLICY_COMBINED:
		// Use time-based scheduling, but also check usage
		nextRotation = lastRotation.Add(interval)
	case RotationPolicy_ROTATION_POLICY_MANUAL:
		// Manual policy doesn't schedule automatic rotation
		return fmt.Errorf("manual rotation policy does not support scheduling")
	default:
		return fmt.Errorf("unsupported rotation policy: %v", policy)
	}

	// Create rotation job
	job := &RotationJob{
		KeyID:          keyID,
		Policy:         policy,
		Interval:       interval,
		LastRotation:   lastRotation,
		NextRotation:   nextRotation,
		MaxUsageCount:  key.MaxUsageCount,
		Enabled:        true,
		RetryCount:     0,
		MaxRetries:     3,
		NotifyChannels: make([]chan<- RotationEvent, 0),
	}

	rm.rotationJobs[keyID] = job

	logger.Info("Scheduled rotation for key %s using policy %v, next rotation: %v",
		keyID, policy, nextRotation)

	// Send scheduled event (after releasing lock)
	event := RotationEvent{
		Type:      RotationEventTypeScheduled,
		KeyID:     keyID,
		Timestamp: time.Now(),
		Message:   fmt.Sprintf("Rotation scheduled for %v", nextRotation),
	}

	// Send event after releasing the lock to avoid deadlock
	go rm.sendRotationEvent(event)

	return nil
}

// CancelRotation cancels scheduled rotation for a key
func (rm *DefaultKeyRotationManager) CancelRotation(keyID string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	_, exists := rm.rotationJobs[keyID]
	if !exists {
		return fmt.Errorf("no rotation scheduled for key %s", keyID)
	}

	delete(rm.rotationJobs, keyID)

	logger.Info("Cancelled rotation for key %s", keyID)

	// Send cancelled event
	go rm.sendRotationEvent(RotationEvent{
		Type:      RotationEventTypeCancelled,
		KeyID:     keyID,
		Timestamp: time.Now(),
		Message:   "Rotation cancelled",
	})

	return nil
}

// CheckRotationNeeded checks if a key needs rotation
func (rm *DefaultKeyRotationManager) CheckRotationNeeded(key *Key) bool {
	rm.mu.RLock()
	job, exists := rm.rotationJobs[key.KeyId]
	rm.mu.RUnlock()

	if !exists || !job.Enabled {
		return false
	}

	now := time.Now()

	switch job.Policy {
	case RotationPolicy_ROTATION_POLICY_TIME_BASED:
		return now.After(job.NextRotation)

	case RotationPolicy_ROTATION_POLICY_USAGE_BASED:
		return key.MaxUsageCount > 0 && key.UsageCount >= key.MaxUsageCount

	case RotationPolicy_ROTATION_POLICY_COMBINED:
		timeBasedRotation := now.After(job.NextRotation)
		usageBasedRotation := key.MaxUsageCount > 0 && key.UsageCount >= key.MaxUsageCount
		return timeBasedRotation || usageBasedRotation

	default:
		return false
	}
}

// PerformRotation performs key rotation
func (rm *DefaultKeyRotationManager) PerformRotation(ctx context.Context, keyID string) (*RotateKeyResponse, error) {
	rm.mu.Lock()
	_, exists := rm.rotationJobs[keyID]
	if !exists {
		rm.mu.Unlock()
		return nil, fmt.Errorf("no rotation job found for key %s", keyID)
	}
	rm.mu.Unlock()

	logger.Info("Starting rotation for key %s", keyID)

	// Send started event
	rm.sendRotationEvent(RotationEvent{
		Type:      RotationEventTypeStarted,
		KeyID:     keyID,
		Timestamp: time.Now(),
		Message:   "Rotation started",
	})

	// Get current key
	oldKey, err := rm.keyStore.GetKey(ctx, keyID)
	if err != nil {
		rm.handleRotationError(keyID, fmt.Errorf("failed to get key: %w", err))
		return nil, err
	}
	if oldKey.ExternallyManaged {
		return nil, fmt.Errorf("key %s is externally managed and cannot be rotated", keyID)
	}
	logger.Debug("RotationManager.PerformRotation: key_id=%s old_key_status=%s usage_count=%d", keyID, oldKey.Status.String(), oldKey.UsageCount)

	// Get appropriate provider (use cached instance)
	provider, err := rm.providerFactory.GetProvider(oldKey.ProviderType)
	if err != nil {
		rm.handleRotationError(keyID, fmt.Errorf("failed to create provider: %w", err))
		return nil, err
	}

	// Perform rotation using provider
	newKeyPair, err := provider.RotateKey(ctx, keyID)
	if err != nil {
		rm.handleRotationError(keyID, fmt.Errorf("failed to rotate key: %w", err))
		return nil, err
	}

	// Convert KeyPair to Key message
	newKey := rm.keyPairToKey(newKeyPair)
	logger.Debug("RotationManager.PerformRotation: key_id=%s new_key_status=%s metadata_entries=%d", keyID, newKey.Status.String(), len(newKey.Metadata))

	// Update key in store
	logger.Debug("RotationManager.PerformRotation: updating key store entry for key_id=%s", keyID)
	err = rm.keyStore.UpdateKey(ctx, newKey)
	if err != nil {
		rm.handleRotationError(keyID, fmt.Errorf("failed to update key in store: %w", err))
		return nil, err
	}

	// Update rotation job
	rm.mu.Lock()
	if job, exists := rm.rotationJobs[keyID]; exists {
		job.LastRotation = time.Now()
		job.NextRotation = job.LastRotation.Add(job.Interval)
		job.RetryCount = 0
	}
	rm.mu.Unlock()

	logger.Info("Successfully rotated key %s", keyID)

	// Create response
	response := &RotateKeyResponse{
		OldKey:    oldKey,
		NewKey:    newKey,
		Timestamp: timestamppb.Now(),
	}

	// Send completed event
	rm.sendRotationEvent(RotationEvent{
		Type:      RotationEventTypeCompleted,
		KeyID:     keyID,
		Timestamp: time.Now(),
		Message:   "Rotation completed successfully",
		OldKey:    oldKey,
		NewKey:    newKey,
	})

	return response, nil
}

// AddNotificationChannel adds a channel to receive rotation events
func (rm *DefaultKeyRotationManager) AddNotificationChannel(keyID string, ch chan<- RotationEvent) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	job, exists := rm.rotationJobs[keyID]
	if !exists {
		return fmt.Errorf("no rotation job found for key %s", keyID)
	}

	job.NotifyChannels = append(job.NotifyChannels, ch)
	return nil
}

// rotationLoop is the main rotation checking loop
func (rm *DefaultKeyRotationManager) rotationLoop() {
	ticker := time.NewTicker(1 * time.Minute) // Check every minute
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rm.checkAndPerformRotations()
		case <-rm.stopChan:
			return
		}
	}
}

// checkAndPerformRotations checks all scheduled rotations and performs them if needed
func (rm *DefaultKeyRotationManager) checkAndPerformRotations() {
	rm.mu.RLock()
	jobsCopy := make(map[string]*RotationJob)
	for k, v := range rm.rotationJobs {
		jobsCopy[k] = v
	}
	rm.mu.RUnlock()

	for keyID, job := range jobsCopy {
		if !job.Enabled {
			continue
		}

		// Get current key state
		key, err := rm.keyStore.GetKey(context.Background(), keyID)
		if err != nil {
			logger.Info("Failed to get key %s for rotation check: %v", keyID, err)
			continue
		}
		if key.ExternallyManaged {
			logger.Info("Skipping rotation for externally managed key %s", keyID)
			continue
		}

		// Check if rotation is needed
		if rm.CheckRotationNeeded(key) {
			go func(keyID string) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
				defer cancel()

				_, err := rm.PerformRotation(ctx, keyID)
				if err != nil {
					logger.Info("Automatic rotation failed for key %s: %v", keyID, err)
				}
			}(keyID)
		}
	}
}

// handleRotationError handles rotation errors and retry logic
func (rm *DefaultKeyRotationManager) handleRotationError(keyID string, err error) {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	job, exists := rm.rotationJobs[keyID]
	if !exists {
		return
	}

	job.RetryCount++
	logger.Info("Rotation failed for key %s (attempt %d/%d): %v",
		keyID, job.RetryCount, job.MaxRetries, err)

	if job.RetryCount >= job.MaxRetries {
		job.Enabled = false
		logger.Info("Disabling rotation for key %s after %d failed attempts", keyID, job.MaxRetries)
	} else {
		// Schedule retry
		job.NextRotation = time.Now().Add(time.Duration(job.RetryCount) * time.Hour)
	}

	// Send failed event
	go rm.sendRotationEvent(RotationEvent{
		Type:      RotationEventTypeFailed,
		KeyID:     keyID,
		Timestamp: time.Now(),
		Message:   fmt.Sprintf("Rotation failed (attempt %d/%d)", job.RetryCount, job.MaxRetries),
		Error:     err,
	})
}

// sendRotationEvent sends events to notification channels
func (rm *DefaultKeyRotationManager) sendRotationEvent(event RotationEvent) {
	rm.mu.RLock()
	job, exists := rm.rotationJobs[event.KeyID]
	if !exists {
		rm.mu.RUnlock()
		return
	}

	channels := make([]chan<- RotationEvent, len(job.NotifyChannels))
	copy(channels, job.NotifyChannels)
	rm.mu.RUnlock()

	// Send to all notification channels (non-blocking)
	for _, ch := range channels {
		select {
		case ch <- event:
		default:
			// Channel is full, skip
		}
	}
}

// keyPairToKey converts a KeyPair to a Key protobuf message
func (rm *DefaultKeyRotationManager) keyPairToKey(keyPair *KeyPair) *Key {
	key := &Key{
		KeyId:         keyPair.KeyID,
		KeyType:       keyPair.KeyType,
		ProviderType:  keyPair.ProviderType,
		Status:        KeyStatus_KEY_STATUS_ACTIVE,
		PublicKeyPem:  keyPair.PublicKeyPEM,
		CreatedAt:     timestamppb.New(keyPair.CreatedAt),
		UsageCount:    keyPair.UsageCount,
		MaxUsageCount: keyPair.MaxUsageCount,
		Metadata:      keyPair.Metadata,
	}

	if keyPair.ExpiresAt != nil {
		key.ExpiresAt = timestamppb.New(*keyPair.ExpiresAt)
	}

	if keyPair.LastRotated != nil {
		key.LastRotated = timestamppb.New(*keyPair.LastRotated)
	}

	if keyPair.ExternallyManaged {
		key.ExternallyManaged = true
		key.ExternalSource = keyPair.ExternalSource
		key.ExternalManifestPath = keyPair.ExternalManifestPath
		key.PrivateKeySource = keyPair.PrivateKeySource
		if keyPair.ExternalLoadedAt != nil {
			key.ExternalLoadedAt = timestamppb.New(*keyPair.ExternalLoadedAt)
		}
	}

	return key
}

// GetRotationStatus returns the status of rotation jobs
func (rm *DefaultKeyRotationManager) GetRotationStatus() map[string]*RotationJob {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	status := make(map[string]*RotationJob)
	for k, v := range rm.rotationJobs {
		// Create a copy to avoid race conditions
		jobCopy := *v
		status[k] = &jobCopy
	}

	return status
}

// UpdateRotationJob updates an existing rotation job
func (rm *DefaultKeyRotationManager) UpdateRotationJob(keyID string, policy RotationPolicy, interval time.Duration) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	job, exists := rm.rotationJobs[keyID]
	if !exists {
		return fmt.Errorf("no rotation job found for key %s", keyID)
	}

	job.Policy = policy
	job.Interval = interval

	// Recalculate next rotation time
	switch policy {
	case RotationPolicy_ROTATION_POLICY_TIME_BASED:
		job.NextRotation = job.LastRotation.Add(interval)
	case RotationPolicy_ROTATION_POLICY_USAGE_BASED:
		job.NextRotation = time.Now().Add(time.Hour)
	case RotationPolicy_ROTATION_POLICY_COMBINED:
		job.NextRotation = job.LastRotation.Add(interval)
	}

	logger.Info("Updated rotation job for key %s, next rotation: %v", keyID, job.NextRotation)
	return nil
}
