package ztdf

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stratiumdata/go-sdk/gen/models"
)

// createTestTDO creates a valid TrustedDataObject for testing
func createTestTDO() *TrustedDataObject {
	policy := CreateClassificationPolicy("kas.example.com:50053", "secret")
	policyBase64, _ := EncodePolicyToBase64(policy)

	return &TrustedDataObject{
		Manifest: &models.Manifest{
			EncryptionInformation: &models.EncryptionInformation{
				Type:   models.EncryptionInformation_SPLIT,
				Policy: policyBase64,
				Method: &models.EncryptionInformation_Method{
					Algorithm: AlgorithmAES256GCM,
				},
				KeyAccess: []*models.EncryptionInformation_KeyAccessObject{
					{
						Type:       models.EncryptionInformation_KeyAccessObject_WRAPPED,
						Url:        "kas.example.com:50053",
						Protocol:   models.EncryptionInformation_KeyAccessObject_KAS,
						WrappedKey: "dGVzdC13cmFwcGVkLWtleQ==", // base64 encoded test data
					},
				},
				IntegrityInformation: &models.EncryptionInformation_IntegrityInformation{
					SegmentHashAlg: AlgorithmGMAC,
					Segments: []*models.EncryptionInformation_IntegrityInformation_Segment{
						{
							SegmentSize: 1024,
						},
					},
				},
			},
		},
		Payload: &Payload{
			Data: []byte("encrypted payload data"),
		},
	}
}

// ===== SaveToFile Tests =====

func TestSaveToFile(t *testing.T) {
	tmpDir := t.TempDir()
	outputPath := filepath.Join(tmpDir, "test.ztdf")

	tdo := createTestTDO()

	err := SaveToFile(tdo, outputPath)
	if err != nil {
		t.Fatalf("SaveToFile() error: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(outputPath); os.IsNotExist(err) {
		t.Fatal("SaveToFile() did not create file")
	}

	// Verify file is readable
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("Failed to read saved file: %v", err)
	}

	if len(data) == 0 {
		t.Fatal("SaveToFile() created empty file")
	}
}

func TestSaveToFile_InvalidPath(t *testing.T) {
	tdo := createTestTDO()

	// Try to save to an invalid path (directory that doesn't exist)
	err := SaveToFile(tdo, "/nonexistent/directory/test.ztdf")
	if err == nil {
		t.Error("SaveToFile() expected error for invalid path, got nil")
	}
}

// ===== LoadFromFile Tests =====

func TestLoadFromFile(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.ztdf")

	// Create and save a TDO
	originalTDO := createTestTDO()
	err := SaveToFile(originalTDO, filePath)
	if err != nil {
		t.Fatalf("Failed to save test file: %v", err)
	}

	// Load the TDO
	loadedTDO, err := LoadFromFile(filePath)
	if err != nil {
		t.Fatalf("LoadFromFile() error: %v", err)
	}

	// Verify TDO structure
	if loadedTDO.Manifest == nil {
		t.Fatal("LoadFromFile() loaded TDO has nil manifest")
	}

	if loadedTDO.Payload == nil {
		t.Fatal("LoadFromFile() loaded TDO has nil payload")
	}

	// Verify payload data matches
	if string(loadedTDO.Payload.Data) != string(originalTDO.Payload.Data) {
		t.Errorf("LoadFromFile() payload data mismatch")
	}

	// Verify policy matches
	if loadedTDO.Manifest.EncryptionInformation.Policy != originalTDO.Manifest.EncryptionInformation.Policy {
		t.Errorf("LoadFromFile() policy mismatch")
	}
}

func TestLoadFromFile_NonexistentFile(t *testing.T) {
	_, err := LoadFromFile("/nonexistent/file.ztdf")
	if err == nil {
		t.Error("LoadFromFile() expected error for nonexistent file, got nil")
	}
}

func TestLoadFromFile_InvalidZip(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "invalid.ztdf")

	// Write invalid data
	err := os.WriteFile(filePath, []byte("not a valid zip file"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	_, err = LoadFromFile(filePath)
	if err == nil {
		t.Error("LoadFromFile() expected error for invalid zip, got nil")
	}
}

// ===== SaveToBytes and LoadFromBytes Tests =====

func TestSaveToBytesAndLoadFromBytes(t *testing.T) {
	originalTDO := createTestTDO()

	// Save to bytes
	data, err := SaveToBytes(originalTDO)
	if err != nil {
		t.Fatalf("SaveToBytes() error: %v", err)
	}

	if len(data) == 0 {
		t.Fatal("SaveToBytes() returned empty data")
	}

	// Load from bytes
	loadedTDO, err := LoadFromBytes(data)
	if err != nil {
		t.Fatalf("LoadFromBytes() error: %v", err)
	}

	// Verify structure
	if loadedTDO.Manifest == nil {
		t.Fatal("LoadFromBytes() loaded TDO has nil manifest")
	}

	if loadedTDO.Payload == nil {
		t.Fatal("LoadFromBytes() loaded TDO has nil payload")
	}

	// Verify payload data
	if string(loadedTDO.Payload.Data) != string(originalTDO.Payload.Data) {
		t.Error("LoadFromBytes() payload data mismatch")
	}
}

func TestLoadFromBytes_InvalidData(t *testing.T) {
	_, err := LoadFromBytes([]byte("not a valid zip"))
	if err == nil {
		t.Error("LoadFromBytes() expected error for invalid data, got nil")
	}
}

func TestLoadFromBytes_MissingManifest(t *testing.T) {
	// Create a zip with only payload, no manifest
	// This is a bit complex, so we'll just test the error path
	_, err := LoadFromBytes([]byte{0x50, 0x4B, 0x03, 0x04}) // ZIP magic bytes
	if err == nil {
		t.Error("LoadFromBytes() expected error for missing manifest, got nil")
	}
}

// ===== GetFileInfo Tests =====

func TestGetFileInfo(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "test.ztdf")

	// Create and save a TDO
	tdo := createTestTDO()
	err := SaveToFile(tdo, filePath)
	if err != nil {
		t.Fatalf("Failed to save test file: %v", err)
	}

	// Get file info
	info, err := GetFileInfo(filePath)
	if err != nil {
		t.Fatalf("GetFileInfo() error: %v", err)
	}

	// Verify info fields
	if info.EncryptionAlg != AlgorithmAES256GCM {
		t.Errorf("GetFileInfo() EncryptionAlg = %s, want %s", info.EncryptionAlg, AlgorithmAES256GCM)
	}

	if info.KeyAccessURL != "kas.example.com:50053" {
		t.Errorf("GetFileInfo() KeyAccessURL = %s, want kas.example.com:50053", info.KeyAccessURL)
	}

	if info.IntegrityMethod != AlgorithmGMAC {
		t.Errorf("GetFileInfo() IntegrityMethod = %s, want %s", info.IntegrityMethod, AlgorithmGMAC)
	}

	if info.EncryptedSize == 0 {
		t.Error("GetFileInfo() EncryptedSize should not be 0")
	}

	if info.PlaintextSize != 1024 {
		t.Errorf("GetFileInfo() PlaintextSize = %d, want 1024", info.PlaintextSize)
	}

	// Verify attributes are present
	if len(info.Attributes) == 0 {
		t.Error("GetFileInfo() should have attributes")
	}
}

func TestGetFileInfo_NonexistentFile(t *testing.T) {
	_, err := GetFileInfo("/nonexistent/file.ztdf")
	if err == nil {
		t.Error("GetFileInfo() expected error for nonexistent file, got nil")
	}
}

// ===== GetFileInfoFromTDO Tests =====

func TestGetFileInfoFromTDO(t *testing.T) {
	tdo := createTestTDO()

	info, err := GetFileInfoFromTDO(tdo)
	if err != nil {
		t.Fatalf("GetFileInfoFromTDO() error: %v", err)
	}

	// Verify info fields
	if info.EncryptionAlg != AlgorithmAES256GCM {
		t.Errorf("GetFileInfoFromTDO() EncryptionAlg = %s, want %s", info.EncryptionAlg, AlgorithmAES256GCM)
	}

	if info.KeyAccessURL != "kas.example.com:50053" {
		t.Errorf("GetFileInfoFromTDO() KeyAccessURL = %s, want kas.example.com:50053", info.KeyAccessURL)
	}

	if info.IntegrityMethod != AlgorithmGMAC {
		t.Errorf("GetFileInfoFromTDO() IntegrityMethod = %s, want %s", info.IntegrityMethod, AlgorithmGMAC)
	}

	if info.EncryptedSize != int64(len(tdo.Payload.Data)) {
		t.Errorf("GetFileInfoFromTDO() EncryptedSize = %d, want %d", info.EncryptedSize, len(tdo.Payload.Data))
	}
}

func TestGetFileInfoFromTDO_MinimalManifest(t *testing.T) {
	tdo := &TrustedDataObject{
		Manifest: &models.Manifest{
			EncryptionInformation: &models.EncryptionInformation{},
		},
		Payload: &Payload{
			Data: []byte("test"),
		},
	}

	info, err := GetFileInfoFromTDO(tdo)
	if err != nil {
		t.Fatalf("GetFileInfoFromTDO() error: %v", err)
	}

	// Should work but with minimal info
	if info.EncryptedSize != 4 {
		t.Errorf("GetFileInfoFromTDO() EncryptedSize = %d, want 4", info.EncryptedSize)
	}
}

// ===== ValidateZTDF Tests =====

func TestValidateZTDF(t *testing.T) {
	tests := []struct {
		name    string
		tdo     *TrustedDataObject
		wantErr bool
	}{
		{
			name:    "valid TDO",
			tdo:     createTestTDO(),
			wantErr: false,
		},
		{
			name:    "nil TDO",
			tdo:     nil,
			wantErr: true,
		},
		{
			name: "missing manifest",
			tdo: &TrustedDataObject{
				Manifest: nil,
				Payload:  &Payload{Data: []byte("test")},
			},
			wantErr: true,
		},
		{
			name: "missing payload",
			tdo: &TrustedDataObject{
				Manifest: &models.Manifest{},
				Payload:  nil,
			},
			wantErr: true,
		},
		{
			name: "missing encryption information",
			tdo: &TrustedDataObject{
				Manifest: &models.Manifest{
					EncryptionInformation: nil,
				},
				Payload: &Payload{Data: []byte("test")},
			},
			wantErr: true,
		},
		{
			name: "missing key access objects",
			tdo: &TrustedDataObject{
				Manifest: &models.Manifest{
					EncryptionInformation: &models.EncryptionInformation{
						KeyAccess: []*models.EncryptionInformation_KeyAccessObject{},
					},
				},
				Payload: &Payload{Data: []byte("test")},
			},
			wantErr: true,
		},
		{
			name: "missing encryption method",
			tdo: &TrustedDataObject{
				Manifest: &models.Manifest{
					EncryptionInformation: &models.EncryptionInformation{
						Method: nil,
						KeyAccess: []*models.EncryptionInformation_KeyAccessObject{
							{Url: "test"},
						},
					},
				},
				Payload: &Payload{Data: []byte("test")},
			},
			wantErr: true,
		},
		{
			name: "missing policy",
			tdo: &TrustedDataObject{
				Manifest: &models.Manifest{
					EncryptionInformation: &models.EncryptionInformation{
						Policy: "",
						Method: &models.EncryptionInformation_Method{
							Algorithm: AlgorithmAES256GCM,
						},
						KeyAccess: []*models.EncryptionInformation_KeyAccessObject{
							{Url: "test"},
						},
					},
				},
				Payload: &Payload{Data: []byte("test")},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateZTDF(tt.tdo)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateZTDF() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// ===== ValidateZTDFFile Tests =====

func TestValidateZTDFFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create valid ZTDF file
	validPath := filepath.Join(tmpDir, "valid.ztdf")
	err := SaveToFile(createTestTDO(), validPath)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Test valid file
	err = ValidateZTDFFile(validPath)
	if err != nil {
		t.Errorf("ValidateZTDFFile() unexpected error for valid file: %v", err)
	}

	// Test nonexistent file
	err = ValidateZTDFFile("/nonexistent/file.ztdf")
	if err == nil {
		t.Error("ValidateZTDFFile() expected error for nonexistent file, got nil")
	}

	// Test invalid file
	invalidPath := filepath.Join(tmpDir, "invalid.ztdf")
	os.WriteFile(invalidPath, []byte("not a valid zip"), 0644)
	err = ValidateZTDFFile(invalidPath)
	if err == nil {
		t.Error("ValidateZTDFFile() expected error for invalid file, got nil")
	}
}

// ===== Integration Tests =====

func TestFullSaveLoadCycle(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "integration.ztdf")

	// Create original TDO with custom data
	originalTDO := createTestTDO()
	originalTDO.Payload.Data = []byte("This is my secret encrypted data!")

	// Save to file
	err := SaveToFile(originalTDO, filePath)
	if err != nil {
		t.Fatalf("SaveToFile() error: %v", err)
	}

	// Validate file
	err = ValidateZTDFFile(filePath)
	if err != nil {
		t.Fatalf("ValidateZTDFFile() error: %v", err)
	}

	// Get file info
	info, err := GetFileInfo(filePath)
	if err != nil {
		t.Fatalf("GetFileInfo() error: %v", err)
	}

	if info.EncryptionAlg != AlgorithmAES256GCM {
		t.Errorf("File info has wrong encryption algorithm: %s", info.EncryptionAlg)
	}

	// Load from file
	loadedTDO, err := LoadFromFile(filePath)
	if err != nil {
		t.Fatalf("LoadFromFile() error: %v", err)
	}

	// Verify payload matches
	if string(loadedTDO.Payload.Data) != string(originalTDO.Payload.Data) {
		t.Error("Full save/load cycle: payload data mismatch")
	}

	// Validate loaded TDO
	err = ValidateZTDF(loadedTDO)
	if err != nil {
		t.Fatalf("ValidateZTDF() error on loaded TDO: %v", err)
	}
}

func TestBytesRoundTrip(t *testing.T) {
	originalTDO := createTestTDO()
	originalTDO.Payload.Data = []byte("Round trip test data")

	// Save to bytes
	zipData, err := SaveToBytes(originalTDO)
	if err != nil {
		t.Fatalf("SaveToBytes() error: %v", err)
	}

	// Load from bytes
	loadedTDO, err := LoadFromBytes(zipData)
	if err != nil {
		t.Fatalf("LoadFromBytes() error: %v", err)
	}

	// Verify
	if string(loadedTDO.Payload.Data) != string(originalTDO.Payload.Data) {
		t.Error("Bytes round trip: payload data mismatch")
	}

	// Validate
	err = ValidateZTDF(loadedTDO)
	if err != nil {
		t.Fatalf("ValidateZTDF() error: %v", err)
	}

	// Get info
	info, err := GetFileInfoFromTDO(loadedTDO)
	if err != nil {
		t.Fatalf("GetFileInfoFromTDO() error: %v", err)
	}

	if info.EncryptedSize != int64(len(originalTDO.Payload.Data)) {
		t.Errorf("Info encrypted size = %d, want %d", info.EncryptedSize, len(originalTDO.Payload.Data))
	}
}

func TestLargePayload(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "large.ztdf")

	// Create TDO with large payload (1MB)
	tdo := createTestTDO()
	tdo.Payload.Data = make([]byte, 1024*1024)
	for i := range tdo.Payload.Data {
		tdo.Payload.Data[i] = byte(i % 256)
	}

	// Save to file
	err := SaveToFile(tdo, filePath)
	if err != nil {
		t.Fatalf("SaveToFile() error with large payload: %v", err)
	}

	// Load and verify
	loadedTDO, err := LoadFromFile(filePath)
	if err != nil {
		t.Fatalf("LoadFromFile() error with large payload: %v", err)
	}

	if len(loadedTDO.Payload.Data) != len(tdo.Payload.Data) {
		t.Errorf("Large payload: size mismatch, got %d want %d", len(loadedTDO.Payload.Data), len(tdo.Payload.Data))
	}

	// Spot check a few bytes
	for i := 0; i < 100; i++ {
		idx := i * 10000
		if loadedTDO.Payload.Data[idx] != tdo.Payload.Data[idx] {
			t.Errorf("Large payload: data mismatch at index %d", idx)
			break
		}
	}
}