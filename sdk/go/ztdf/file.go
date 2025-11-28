package ztdf

import (
	"archive/zip"
	"bufio"
	"bytes"
	"fmt"
	"hash/crc32"
	"io"
	"os"

	"github.com/stratiumdata/go-sdk/gen/models"
	"google.golang.org/protobuf/encoding/protojson"
)

// SaveToFile saves a ZTDF to a ZIP file.
//
// Example:
//
//	if err := ztdf.SaveToFile(tdo, "encrypted.ztdf"); err != nil {
//	    log.Fatal(err)
//	}
func SaveToFile(tdo *TrustedDataObject, outputPath string) error {
	file, err := os.Create(outputPath)
	if err != nil {
		return fmt.Errorf("failed to create zip file: %w", err)
	}
	defer file.Close()

	buffered := bufio.NewWriter(file)
	if err := writeTrustedDataObject(tdo, buffered); err != nil {
		return err
	}

	if err := buffered.Flush(); err != nil {
		return fmt.Errorf("failed to flush zip file: %w", err)
	}

	return nil
}

// LoadFromFile loads a ZTDF from a ZIP file.
//
// Example:
//
//	tdo, err := ztdf.LoadFromFile("encrypted.ztdf")
//	if err != nil {
//	    log.Fatal(err)
//	}
func LoadFromFile(zipPath string) (*TrustedDataObject, error) {
	reader, err := zip.OpenReader(zipPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open zip: %w", err)
	}
	defer reader.Close()

	tdo := &TrustedDataObject{}

	for _, file := range reader.File {
		if file.Name == ManifestFileName {
			rc, err := file.Open()
			if err != nil {
				return nil, fmt.Errorf("failed to open manifest: %w", err)
			}
			manifestData, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return nil, fmt.Errorf("failed to read manifest: %w", err)
			}

			manifest := &models.Manifest{}
			if err := protojson.Unmarshal(manifestData, manifest); err != nil {
				return nil, fmt.Errorf("failed to unmarshal manifest: %w", err)
			}
			tdo.Manifest = manifest
		} else if file.Name == PayloadFileName {
			rc, err := file.Open()
			if err != nil {
				return nil, fmt.Errorf("failed to open payload: %w", err)
			}
			payloadData, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return nil, fmt.Errorf("failed to read payload: %w", err)
			}
			tdo.Payload = &Payload{Data: payloadData}
		}
	}

	if tdo.Manifest == nil || tdo.Payload == nil {
		return nil, fmt.Errorf("incomplete ZTDF: missing manifest or payload")
	}

	return tdo, nil
}

// LoadFromBytes loads a ZTDF from byte data.
//
// Example:
//
//	tdo, err := ztdf.LoadFromBytes(zipData)
//	if err != nil {
//	    log.Fatal(err)
//	}
func LoadFromBytes(zipData []byte) (*TrustedDataObject, error) {
	reader, err := zip.NewReader(bytes.NewReader(zipData), int64(len(zipData)))
	if err != nil {
		return nil, fmt.Errorf("failed to open zip: %w", err)
	}

	tdo := &TrustedDataObject{}

	for _, file := range reader.File {
		if file.Name == ManifestFileName {
			rc, err := file.Open()
			if err != nil {
				return nil, fmt.Errorf("failed to open manifest: %w", err)
			}
			manifestData, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return nil, fmt.Errorf("failed to read manifest: %w", err)
			}

			manifest := &models.Manifest{}
			if err := protojson.Unmarshal(manifestData, manifest); err != nil {
				return nil, fmt.Errorf("failed to unmarshal manifest: %w", err)
			}
			tdo.Manifest = manifest
		} else if file.Name == PayloadFileName {
			rc, err := file.Open()
			if err != nil {
				return nil, fmt.Errorf("failed to open payload: %w", err)
			}
			payloadData, err := io.ReadAll(rc)
			rc.Close()
			if err != nil {
				return nil, fmt.Errorf("failed to read payload: %w", err)
			}
			tdo.Payload = &Payload{Data: payloadData}
		}
	}

	if tdo.Manifest == nil || tdo.Payload == nil {
		return nil, fmt.Errorf("incomplete ZTDF: missing manifest or payload")
	}

	return tdo, nil
}

// SaveToBytes saves a ZTDF to a byte slice (ZIP format).
//
// Example:
//
//	data, err := ztdf.SaveToBytes(tdo)
//	if err != nil {
//	    log.Fatal(err)
//	}
func SaveToBytes(tdo *TrustedDataObject) ([]byte, error) {
	buf := &bytes.Buffer{}
	if err := writeTrustedDataObject(tdo, buf); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeTrustedDataObject(tdo *TrustedDataObject, w io.Writer) error {
	zipWriter := zip.NewWriter(w)

	manifestJSON, err := protojson.MarshalOptions{
		Indent: "  ",
	}.Marshal(tdo.Manifest)
	if err != nil {
		zipWriter.Close()
		return fmt.Errorf("failed to marshal manifest: %w", err)
	}

	manifestHeader := &zip.FileHeader{
		Name:   ManifestFileName,
		Method: zip.Deflate,
	}
	manifestWriter, err := zipWriter.CreateHeader(manifestHeader)
	if err != nil {
		zipWriter.Close()
		return fmt.Errorf("failed to create manifest entry: %w", err)
	}
	if _, err := manifestWriter.Write(manifestJSON); err != nil {
		zipWriter.Close()
		return fmt.Errorf("failed to write manifest: %w", err)
	}

	payloadHeader := &zip.FileHeader{
		Name:   PayloadFileName,
		Method: zip.Store,
	}
	payloadHeader.UncompressedSize64 = uint64(len(tdo.Payload.Data))
	payloadHeader.CRC32 = crc32.ChecksumIEEE(tdo.Payload.Data)

	payloadWriter, err := zipWriter.CreateHeader(payloadHeader)
	if err != nil {
		zipWriter.Close()
		return fmt.Errorf("failed to create payload entry: %w", err)
	}
	if _, err := payloadWriter.Write(tdo.Payload.Data); err != nil {
		zipWriter.Close()
		return fmt.Errorf("failed to write payload: %w", err)
	}

	if err := zipWriter.Close(); err != nil {
		return fmt.Errorf("failed to close zip writer: %w", err)
	}

	return nil
}

// GetFileInfo extracts metadata about a ZTDF file without fully decrypting it.
//
// Example:
//
//	info, err := ztdf.GetFileInfo("encrypted.ztdf")
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Encryption: %s\n", info.EncryptionAlg)
//	fmt.Printf("Encrypted size: %d bytes\n", info.EncryptedSize)
func GetFileInfo(zipPath string) (*FileInfo, error) {
	tdo, err := LoadFromFile(zipPath)
	if err != nil {
		return nil, err
	}

	return GetFileInfoFromTDO(tdo)
}

// GetFileInfoFromTDO extracts metadata from a TrustedDataObject.
//
// Example:
//
//	info, err := ztdf.GetFileInfoFromTDO(tdo)
//	if err != nil {
//	    log.Fatal(err)
//	}
func GetFileInfoFromTDO(tdo *TrustedDataObject) (*FileInfo, error) {
	info := &FileInfo{
		EncryptedSize: int64(len(tdo.Payload.Data)),
	}

	if tdo.Manifest != nil && tdo.Manifest.EncryptionInformation != nil {
		encInfo := tdo.Manifest.EncryptionInformation

		if encInfo.Method != nil {
			info.EncryptionAlg = encInfo.Method.Algorithm
		}

		if len(encInfo.KeyAccess) > 0 {
			info.KeyAccessURL = encInfo.KeyAccess[0].Url
		}

		if encInfo.IntegrityInformation != nil {
			info.IntegrityMethod = encInfo.IntegrityInformation.SegmentHashAlg
			if len(encInfo.IntegrityInformation.Segments) > 0 {
				info.PlaintextSize = int64(encInfo.IntegrityInformation.Segments[0].SegmentSize)
			}
		}
	}

	// Get policy attributes
	policyInfo, err := GetPolicyInfo(tdo)
	if err == nil {
		info.Attributes = policyInfo.DataAttributes
	}

	return info, nil
}

// ValidateZTDFFile validates the structure of a ZTDF file.
//
// Example:
//
//	if err := ztdf.ValidateZTDFFile("encrypted.ztdf"); err != nil {
//	    log.Fatal("Invalid ZTDF:", err)
//	}
func ValidateZTDFFile(zipPath string) error {
	tdo, err := LoadFromFile(zipPath)
	if err != nil {
		return err
	}

	return ValidateZTDF(tdo)
}

// ValidateZTDF validates the structure and integrity of a ZTDF.
//
// Example:
//
//	if err := ztdf.ValidateZTDF(tdo); err != nil {
//	    log.Fatal("Invalid ZTDF:", err)
//	}
func ValidateZTDF(tdo *TrustedDataObject) error {
	if tdo == nil {
		return fmt.Errorf("TDO cannot be nil")
	}
	if tdo.Manifest == nil {
		return fmt.Errorf("manifest is required")
	}
	if tdo.Payload == nil {
		return fmt.Errorf("payload is required")
	}
	if tdo.Manifest.EncryptionInformation == nil {
		return fmt.Errorf("encryption information is required")
	}
	if len(tdo.Manifest.EncryptionInformation.KeyAccess) == 0 {
		return fmt.Errorf("at least one key access object is required")
	}
	if tdo.Manifest.EncryptionInformation.Method == nil {
		return fmt.Errorf("encryption method is required")
	}
	if tdo.Manifest.EncryptionInformation.Policy == "" {
		return fmt.Errorf("policy is required")
	}

	// Validate policy
	policy, err := ParsePolicyFromManifest(tdo.Manifest)
	if err != nil {
		return fmt.Errorf("invalid policy: %w", err)
	}

	return ValidatePolicy(policy)
}
