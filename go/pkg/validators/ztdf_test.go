package validators

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"os"
	"stratium/pkg/models"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/structpb"
)

const ztdfParserConfigPath = "../../configs/ztdf/parser.config.yaml"

func getDefaultTDO(policyData string) *models.TrustedDataObject {
	return &models.TrustedDataObject{
		Manifest: &models.Manifest{
			Assertions: []*models.Assertion{
				{
					Id:             "123abc",
					Type:           models.Assertion_HANDLING,
					Scope:          models.Assertion_TDO,
					AppliesToState: models.AppliesTo_PLAINTEXT,
					Statement: &models.Assertion_Statement{
						Format: models.Assertion_Statement_XML_STRUCTURED,
						Schema: "urn:nato:stanag:5636:A:1:elements:json",
						Value: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								"attribute": {
									Kind: &structpb.Value_StringValue{
										StringValue: "https://demo.com/attr/classification/value/secret",
									},
								},
							},
						},
					},
					Binding: &models.Assertion_AssertionBinding{
						Method:    "JWS",
						Signature: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhc3NlcnRpb25IYXNoIjoiZjIxYjc3YzE2ZDU4MzNhNGVlMjYyYTZhZTRmMDhjNTZhMTg3NDYwNGZiMGQ1NWE0M2VjYmVjMDAwZDQxMWFhOSIsImFzc2VydGlvblNpZyI6IlpUZ3laR1ExTkRjM01HWXdOVFkzTWpabU9ETXlabVpoTWpWbU1tTm1NREptTWpGaU56ZGpNVFprTlRnek0yRTBaV1V5TmpKaE5tRmxOR1l3T0dNMU5tRXhPRGMwTmpBMFptSXdaRFUxWVRRelpXTmlaV013TURCa05ERXhZV0U1In0.a6ZVmsMsAkwllb5OWnfBcyoC0WKhE-uTozG8jbKB0mw",
					},
				},
			},
			EncryptionInformation: getDefaultEncryptionInformation(policyData),
			Payload: &models.PayloadReference{
				Url:      "0.payload",
				Protocol: "zip",
			},
		},
		Payload: &models.Payload{
			Data: []byte("This is a trusted data object"),
		},
	}
}

func getDefaultEncryptionInformation(policyData string) *models.EncryptionInformation {
	return &models.EncryptionInformation{
		Type: models.EncryptionInformation_SPLIT,
		KeyAccess: []*models.EncryptionInformation_KeyAccessObject{
			getDefaultKeyAccess(),
		},
		Method: &models.EncryptionInformation_Method{
			Algorithm:    "AES-256-GCM",
			IsStreamable: true,
		},
		IntegrityInformation: getDefaultIntegrityInformation(),
		Policy:               getDefaultPolicy(policyData),
	}
}

func getDefaultKeyAccess() *models.EncryptionInformation_KeyAccessObject {
	return &models.EncryptionInformation_KeyAccessObject{
		Type:       models.EncryptionInformation_KeyAccessObject_REMOTE,
		Url:        "https://example.com/kas",
		Protocol:   models.EncryptionInformation_KeyAccessObject_KAS,
		WrappedKey: "IGz0ARqghTCkqB+/ClW0CRmWxJxd7nwJoHaHwsiw/d4CqGWKFNpTknjKOU0darqrhJ8nV8xWRn1NhNkK7Lzfz1kfqPsDRbQm37tVkAlFrgZ4cBX7U23MlCJKnvLVJLnjLrhjAhiip/hC5JcZW6ZQsD1MIvelzze7mfJsJqaJUkRZAmc2BeHEXfbsukyWK/sYWT5hUbMyNE2SFt7Eajt9crRgmK+/R8ahoDOjHYXkcXiv/G1Nppt4u6bqZ2YC3z4P165FB6TOZIQJ2Tb7JGT0PUJfD5DZLcBXKcEXR1+ln+xLPBYgijNhks/trOLtYcCyRyg4aSIPoX3k5IYTuQHz4A==",
		Sid:        "00000000-0000-0000-0000-000000000001",
		Kid:        "r1",
		PolicyBinding: &models.EncryptionInformation_KeyAccessObject_PolicyBinding{
			Alg:  "HS256",
			Hash: "ZjkwZWNhZGYyZmE5NjMwYjkwZjk2YjVkNDU4OTMxOTg3MTgxODgyZmU1MDk5MjE1MDYwODljNTkzMGJkNzljNw==",
		},
	}
}

func getDefaultIntegrityInformation() *models.EncryptionInformation_IntegrityInformation {
	return &models.EncryptionInformation_IntegrityInformation{
		RootSignature: &models.EncryptionInformation_IntegrityInformation_RootSignature{
			Alg: "HS256",
			Sig: "ZGJhZmNkNGEyNTRhZjZkMWE0ZGY0MmIzNWUwZjVjYTk5YTYxMTg3YTM2Nzk2NDBlM2E2ZDFjMDRmNjc1OGFhOA==",
		},
		SegmentHashAlg: "GMAC",
		Segments: []*models.EncryptionInformation_IntegrityInformation_Segment{
			{
				Hash:                 "ZTgyZGQ1NDc3MGYwNTY3MjZmODMyZmZhMjVmMmNmMDI=",
				SegmentSize:          15229,
				EncryptedSegmentSize: 15257,
			},
		},
		SegmentSizeDefault:          2097152,
		EncryptedSegmentSizeDefault: 2097180,
	}
}

func getDefaultPolicy(policyData string) string {
	if policyData == "" {
		policyData = `{
  "uuid": "4ee9aef2-85a0-11ef-b51f-728be6ea4bba",
  "body": {
    "dataAttributes": [
      {
		"description": null,
		"type": null,
		"attribute": "https://demo.com/attr/classification/value/secret",
		"displayName": null,
		"kasURL": "https://platform.dsp3.initech.lab/kas",
		"pubKey": null,
		"isDefault": null
      },
      {
		"description": null,
		"type": null,
		"attribute": "https://demo.com/attr/relto/value/usa",
		"displayName": null,
		"kasURL": "https://platform.dsp3.initech.lab/kas",
		"pubKey": null,
		"isDefault": null
      }
    ],
    "dissem": []
  }
}`
	}

	return base64.StdEncoding.EncodeToString([]byte(policyData))
}

func TestParse_Success(t *testing.T) {
	file, _ := os.Open(`../../test/files/tdf_1.json`)
	defer file.Close()

	data, _ := io.ReadAll(file)

	parsed, err := NewZtdfParser(ztdfParserConfigPath).Parse(data)

	assert.Nil(t, err)
	assert.NotNil(t, parsed)
}

func TestParse_Error(t *testing.T) {
	file, _ := os.Open(`../../test/files/tdf_1.json`)
	defer file.Close()

	data, _ := io.ReadAll(file)
	data = data[:len(data)-1]

	parsed, err := NewZtdfParser(ztdfParserConfigPath).Parse(data)

	assert.NotNil(t, err)
	assert.Nil(t, parsed)
}

func TestParse(t *testing.T) {
	file, _ := os.Open(`../../test/files/tdf_1.json`)
	defer file.Close()

	data, _ := io.ReadAll(file)

	manifest, err := NewZtdfParser(ztdfParserConfigPath).Parse(data)

	assert.Nil(t, err)
	assert.NotNil(t, manifest)

	ztdf := &models.TrustedDataObject{
		Manifest: manifest,
		Payload: &models.Payload{
			Data: []byte("This is a trusted data object"),
		},
	}

	assert.True(t, Validate(ztdf))
}

func TestParse_ZtdfParserConfigFile_Error(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	file, _ := os.Open(`../../test/files/tdf_1.json`)
	defer file.Close()

	parser := NewZtdfParser("bad/file/path/config.yaml")

	assert.Nil(t, parser)
	assert.Contains(t, buf.String(), "error opening config file: ")
}

func TestParse_ZtdfParserConfigDecoder_Error(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	file, _ := os.Open(`../../test/files/tdf_1.json`)
	defer file.Close()

	parser := NewZtdfParser("../../test/configs/ztdf/bad.yaml")

	assert.Nil(t, parser)
	assert.Contains(t, buf.String(), "error decoding config file: ")
}

func TestParse_ParseAssertions_BadJSON(t *testing.T) {
	parser := NewZtdfParser(ztdfParserConfigPath)

	_, err := parser.ParseAssertions([]byte(`{`))

	assert.NotNil(t, err)
	assert.Equal(t, "manifest is an invalid json format", err.Error())
}

func TestParse_ParseAssertions_NoAssertions(t *testing.T) {
	parser := NewZtdfParser(ztdfParserConfigPath)

	_, err := parser.ParseAssertions([]byte(`{"nothing": "here"}`))

	assert.NotNil(t, err)
	assert.Equal(t, "assertions field is null", err.Error())
}

func TestParseType_Handling(t *testing.T) {
	parser := NewZtdfParser(ztdfParserConfigPath)

	data := `{"id":"f85b23c7e71b43e0b7913c008f5feb6a","type":"handling","scope":"tdo","appliesToState":null,"statement":{"format":"json-structured","value":{"ocl":{"pol":"73e6da23-8b3e-44b2-b719-5f4f384dd262","cls":"SECRET","catl":[{"type":"P","name":"ReleasableTo","vals":["fvey","usa"]}],"dcr":"2024-11-14T20:37:20Z"},"context":{"@base":"urn:nato:stanag:5636:A:1:elements:json"}}},"binding":{"method":"jws","signature":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJDb25maWRlbnRpYWxpdHlJbmZvcm1hdGlvbiI6InsgXCJvY2xcIjogeyBcInBvbFwiOiBcIjczZTZkYTIzLThiM2UtNDRiMi1iNzE5LTVmNGYzODRkZDI2MlwiLCBcImNsc1wiOiBcIlNFQ1JFVFwiLCBcImNhdGxcIjogWyB7IFwidHlwZVwiOiBcIlBcIiwgXCJuYW1lXCI6IFwiUmVsZWFzYWJsZSBUb1wiLCBcInZhbHNcIjogWyBcImZ2ZXlcIiwgXCJ1c2FcIiBdIH0gXSwgXCJkY3JcIjogXCIyMDI0LTExLTE0VDIwOjM3OjIwWlwiIH0sIFwiY29udGV4dFwiOiB7IFwiQGJhc2VcIjogXCJ1cm46bmF0bzpzdGFuYWc6NTYzNjpBOjE6ZWxlbWVudHM6anNvblwiIH0gfSJ9.GauWgEbUewQYx_CdTZGUwUFN4Iq2kguURTfHdBSvSdS6I4nOLQiRtpG1JFdtZaUYW_hwICQuCp9aSneEwCRO9skS-DLg25dpAIGUn8a420wcbHlwaZ6DNTyrRAxTM1VUvcJiTV4MwNbpkSG0IbEDa1wl_krcFyPlGANj5L8QMeqarZPHvD07fJ3CFr3Zhb6IXbIlrCjPSqRYAA2AaZRekZxnyriPIQe_WBz9amGhzTcACwTkph3vz_lGOZwPZVQKDnvVzWN7ACfo_mXyGU0mVNGJVpRTpifAuTsdv_3JNh2z8ZqmfWWzsAADoh1kUnL-kRI1d144hQgU7pqnIpKvCA"}}`

	var assertionGeneric interface{}
	_ = json.Unmarshal([]byte(data), &assertionGeneric)

	parseType := parser.parseType(assertionGeneric)

	assert.Equal(t, models.Assertion_HANDLING, parseType)
}

func TestParseType_Other(t *testing.T) {
	parser := NewZtdfParser(ztdfParserConfigPath)

	data := `{"id":"f85b23c7e71b43e0b7913c008f5feb6a","type":"other","scope":"tdo","appliesToState":null,"statement":{"format":"json-structured","value":{"ocl":{"pol":"73e6da23-8b3e-44b2-b719-5f4f384dd262","cls":"SECRET","catl":[{"type":"P","name":"ReleasableTo","vals":["fvey","usa"]}],"dcr":"2024-11-14T20:37:20Z"},"context":{"@base":"urn:nato:stanag:5636:A:1:elements:json"}}},"binding":{"method":"jws","signature":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJDb25maWRlbnRpYWxpdHlJbmZvcm1hdGlvbiI6InsgXCJvY2xcIjogeyBcInBvbFwiOiBcIjczZTZkYTIzLThiM2UtNDRiMi1iNzE5LTVmNGYzODRkZDI2MlwiLCBcImNsc1wiOiBcIlNFQ1JFVFwiLCBcImNhdGxcIjogWyB7IFwidHlwZVwiOiBcIlBcIiwgXCJuYW1lXCI6IFwiUmVsZWFzYWJsZSBUb1wiLCBcInZhbHNcIjogWyBcImZ2ZXlcIiwgXCJ1c2FcIiBdIH0gXSwgXCJkY3JcIjogXCIyMDI0LTExLTE0VDIwOjM3OjIwWlwiIH0sIFwiY29udGV4dFwiOiB7IFwiQGJhc2VcIjogXCJ1cm46bmF0bzpzdGFuYWc6NTYzNjpBOjE6ZWxlbWVudHM6anNvblwiIH0gfSJ9.GauWgEbUewQYx_CdTZGUwUFN4Iq2kguURTfHdBSvSdS6I4nOLQiRtpG1JFdtZaUYW_hwICQuCp9aSneEwCRO9skS-DLg25dpAIGUn8a420wcbHlwaZ6DNTyrRAxTM1VUvcJiTV4MwNbpkSG0IbEDa1wl_krcFyPlGANj5L8QMeqarZPHvD07fJ3CFr3Zhb6IXbIlrCjPSqRYAA2AaZRekZxnyriPIQe_WBz9amGhzTcACwTkph3vz_lGOZwPZVQKDnvVzWN7ACfo_mXyGU0mVNGJVpRTpifAuTsdv_3JNh2z8ZqmfWWzsAADoh1kUnL-kRI1d144hQgU7pqnIpKvCA"}}`

	var assertionGeneric interface{}
	_ = json.Unmarshal([]byte(data), &assertionGeneric)

	parseType := parser.parseType(assertionGeneric)

	assert.Equal(t, models.Assertion_OTHER, parseType)
}

func TestParseType_Default(t *testing.T) {
	parser := NewZtdfParser(ztdfParserConfigPath)

	data := `{"id":"f85b23c7e71b43e0b7913c008f5feb6a","type":"handled","scope":"tdo","appliesToState":null,"statement":{"format":"json-structured","value":{"ocl":{"pol":"73e6da23-8b3e-44b2-b719-5f4f384dd262","cls":"SECRET","catl":[{"type":"P","name":"ReleasableTo","vals":["fvey","usa"]}],"dcr":"2024-11-14T20:37:20Z"},"context":{"@base":"urn:nato:stanag:5636:A:1:elements:json"}}},"binding":{"method":"jws","signature":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJDb25maWRlbnRpYWxpdHlJbmZvcm1hdGlvbiI6InsgXCJvY2xcIjogeyBcInBvbFwiOiBcIjczZTZkYTIzLThiM2UtNDRiMi1iNzE5LTVmNGYzODRkZDI2MlwiLCBcImNsc1wiOiBcIlNFQ1JFVFwiLCBcImNhdGxcIjogWyB7IFwidHlwZVwiOiBcIlBcIiwgXCJuYW1lXCI6IFwiUmVsZWFzYWJsZSBUb1wiLCBcInZhbHNcIjogWyBcImZ2ZXlcIiwgXCJ1c2FcIiBdIH0gXSwgXCJkY3JcIjogXCIyMDI0LTExLTE0VDIwOjM3OjIwWlwiIH0sIFwiY29udGV4dFwiOiB7IFwiQGJhc2VcIjogXCJ1cm46bmF0bzpzdGFuYWc6NTYzNjpBOjE6ZWxlbWVudHM6anNvblwiIH0gfSJ9.GauWgEbUewQYx_CdTZGUwUFN4Iq2kguURTfHdBSvSdS6I4nOLQiRtpG1JFdtZaUYW_hwICQuCp9aSneEwCRO9skS-DLg25dpAIGUn8a420wcbHlwaZ6DNTyrRAxTM1VUvcJiTV4MwNbpkSG0IbEDa1wl_krcFyPlGANj5L8QMeqarZPHvD07fJ3CFr3Zhb6IXbIlrCjPSqRYAA2AaZRekZxnyriPIQe_WBz9amGhzTcACwTkph3vz_lGOZwPZVQKDnvVzWN7ACfo_mXyGU0mVNGJVpRTpifAuTsdv_3JNh2z8ZqmfWWzsAADoh1kUnL-kRI1d144hQgU7pqnIpKvCA"}}`

	var assertionGeneric interface{}
	_ = json.Unmarshal([]byte(data), &assertionGeneric)

	parseType := parser.parseType(assertionGeneric)

	assert.Equal(t, models.Assertion_OTHER, parseType)
}

func TestParseScope_Tdo(t *testing.T) {
	parser := NewZtdfParser(ztdfParserConfigPath)

	data := `{"id":"f85b23c7e71b43e0b7913c008f5feb6a","type":"handling","scope":"tdo","appliesToState":null,"statement":{"format":"json-structured","value":{"ocl":{"pol":"73e6da23-8b3e-44b2-b719-5f4f384dd262","cls":"SECRET","catl":[{"type":"P","name":"ReleasableTo","vals":["fvey","usa"]}],"dcr":"2024-11-14T20:37:20Z"},"context":{"@base":"urn:nato:stanag:5636:A:1:elements:json"}}},"binding":{"method":"jws","signature":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJDb25maWRlbnRpYWxpdHlJbmZvcm1hdGlvbiI6InsgXCJvY2xcIjogeyBcInBvbFwiOiBcIjczZTZkYTIzLThiM2UtNDRiMi1iNzE5LTVmNGYzODRkZDI2MlwiLCBcImNsc1wiOiBcIlNFQ1JFVFwiLCBcImNhdGxcIjogWyB7IFwidHlwZVwiOiBcIlBcIiwgXCJuYW1lXCI6IFwiUmVsZWFzYWJsZSBUb1wiLCBcInZhbHNcIjogWyBcImZ2ZXlcIiwgXCJ1c2FcIiBdIH0gXSwgXCJkY3JcIjogXCIyMDI0LTExLTE0VDIwOjM3OjIwWlwiIH0sIFwiY29udGV4dFwiOiB7IFwiQGJhc2VcIjogXCJ1cm46bmF0bzpzdGFuYWc6NTYzNjpBOjE6ZWxlbWVudHM6anNvblwiIH0gfSJ9.GauWgEbUewQYx_CdTZGUwUFN4Iq2kguURTfHdBSvSdS6I4nOLQiRtpG1JFdtZaUYW_hwICQuCp9aSneEwCRO9skS-DLg25dpAIGUn8a420wcbHlwaZ6DNTyrRAxTM1VUvcJiTV4MwNbpkSG0IbEDa1wl_krcFyPlGANj5L8QMeqarZPHvD07fJ3CFr3Zhb6IXbIlrCjPSqRYAA2AaZRekZxnyriPIQe_WBz9amGhzTcACwTkph3vz_lGOZwPZVQKDnvVzWN7ACfo_mXyGU0mVNGJVpRTpifAuTsdv_3JNh2z8ZqmfWWzsAADoh1kUnL-kRI1d144hQgU7pqnIpKvCA"}}`

	var assertionGeneric interface{}
	_ = json.Unmarshal([]byte(data), &assertionGeneric)

	parseScope := parser.parseScope(assertionGeneric)

	assert.Equal(t, models.Assertion_TDO, parseScope)
}

func TestParseScope_Payload(t *testing.T) {
	parser := NewZtdfParser(ztdfParserConfigPath)

	data := `{"id":"f85b23c7e71b43e0b7913c008f5feb6a","type":"handling","scope":"payload","appliesToState":null,"statement":{"format":"json-structured","value":{"ocl":{"pol":"73e6da23-8b3e-44b2-b719-5f4f384dd262","cls":"SECRET","catl":[{"type":"P","name":"ReleasableTo","vals":["fvey","usa"]}],"dcr":"2024-11-14T20:37:20Z"},"context":{"@base":"urn:nato:stanag:5636:A:1:elements:json"}}},"binding":{"method":"jws","signature":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJDb25maWRlbnRpYWxpdHlJbmZvcm1hdGlvbiI6InsgXCJvY2xcIjogeyBcInBvbFwiOiBcIjczZTZkYTIzLThiM2UtNDRiMi1iNzE5LTVmNGYzODRkZDI2MlwiLCBcImNsc1wiOiBcIlNFQ1JFVFwiLCBcImNhdGxcIjogWyB7IFwidHlwZVwiOiBcIlBcIiwgXCJuYW1lXCI6IFwiUmVsZWFzYWJsZSBUb1wiLCBcInZhbHNcIjogWyBcImZ2ZXlcIiwgXCJ1c2FcIiBdIH0gXSwgXCJkY3JcIjogXCIyMDI0LTExLTE0VDIwOjM3OjIwWlwiIH0sIFwiY29udGV4dFwiOiB7IFwiQGJhc2VcIjogXCJ1cm46bmF0bzpzdGFuYWc6NTYzNjpBOjE6ZWxlbWVudHM6anNvblwiIH0gfSJ9.GauWgEbUewQYx_CdTZGUwUFN4Iq2kguURTfHdBSvSdS6I4nOLQiRtpG1JFdtZaUYW_hwICQuCp9aSneEwCRO9skS-DLg25dpAIGUn8a420wcbHlwaZ6DNTyrRAxTM1VUvcJiTV4MwNbpkSG0IbEDa1wl_krcFyPlGANj5L8QMeqarZPHvD07fJ3CFr3Zhb6IXbIlrCjPSqRYAA2AaZRekZxnyriPIQe_WBz9amGhzTcACwTkph3vz_lGOZwPZVQKDnvVzWN7ACfo_mXyGU0mVNGJVpRTpifAuTsdv_3JNh2z8ZqmfWWzsAADoh1kUnL-kRI1d144hQgU7pqnIpKvCA"}}`

	var assertionGeneric interface{}
	_ = json.Unmarshal([]byte(data), &assertionGeneric)

	parseScope := parser.parseScope(assertionGeneric)

	assert.Equal(t, models.Assertion_PAYLOAD, parseScope)
}

func TestParseScope_Default(t *testing.T) {
	parser := NewZtdfParser(ztdfParserConfigPath)

	data := `{"id":"f85b23c7e71b43e0b7913c008f5feb6a","type":"handling","scope":"trusteddataobject","appliesToState":null,"statement":{"format":"json-structured","value":{"ocl":{"pol":"73e6da23-8b3e-44b2-b719-5f4f384dd262","cls":"SECRET","catl":[{"type":"P","name":"ReleasableTo","vals":["fvey","usa"]}],"dcr":"2024-11-14T20:37:20Z"},"context":{"@base":"urn:nato:stanag:5636:A:1:elements:json"}}},"binding":{"method":"jws","signature":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJDb25maWRlbnRpYWxpdHlJbmZvcm1hdGlvbiI6InsgXCJvY2xcIjogeyBcInBvbFwiOiBcIjczZTZkYTIzLThiM2UtNDRiMi1iNzE5LTVmNGYzODRkZDI2MlwiLCBcImNsc1wiOiBcIlNFQ1JFVFwiLCBcImNhdGxcIjogWyB7IFwidHlwZVwiOiBcIlBcIiwgXCJuYW1lXCI6IFwiUmVsZWFzYWJsZSBUb1wiLCBcInZhbHNcIjogWyBcImZ2ZXlcIiwgXCJ1c2FcIiBdIH0gXSwgXCJkY3JcIjogXCIyMDI0LTExLTE0VDIwOjM3OjIwWlwiIH0sIFwiY29udGV4dFwiOiB7IFwiQGJhc2VcIjogXCJ1cm46bmF0bzpzdGFuYWc6NTYzNjpBOjE6ZWxlbWVudHM6anNvblwiIH0gfSJ9.GauWgEbUewQYx_CdTZGUwUFN4Iq2kguURTfHdBSvSdS6I4nOLQiRtpG1JFdtZaUYW_hwICQuCp9aSneEwCRO9skS-DLg25dpAIGUn8a420wcbHlwaZ6DNTyrRAxTM1VUvcJiTV4MwNbpkSG0IbEDa1wl_krcFyPlGANj5L8QMeqarZPHvD07fJ3CFr3Zhb6IXbIlrCjPSqRYAA2AaZRekZxnyriPIQe_WBz9amGhzTcACwTkph3vz_lGOZwPZVQKDnvVzWN7ACfo_mXyGU0mVNGJVpRTpifAuTsdv_3JNh2z8ZqmfWWzsAADoh1kUnL-kRI1d144hQgU7pqnIpKvCA"}}`

	var assertionGeneric interface{}
	_ = json.Unmarshal([]byte(data), &assertionGeneric)

	parseScope := parser.parseScope(assertionGeneric)

	assert.Equal(t, models.Assertion_PAYLOAD, parseScope)
}

func TestParseAppliesToState_Encrypted(t *testing.T) {
	parser := NewZtdfParser(ztdfParserConfigPath)

	data := `{"id":"f85b23c7e71b43e0b7913c008f5feb6a","type":"handling","scope":"tdo","appliesToState":"encrypted","statement":{"format":"json-structured","value":{"ocl":{"pol":"73e6da23-8b3e-44b2-b719-5f4f384dd262","cls":"SECRET","catl":[{"type":"P","name":"ReleasableTo","vals":["fvey","usa"]}],"dcr":"2024-11-14T20:37:20Z"},"context":{"@base":"urn:nato:stanag:5636:A:1:elements:json"}}},"binding":{"method":"jws","signature":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJDb25maWRlbnRpYWxpdHlJbmZvcm1hdGlvbiI6InsgXCJvY2xcIjogeyBcInBvbFwiOiBcIjczZTZkYTIzLThiM2UtNDRiMi1iNzE5LTVmNGYzODRkZDI2MlwiLCBcImNsc1wiOiBcIlNFQ1JFVFwiLCBcImNhdGxcIjogWyB7IFwidHlwZVwiOiBcIlBcIiwgXCJuYW1lXCI6IFwiUmVsZWFzYWJsZSBUb1wiLCBcInZhbHNcIjogWyBcImZ2ZXlcIiwgXCJ1c2FcIiBdIH0gXSwgXCJkY3JcIjogXCIyMDI0LTExLTE0VDIwOjM3OjIwWlwiIH0sIFwiY29udGV4dFwiOiB7IFwiQGJhc2VcIjogXCJ1cm46bmF0bzpzdGFuYWc6NTYzNjpBOjE6ZWxlbWVudHM6anNvblwiIH0gfSJ9.GauWgEbUewQYx_CdTZGUwUFN4Iq2kguURTfHdBSvSdS6I4nOLQiRtpG1JFdtZaUYW_hwICQuCp9aSneEwCRO9skS-DLg25dpAIGUn8a420wcbHlwaZ6DNTyrRAxTM1VUvcJiTV4MwNbpkSG0IbEDa1wl_krcFyPlGANj5L8QMeqarZPHvD07fJ3CFr3Zhb6IXbIlrCjPSqRYAA2AaZRekZxnyriPIQe_WBz9amGhzTcACwTkph3vz_lGOZwPZVQKDnvVzWN7ACfo_mXyGU0mVNGJVpRTpifAuTsdv_3JNh2z8ZqmfWWzsAADoh1kUnL-kRI1d144hQgU7pqnIpKvCA"}}`

	var assertionGeneric interface{}
	_ = json.Unmarshal([]byte(data), &assertionGeneric)

	parseAppliesTo := parser.parseAppliesToState(assertionGeneric)

	assert.Equal(t, models.AppliesTo_CIPHERTEXT, parseAppliesTo)
}

func TestParseAppliesToState_Unencrypted(t *testing.T) {
	parser := NewZtdfParser(ztdfParserConfigPath)

	data := `{"id":"f85b23c7e71b43e0b7913c008f5feb6a","type":"handling","scope":"tdo","appliesToState":"unencrypted","statement":{"format":"json-structured","value":{"ocl":{"pol":"73e6da23-8b3e-44b2-b719-5f4f384dd262","cls":"SECRET","catl":[{"type":"P","name":"ReleasableTo","vals":["fvey","usa"]}],"dcr":"2024-11-14T20:37:20Z"},"context":{"@base":"urn:nato:stanag:5636:A:1:elements:json"}}},"binding":{"method":"jws","signature":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJDb25maWRlbnRpYWxpdHlJbmZvcm1hdGlvbiI6InsgXCJvY2xcIjogeyBcInBvbFwiOiBcIjczZTZkYTIzLThiM2UtNDRiMi1iNzE5LTVmNGYzODRkZDI2MlwiLCBcImNsc1wiOiBcIlNFQ1JFVFwiLCBcImNhdGxcIjogWyB7IFwidHlwZVwiOiBcIlBcIiwgXCJuYW1lXCI6IFwiUmVsZWFzYWJsZSBUb1wiLCBcInZhbHNcIjogWyBcImZ2ZXlcIiwgXCJ1c2FcIiBdIH0gXSwgXCJkY3JcIjogXCIyMDI0LTExLTE0VDIwOjM3OjIwWlwiIH0sIFwiY29udGV4dFwiOiB7IFwiQGJhc2VcIjogXCJ1cm46bmF0bzpzdGFuYWc6NTYzNjpBOjE6ZWxlbWVudHM6anNvblwiIH0gfSJ9.GauWgEbUewQYx_CdTZGUwUFN4Iq2kguURTfHdBSvSdS6I4nOLQiRtpG1JFdtZaUYW_hwICQuCp9aSneEwCRO9skS-DLg25dpAIGUn8a420wcbHlwaZ6DNTyrRAxTM1VUvcJiTV4MwNbpkSG0IbEDa1wl_krcFyPlGANj5L8QMeqarZPHvD07fJ3CFr3Zhb6IXbIlrCjPSqRYAA2AaZRekZxnyriPIQe_WBz9amGhzTcACwTkph3vz_lGOZwPZVQKDnvVzWN7ACfo_mXyGU0mVNGJVpRTpifAuTsdv_3JNh2z8ZqmfWWzsAADoh1kUnL-kRI1d144hQgU7pqnIpKvCA"}}`

	var assertionGeneric interface{}
	_ = json.Unmarshal([]byte(data), &assertionGeneric)

	parseAppliesTo := parser.parseAppliesToState(assertionGeneric)

	assert.Equal(t, models.AppliesTo_PLAINTEXT, parseAppliesTo)
}

func TestParseAppliesToState_Default(t *testing.T) {
	parser := NewZtdfParser(ztdfParserConfigPath)

	data := `{"id":"f85b23c7e71b43e0b7913c008f5feb6a","type":"handling","scope":"tdo","appliesToState":"ciphertext","statement":{"format":"json-structured","value":{"ocl":{"pol":"73e6da23-8b3e-44b2-b719-5f4f384dd262","cls":"SECRET","catl":[{"type":"P","name":"ReleasableTo","vals":["fvey","usa"]}],"dcr":"2024-11-14T20:37:20Z"},"context":{"@base":"urn:nato:stanag:5636:A:1:elements:json"}}},"binding":{"method":"jws","signature":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJDb25maWRlbnRpYWxpdHlJbmZvcm1hdGlvbiI6InsgXCJvY2xcIjogeyBcInBvbFwiOiBcIjczZTZkYTIzLThiM2UtNDRiMi1iNzE5LTVmNGYzODRkZDI2MlwiLCBcImNsc1wiOiBcIlNFQ1JFVFwiLCBcImNhdGxcIjogWyB7IFwidHlwZVwiOiBcIlBcIiwgXCJuYW1lXCI6IFwiUmVsZWFzYWJsZSBUb1wiLCBcInZhbHNcIjogWyBcImZ2ZXlcIiwgXCJ1c2FcIiBdIH0gXSwgXCJkY3JcIjogXCIyMDI0LTExLTE0VDIwOjM3OjIwWlwiIH0sIFwiY29udGV4dFwiOiB7IFwiQGJhc2VcIjogXCJ1cm46bmF0bzpzdGFuYWc6NTYzNjpBOjE6ZWxlbWVudHM6anNvblwiIH0gfSJ9.GauWgEbUewQYx_CdTZGUwUFN4Iq2kguURTfHdBSvSdS6I4nOLQiRtpG1JFdtZaUYW_hwICQuCp9aSneEwCRO9skS-DLg25dpAIGUn8a420wcbHlwaZ6DNTyrRAxTM1VUvcJiTV4MwNbpkSG0IbEDa1wl_krcFyPlGANj5L8QMeqarZPHvD07fJ3CFr3Zhb6IXbIlrCjPSqRYAA2AaZRekZxnyriPIQe_WBz9amGhzTcACwTkph3vz_lGOZwPZVQKDnvVzWN7ACfo_mXyGU0mVNGJVpRTpifAuTsdv_3JNh2z8ZqmfWWzsAADoh1kUnL-kRI1d144hQgU7pqnIpKvCA"}}`

	var assertionGeneric interface{}
	_ = json.Unmarshal([]byte(data), &assertionGeneric)

	parseAppliesTo := parser.parseAppliesToState(assertionGeneric)

	assert.Equal(t, models.AppliesTo_PLAINTEXT, parseAppliesTo)
}

func TestParseStatement_JSON_Structured(t *testing.T) {
	parser := NewZtdfParser(ztdfParserConfigPath)

	data := `{"id":"f85b23c7e71b43e0b7913c008f5feb6a","type":"handling","scope":"tdo","appliesToState":"encrypted","statement":{"format":"json-structured","value":{"ocl":{"pol":"73e6da23-8b3e-44b2-b719-5f4f384dd262","cls":"SECRET","catl":[{"type":"P","name":"ReleasableTo","vals":["fvey","usa"]}],"dcr":"2024-11-14T20:37:20Z"},"context":{"@base":"urn:nato:stanag:5636:A:1:elements:json"}}},"binding":{"method":"jws","signature":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJDb25maWRlbnRpYWxpdHlJbmZvcm1hdGlvbiI6InsgXCJvY2xcIjogeyBcInBvbFwiOiBcIjczZTZkYTIzLThiM2UtNDRiMi1iNzE5LTVmNGYzODRkZDI2MlwiLCBcImNsc1wiOiBcIlNFQ1JFVFwiLCBcImNhdGxcIjogWyB7IFwidHlwZVwiOiBcIlBcIiwgXCJuYW1lXCI6IFwiUmVsZWFzYWJsZSBUb1wiLCBcInZhbHNcIjogWyBcImZ2ZXlcIiwgXCJ1c2FcIiBdIH0gXSwgXCJkY3JcIjogXCIyMDI0LTExLTE0VDIwOjM3OjIwWlwiIH0sIFwiY29udGV4dFwiOiB7IFwiQGJhc2VcIjogXCJ1cm46bmF0bzpzdGFuYWc6NTYzNjpBOjE6ZWxlbWVudHM6anNvblwiIH0gfSJ9.GauWgEbUewQYx_CdTZGUwUFN4Iq2kguURTfHdBSvSdS6I4nOLQiRtpG1JFdtZaUYW_hwICQuCp9aSneEwCRO9skS-DLg25dpAIGUn8a420wcbHlwaZ6DNTyrRAxTM1VUvcJiTV4MwNbpkSG0IbEDa1wl_krcFyPlGANj5L8QMeqarZPHvD07fJ3CFr3Zhb6IXbIlrCjPSqRYAA2AaZRekZxnyriPIQe_WBz9amGhzTcACwTkph3vz_lGOZwPZVQKDnvVzWN7ACfo_mXyGU0mVNGJVpRTpifAuTsdv_3JNh2z8ZqmfWWzsAADoh1kUnL-kRI1d144hQgU7pqnIpKvCA"}}`

	var assertionGeneric interface{}
	_ = json.Unmarshal([]byte(data), &assertionGeneric)

	parseStatement := parser.parseStatement(assertionGeneric.(map[string]interface{})["statement"])

	assert.Equal(t, models.Assertion_Statement_JSON_STRUCTURED, parseStatement.Format)
}

func TestParseStatement_XML_Structured(t *testing.T) {
	parser := NewZtdfParser(ztdfParserConfigPath)

	data := `{"id":"f85b23c7e71b43e0b7913c008f5feb6a","type":"handling","scope":"tdo","appliesToState":"encrypted","statement":{"format":"xml-structured","value":{"ocl":{"pol":"73e6da23-8b3e-44b2-b719-5f4f384dd262","cls":"SECRET","catl":[{"type":"P","name":"ReleasableTo","vals":["fvey","usa"]}],"dcr":"2024-11-14T20:37:20Z"},"context":{"@base":"urn:nato:stanag:5636:A:1:elements:json"}}},"binding":{"method":"jws","signature":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJDb25maWRlbnRpYWxpdHlJbmZvcm1hdGlvbiI6InsgXCJvY2xcIjogeyBcInBvbFwiOiBcIjczZTZkYTIzLThiM2UtNDRiMi1iNzE5LTVmNGYzODRkZDI2MlwiLCBcImNsc1wiOiBcIlNFQ1JFVFwiLCBcImNhdGxcIjogWyB7IFwidHlwZVwiOiBcIlBcIiwgXCJuYW1lXCI6IFwiUmVsZWFzYWJsZSBUb1wiLCBcInZhbHNcIjogWyBcImZ2ZXlcIiwgXCJ1c2FcIiBdIH0gXSwgXCJkY3JcIjogXCIyMDI0LTExLTE0VDIwOjM3OjIwWlwiIH0sIFwiY29udGV4dFwiOiB7IFwiQGJhc2VcIjogXCJ1cm46bmF0bzpzdGFuYWc6NTYzNjpBOjE6ZWxlbWVudHM6anNvblwiIH0gfSJ9.GauWgEbUewQYx_CdTZGUwUFN4Iq2kguURTfHdBSvSdS6I4nOLQiRtpG1JFdtZaUYW_hwICQuCp9aSneEwCRO9skS-DLg25dpAIGUn8a420wcbHlwaZ6DNTyrRAxTM1VUvcJiTV4MwNbpkSG0IbEDa1wl_krcFyPlGANj5L8QMeqarZPHvD07fJ3CFr3Zhb6IXbIlrCjPSqRYAA2AaZRekZxnyriPIQe_WBz9amGhzTcACwTkph3vz_lGOZwPZVQKDnvVzWN7ACfo_mXyGU0mVNGJVpRTpifAuTsdv_3JNh2z8ZqmfWWzsAADoh1kUnL-kRI1d144hQgU7pqnIpKvCA"}}`

	var assertionGeneric interface{}
	_ = json.Unmarshal([]byte(data), &assertionGeneric)

	parseStatement := parser.parseStatement(assertionGeneric.(map[string]interface{})["statement"])

	assert.Equal(t, models.Assertion_Statement_XML_STRUCTURED, parseStatement.Format)
}

func TestParseStatement_Base64Binary(t *testing.T) {
	parser := NewZtdfParser(ztdfParserConfigPath)

	data := `{"id":"f85b23c7e71b43e0b7913c008f5feb6a","type":"handling","scope":"tdo","appliesToState":"encrypted","statement":{"format":"base64binary","value":{"ocl":{"pol":"73e6da23-8b3e-44b2-b719-5f4f384dd262","cls":"SECRET","catl":[{"type":"P","name":"ReleasableTo","vals":["fvey","usa"]}],"dcr":"2024-11-14T20:37:20Z"},"context":{"@base":"urn:nato:stanag:5636:A:1:elements:json"}}},"binding":{"method":"jws","signature":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJDb25maWRlbnRpYWxpdHlJbmZvcm1hdGlvbiI6InsgXCJvY2xcIjogeyBcInBvbFwiOiBcIjczZTZkYTIzLThiM2UtNDRiMi1iNzE5LTVmNGYzODRkZDI2MlwiLCBcImNsc1wiOiBcIlNFQ1JFVFwiLCBcImNhdGxcIjogWyB7IFwidHlwZVwiOiBcIlBcIiwgXCJuYW1lXCI6IFwiUmVsZWFzYWJsZSBUb1wiLCBcInZhbHNcIjogWyBcImZ2ZXlcIiwgXCJ1c2FcIiBdIH0gXSwgXCJkY3JcIjogXCIyMDI0LTExLTE0VDIwOjM3OjIwWlwiIH0sIFwiY29udGV4dFwiOiB7IFwiQGJhc2VcIjogXCJ1cm46bmF0bzpzdGFuYWc6NTYzNjpBOjE6ZWxlbWVudHM6anNvblwiIH0gfSJ9.GauWgEbUewQYx_CdTZGUwUFN4Iq2kguURTfHdBSvSdS6I4nOLQiRtpG1JFdtZaUYW_hwICQuCp9aSneEwCRO9skS-DLg25dpAIGUn8a420wcbHlwaZ6DNTyrRAxTM1VUvcJiTV4MwNbpkSG0IbEDa1wl_krcFyPlGANj5L8QMeqarZPHvD07fJ3CFr3Zhb6IXbIlrCjPSqRYAA2AaZRekZxnyriPIQe_WBz9amGhzTcACwTkph3vz_lGOZwPZVQKDnvVzWN7ACfo_mXyGU0mVNGJVpRTpifAuTsdv_3JNh2z8ZqmfWWzsAADoh1kUnL-kRI1d144hQgU7pqnIpKvCA"}}`

	var assertionGeneric interface{}
	_ = json.Unmarshal([]byte(data), &assertionGeneric)

	parseStatement := parser.parseStatement(assertionGeneric.(map[string]interface{})["statement"])

	assert.Equal(t, models.Assertion_Statement_BASE_64_BINARY, parseStatement.Format)
}

func TestParseStatement_String(t *testing.T) {
	parser := NewZtdfParser(ztdfParserConfigPath)

	data := `{"id":"f85b23c7e71b43e0b7913c008f5feb6a","type":"handling","scope":"tdo","appliesToState":"encrypted","statement":{"format":"string","value":{"ocl":{"pol":"73e6da23-8b3e-44b2-b719-5f4f384dd262","cls":"SECRET","catl":[{"type":"P","name":"ReleasableTo","vals":["fvey","usa"]}],"dcr":"2024-11-14T20:37:20Z"},"context":{"@base":"urn:nato:stanag:5636:A:1:elements:json"}}},"binding":{"method":"jws","signature":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJDb25maWRlbnRpYWxpdHlJbmZvcm1hdGlvbiI6InsgXCJvY2xcIjogeyBcInBvbFwiOiBcIjczZTZkYTIzLThiM2UtNDRiMi1iNzE5LTVmNGYzODRkZDI2MlwiLCBcImNsc1wiOiBcIlNFQ1JFVFwiLCBcImNhdGxcIjogWyB7IFwidHlwZVwiOiBcIlBcIiwgXCJuYW1lXCI6IFwiUmVsZWFzYWJsZSBUb1wiLCBcInZhbHNcIjogWyBcImZ2ZXlcIiwgXCJ1c2FcIiBdIH0gXSwgXCJkY3JcIjogXCIyMDI0LTExLTE0VDIwOjM3OjIwWlwiIH0sIFwiY29udGV4dFwiOiB7IFwiQGJhc2VcIjogXCJ1cm46bmF0bzpzdGFuYWc6NTYzNjpBOjE6ZWxlbWVudHM6anNvblwiIH0gfSJ9.GauWgEbUewQYx_CdTZGUwUFN4Iq2kguURTfHdBSvSdS6I4nOLQiRtpG1JFdtZaUYW_hwICQuCp9aSneEwCRO9skS-DLg25dpAIGUn8a420wcbHlwaZ6DNTyrRAxTM1VUvcJiTV4MwNbpkSG0IbEDa1wl_krcFyPlGANj5L8QMeqarZPHvD07fJ3CFr3Zhb6IXbIlrCjPSqRYAA2AaZRekZxnyriPIQe_WBz9amGhzTcACwTkph3vz_lGOZwPZVQKDnvVzWN7ACfo_mXyGU0mVNGJVpRTpifAuTsdv_3JNh2z8ZqmfWWzsAADoh1kUnL-kRI1d144hQgU7pqnIpKvCA"}}`

	var assertionGeneric interface{}
	_ = json.Unmarshal([]byte(data), &assertionGeneric)

	parseStatement := parser.parseStatement(assertionGeneric.(map[string]interface{})["statement"])

	assert.Equal(t, models.Assertion_Statement_STRING, parseStatement.Format)
}

func TestValidate(t *testing.T) {
	tdo := getDefaultTDO("")

	validated := Validate(tdo)

	assert.True(t, validated)
}

func TestValidate_Manifest_Nil(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest = nil

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_Manifest_Empty(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest = &models.Manifest{}

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_Payload_Nil(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Payload = nil

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_Payload_Empty(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Payload = &models.Payload{}

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_Assertions_Nil(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.Assertions = nil

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_Assertions_Empty(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.Assertions = []*models.Assertion{}

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_HandlingAssertions_Nil(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.Assertions = nil

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_HandlingAssertions_Empty(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.Assertions = []*models.Assertion{}

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_HandlingAssertions_BadAssertionScope(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.Assertions[0].Scope = models.Assertion_PAYLOAD

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_Assertion_Id_EmptyString(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.Assertions[0].Id = ""

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_Assertion_Statement_Nil(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.Assertions[0].Statement = nil

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_Assertion_Statement_Empty(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.Assertions[0].Statement = &models.Assertion_Statement{}

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_Assertion_StatementValue_Nil(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.Assertions[0].Statement.Value = nil

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_Assertion_StatementValue_Empty(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.Assertions[0].Statement.Value = &structpb.Struct{}

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_Assertion_AssertionBinding_Nil(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.Assertions[0].Binding = nil

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_Assertion_AssertionBinding_Empty(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.Assertions[0].Binding = &models.Assertion_AssertionBinding{}

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_Assertion_AssertionBindingMethod_EmptyString(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.Assertions[0].Binding.Method = ""

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_Assertion_AssertionBindingSignature_EmptyString(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.Assertions[0].Binding.Signature = ""

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_EncryptionInformation_Nil(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation = nil

	validated := Validate(tdo)

	assert.True(t, validated)
}

func TestValidate_EncryptionInformation_Empty(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation = &models.EncryptionInformation{}

	validated := Validate(tdo)

	assert.True(t, validated)
}

func TestValidate_EncryptionInformation_KeyAccess_Nil(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation.KeyAccess = nil

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_EncryptionInformation_KeyAccess_EmptyArray(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation.KeyAccess = []*models.EncryptionInformation_KeyAccessObject{}

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_EncryptionInformation_KeyAccessUrl_EmptyString(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation.KeyAccess[0].Url = ""

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_EncryptionInformation_KeyAccessWrappedKey_EmptyString(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation.KeyAccess[0].WrappedKey = ""

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_EncryptionInformation_KeyAccessPolicyBinding_Nil(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation.KeyAccess[0].PolicyBinding = nil

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_EncryptionInformation_KeyAccessPolicyBinding_Empty(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation.KeyAccess[0].PolicyBinding = &models.EncryptionInformation_KeyAccessObject_PolicyBinding{}

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_EncryptionInformation_KeyAccessPolicyBindingAlg_EmptyString(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation.KeyAccess[0].PolicyBinding.Alg = ""

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_EncryptionInformation_KeyAccessPolicyBindingHash_EmptyString(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation.KeyAccess[0].PolicyBinding.Hash = ""

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_EncryptionInformation_Method_Nil(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation.Method = nil

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_EncryptionInformation_Method_Empty(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation.Method = &models.EncryptionInformation_Method{}

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_EncryptionInformation_MethodAlgorithm_EmptyString(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation.Method.Algorithm = ""

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_EncryptionInformation_IntegrityInformation_Nil(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation.IntegrityInformation = nil

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_EncryptionInformation_IntegrityInformation_Empty(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation.IntegrityInformation = &models.EncryptionInformation_IntegrityInformation{}

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_EncryptionInformation_IntegrityInformationSegments_Nil(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation.IntegrityInformation.Segments = nil

	validated := Validate(tdo)

	assert.True(t, validated)
}

func TestValidate_EncryptionInformation_IntegrityInformationSegments_Empty(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation.IntegrityInformation.Segments = []*models.EncryptionInformation_IntegrityInformation_Segment{}

	validated := Validate(tdo)

	assert.True(t, validated)
}

func TestValidate_EncryptionInformation_IntegrityInformationSegment_Hash_EmptyString(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation.IntegrityInformation.Segments[0].Hash = ""

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_EncryptionInformation_IntegrityInformationSegment_SegmentSize_Zero(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation.IntegrityInformation.Segments[0].SegmentSize = 0

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_EncryptionInformation_IntegrityInformationSegment_EncryptedSegmentSize_Zero(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation.IntegrityInformation.Segments[0].EncryptedSegmentSize = 0

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_EncryptionInformation_IntegrityInformationRootSignature_Nil(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation.IntegrityInformation.RootSignature = nil

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_EncryptionInformation_IntegrityInformationRootSignature_Empty(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation.IntegrityInformation.RootSignature = &models.EncryptionInformation_IntegrityInformation_RootSignature{}

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_EncryptionInformation_IntegrityInformationRootSignatureAlg_EmptyString(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation.IntegrityInformation.RootSignature.Alg = ""

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_EncryptionInformation_IntegrityInformationRootSignatureSig_EmptyString(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation.IntegrityInformation.RootSignature.Sig = ""

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_EncryptionInformation_IntegrityInformationSegmentHashAlg_EmptyString(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation.IntegrityInformation.SegmentHashAlg = ""

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_EncryptionInformation_IntegrityInformationSegmentSizeDefault_Zero(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation.IntegrityInformation.SegmentSizeDefault = 0

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_EncryptionInformation_IntegrityInformationEncryptedSegmentSizeDefault_Zero(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation.IntegrityInformation.EncryptedSegmentSizeDefault = 0

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_EncryptionInformation_Policy_EmptyString(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation.Policy = ""

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_EncryptionInformation_Policy_DecodingError(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation.Policy = "not_base64"

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_EncryptionInformation_Policy_UnmarshallingError(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation.Policy = base64.StdEncoding.EncodeToString([]byte(`{`))

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_EncryptionInformation_PolicyUuid_EmptyString(t *testing.T) {
	policyData := `{
  "uuid": "",
  "body": {
    "dataAttributes": [
      {
        "attribute": "https://demo.com/attr/classification/value/secret",
        "displayName": "",
        "isDefault": false,
        "pubKey": "",
        "kasURL": ""
      },
      {
        "attribute": "https://demo.com/attr/relto/value/usa",
        "displayName": "",
        "isDefault": false,
        "pubKey": "",
        "kasURL": ""
      }
    ],
    "dissem": []
  }
}`

	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation.Policy = getDefaultPolicy(policyData)

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_EncryptionInformation_PolicyBody_Nil(t *testing.T) {
	policyData := `{
  "uuid": "4ee9aef2-85a0-11ef-b51f-728be6ea4bba",
  "body": null
}`

	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation.Policy = getDefaultPolicy(policyData)

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_EncryptionInformation_PolicyBody_Empty(t *testing.T) {
	policyData := `{
  "uuid": "4ee9aef2-85a0-11ef-b51f-728be6ea4bba",
  "body": {}
}`

	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation.Policy = getDefaultPolicy(policyData)

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_PayloadReference_Nil(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.Payload = nil

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_PayloadReference_Empty(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.Payload = &models.PayloadReference{}

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_PayloadReference_Url_EmptyString(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.Payload.Url = ""

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_PayloadReference_Protocol_EmptyString(t *testing.T) {
	tdo := getDefaultTDO("")
	tdo.Manifest.Payload.Protocol = ""

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_DataAttributes_Attribute_EmptyString(t *testing.T) {
	policyData := `{
  "uuid": "4ee9aef2-85a0-11ef-b51f-728be6ea4bba",
  "body": {
	"dataAttributes": [
	  {
		"description": null,
		"type": null,
		"attribute": "",
		"displayName": null,
		"kasURL": "https://platform.dsp3.initech.lab/kas",
		"pubKey": null,
		"isDefault": null
	  },
	  {
		"description": null,
		"type": null,
		"attribute": "https://demo.com/attr/classification/value/secret",
		"displayName": null,
		"kasURL": "https://platform.dsp3.initech.lab/kas",
		"pubKey": null,
		"isDefault": null
	  }
	],
	"dissem": []
  }
}`

	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation.Policy = getDefaultPolicy(policyData)

	validated := Validate(tdo)

	assert.False(t, validated)
}

func TestValidate_DataAttributes_KasUrl_EmptyString(t *testing.T) {
	policyData := `{
  "uuid": "4ee9aef2-85a0-11ef-b51f-728be6ea4bba",
  "body": {
	"dataAttributes": [
	  {
		"description": null,
		"type": null,
		"attribute": "https://demo.com/attr/nationality/value/usa",
		"displayName": null,
		"kasURL": "",
		"pubKey": null,
		"isDefault": null
	  },
	  {
		"description": null,
		"type": null,
		"attribute": "https://demo.com/attr/classification/value/secret",
		"displayName": null,
		"kasURL": "https://platform.dsp3.initech.lab/kas",
		"pubKey": null,
		"isDefault": null
	  }
	],
	"dissem": []
  }
}`

	tdo := getDefaultTDO("")
	tdo.Manifest.EncryptionInformation.Policy = getDefaultPolicy(policyData)

	validated := Validate(tdo)

	assert.False(t, validated)
}
