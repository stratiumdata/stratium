package validators

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"os"
	"stratium/pkg/models"

	"github.com/samber/lo"
	"google.golang.org/protobuf/encoding/protojson"
	"gopkg.in/yaml.v3"
)

type ZtdfParserConfigStatementKeys struct {
	Format string "yaml:format"
	Value  string "yaml:value"
}

type ZtdfParserConfigManifestKeys struct {
	Assertions string                        "yaml:assertions"
	Type       string                        "yaml:type"
	Scope      string                        "yaml:scope"
	State      string                        "yaml:state"
	Statement  ZtdfParserConfigStatementKeys "yaml:statement"
}

type ZtdfParserConfig struct {
	Keys ZtdfParserConfigManifestKeys "yaml:keys"
}

type ZtdfParser struct {
	Config ZtdfParserConfig
}

func NewZtdfParser(configFile string) *ZtdfParser {
	file, err := os.Open(configFile)
	if err != nil {
		log.Printf("error opening config file: %v", err)
		return nil
	}
	defer file.Close()

	var config ZtdfParserConfig
	err = yaml.NewDecoder(file).Decode(&config)
	if err != nil {
		log.Printf("error decoding config file: %v", err)
		return nil
	}

	return &ZtdfParser{
		Config: config,
	}
}

func (parser *ZtdfParser) ParseAssertions(data []byte) ([]*models.Assertion, error) {
	if !json.Valid(data) {
		return nil, errors.New("manifest is an invalid json format")
	}

	var result map[string]interface{}

	err := json.Unmarshal(data, &result)
	if err != nil {
		log.Println("error unmarshalling data:", err)
		return nil, err
	}

	assertionsJSON := result[parser.Config.Keys.Assertions]
	assertionsJSONBytes, err := json.Marshal(assertionsJSON)
	if err != nil {
		log.Println("error marshalling assertions:", err)
		return nil, err
	}

	if string(assertionsJSONBytes) == "null" {
		return nil, errors.New("assertions field is null")
	}

	var rawMessages []json.RawMessage
	err = json.Unmarshal(assertionsJSONBytes, &rawMessages)

	var assertions []*models.Assertion
	for _, rawMessage := range rawMessages {
		var assertionGeneric interface{}
		err = json.Unmarshal(rawMessage, &assertionGeneric)
		if err != nil {
			log.Println("error unmarshalling assertion:", err)
			return nil, err
		}

		assertion := &models.Assertion{}
		err = protojson.UnmarshalOptions{
			AllowPartial: true,
		}.Unmarshal(rawMessage, assertion)

		assertion.Type = parser.parseType(assertionGeneric)
		assertion.Scope = parser.parseScope(assertionGeneric)
		assertion.AppliesToState = parser.parseAppliesToState(assertionGeneric)

		assertion.Statement = parser.parseStatement(assertionGeneric.(map[string]interface{})["statement"])

		assertions = append(assertions, assertion)
	}

	return assertions, nil
}

func (parser *ZtdfParser) parseType(generic interface{}) models.Assertion_AssertionType {
	t := generic.(map[string]interface{})[parser.Config.Keys.Type]

	switch t {
	case "handling":
		return models.Assertion_HANDLING
	case "other":
		return models.Assertion_OTHER
	}

	return models.Assertion_OTHER
}

func (parser *ZtdfParser) parseScope(generic interface{}) models.Assertion_AssertionScope {
	s := generic.(map[string]interface{})[parser.Config.Keys.Scope]

	switch s {
	case "tdo":
		return models.Assertion_TDO
	case "payload":
		return models.Assertion_PAYLOAD
	}

	return models.Assertion_PAYLOAD
}

func (parser *ZtdfParser) parseAppliesToState(generic interface{}) models.AppliesTo {
	a := generic.(map[string]interface{})[parser.Config.Keys.State]

	switch a {
	case "encrypted":
		return models.AppliesTo_CIPHERTEXT
	case "unencrypted":
		return models.AppliesTo_PLAINTEXT
	}

	return models.AppliesTo_PLAINTEXT
}

func (parser *ZtdfParser) parseStatement(s interface{}) *models.Assertion_Statement {
	statement := &models.Assertion_Statement{}

	format := s.(map[string]interface{})[parser.Config.Keys.Statement.Format]

	switch format {
	case "json-structured":
		statement.Format = models.Assertion_Statement_JSON_STRUCTURED
	case "xml-structured":
		statement.Format = models.Assertion_Statement_XML_STRUCTURED
	case "base64binary":
		statement.Format = models.Assertion_Statement_BASE_64_BINARY
	case "string":
		statement.Format = models.Assertion_Statement_STRING
	}

	return statement
}

func (parser *ZtdfParser) Parse(data []byte) (*models.Manifest, error) {
	manifest := &models.Manifest{}
	err := protojson.UnmarshalOptions{
		AllowPartial:   true,
		DiscardUnknown: true,
	}.Unmarshal(data, manifest)
	if err != nil {
		log.Println("error unmarshalling data:", err)
		return nil, err
	}

	parsedAssertions, err := parser.ParseAssertions(data)

	log.Println(parsedAssertions)

	for _, assertion := range manifest.GetAssertions() {
		if assertion.GetStatement() != nil && assertion.GetStatement().GetValue() != nil {
			statementJSON, err := json.Marshal(assertion.GetStatement().GetValue().AsMap())
			if err != nil {
				log.Println("error marshalling statement value:", err)
				return nil, err
			}

			if enumAssertion, ok := lo.Find(parsedAssertions, func(parsedAssertion *models.Assertion) bool {
				return parsedAssertion.GetId() == assertion.GetId()
			}); ok {
				assertion.Type = enumAssertion.Type
				assertion.Scope = enumAssertion.Scope
				assertion.AppliesToState = enumAssertion.AppliesToState
				assertion.GetStatement().Format = enumAssertion.GetStatement().Format
			}

			assertion.GetStatement().JsonValue = string(statementJSON)
		}
	}

	return manifest, nil
}

func Validate(ztdf *models.TrustedDataObject) bool {
	if isZero(ztdf.GetManifest()) || isZero(ztdf.GetPayload()) {
		return false
	}

	return validateManifest(ztdf.GetManifest())
}

func validateManifest(manifest *models.Manifest) bool {
	if isZero(manifest.GetAssertions()) {
		return false
	}

	return validateAssertions(manifest.GetAssertions()) &&
		validateEncryptionInformation(manifest.GetEncryptionInformation()) &&
		validatePayloadReference(manifest.GetPayload())
}

func validateAssertions(assertions []*models.Assertion) bool {
	if _, ok := lo.Find(assertions, func(assertion *models.Assertion) bool {
		return assertion.Type == models.Assertion_HANDLING && assertion.GetScope() == models.Assertion_TDO
	}); !ok {
		return false
	}

	validAssertion := true

	for _, assertion := range assertions {
		validAssertion = validAssertion && validateAssertion(assertion)
	}

	return validAssertion
}

func validateAssertion(assertion *models.Assertion) bool {
	return assertion != nil &&
		assertion.GetId() != "" &&
		!isZero(assertion.GetStatement()) &&
		(!isZero(assertion.GetStatement().GetValue()) || !isZero(assertion.GetStatement().GetJsonValue())) &&
		assertion.GetBinding() != nil &&
		assertion.GetBinding().GetMethod() != "" &&
		assertion.GetBinding().GetSignature() != ""
}

func validateEncryptionInformation(encryptionInformation *models.EncryptionInformation) bool {
	if isZero(encryptionInformation) {
		return true
	}

	validKeyAccessObject := true
	for _, kao := range encryptionInformation.GetKeyAccess() {
		validKeyAccessObject = validKeyAccessObject &&
			kao != nil &&
			kao.GetUrl() != "" &&
			kao.GetWrappedKey() != "" &&
			kao.GetPolicyBinding() != nil &&
			kao.GetPolicyBinding().GetAlg() != "" &&
			kao.GetPolicyBinding().GetHash() != ""
	}

	return validKeyAccessObject &&
		len(encryptionInformation.GetKeyAccess()) > 0 &&
		encryptionInformation.GetMethod() != nil &&
		encryptionInformation.GetMethod().GetAlgorithm() != "" &&
		encryptionInformation.GetIntegrityInformation() != nil &&
		validateIntegrityInformation(encryptionInformation.GetIntegrityInformation()) &&
		encryptionInformation.GetPolicy() != "" &&
		validateEncryptionInformationPolicy(encryptionInformation.GetPolicy())
}

func validateIntegrityInformation(information *models.EncryptionInformation_IntegrityInformation) bool {
	validSegments := true
	for _, segment := range information.GetSegments() {
		validSegments = validSegments &&
			segment.GetHash() != "" &&
			segment.GetSegmentSize() > 0 &&
			segment.GetEncryptedSegmentSize() > 0
	}

	return validSegments &&
		information.GetRootSignature() != nil &&
		information.GetRootSignature().GetAlg() != "" &&
		information.GetRootSignature().GetSig() != "" &&
		information.GetSegmentHashAlg() != "" &&
		information.GetSegmentSizeDefault() > 0 &&
		information.GetEncryptedSegmentSizeDefault() > 0
}

func validateEncryptionInformationPolicy(policy string) bool {
	decodedBytes, err := base64.StdEncoding.DecodeString(policy)
	if err != nil {
		log.Println("error decoding string:", err)
		return false
	}

	policyModel := models.ZtdfPolicy{}
	err = protojson.UnmarshalOptions{
		AllowPartial:   true,
		DiscardUnknown: true,
	}.Unmarshal(decodedBytes, &policyModel)
	if err != nil {
		log.Println("error unmarshalling policy:", err)
		return false
	}

	return policyModel.GetUuid() != "" &&
		!isZero(policyModel.GetBody()) &&
		validateDataAttributes(policyModel.GetBody().GetDataAttributes())
}

func validateDataAttributes(attributes []*models.ZtdfPolicy_Body_Attribute) bool {
	validAttributes := true

	for _, attribute := range attributes {
		validAttributes = validAttributes &&
			attribute.GetAttribute() != "" &&
			attribute.GetKas_URL() != ""

		if !validAttributes {
			break
		}
	}

	return validAttributes
}

func validatePayloadReference(reference *models.PayloadReference) bool {
	if isZero(reference) {
		return false
	}

	return reference.GetUrl() != "" && reference.GetProtocol() != ""
}
