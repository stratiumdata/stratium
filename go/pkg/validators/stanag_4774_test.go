package validators

import (
	"bytes"
	"log"
	"os"
	"stratium/pkg/models"
	"testing"

	"github.com/stretchr/testify/assert"
)

const stanag4774ParserConfigPath = "../../configs/stanag4774/parser.config.yaml"
const validatorConfigPath = "../../configs/stanag4774/value.domains.yaml"

func Test_Standard_Example1(t *testing.T) {
	parser := NewStanag4774Parser(stanag4774ParserConfigPath)
	model := parser.Parse("NATO RESTRICTED", validatorConfigPath)
	assert.NotNil(t, model)
	assert.Equal(t, "NATO", model.PolicyIdentifier)
	assert.Equal(t, models.Classification_CLASSIFICATION_RESTRICTED, model.Classification)
}

func Test_Standard_Example2(t *testing.T) {
	parser := NewStanag4774Parser(stanag4774ParserConfigPath)
	model := parser.Parse("NATO CONFIDENTIAL - STAFF", validatorConfigPath)
	assert.NotNil(t, model)
	assert.Equal(t, "NATO", model.PolicyIdentifier)
	assert.Equal(t, models.Classification_CLASSIFICATION_CONFIDENTIAL, model.Classification)
	assert.Equal(t, models.Administrative_ADMINISTRATIVE_STAFF, model.Administrative)
}

func Test_Standard_Example3(t *testing.T) {
	parser := NewStanag4774Parser(stanag4774ParserConfigPath)
	model := parser.Parse("NATO RESTRICTED Releasable To Japan, Australia, PFP", validatorConfigPath)
	assert.NotNil(t, model)
	assert.Equal(t, "NATO", model.PolicyIdentifier)
	assert.Equal(t, models.Classification_CLASSIFICATION_RESTRICTED, model.Classification)
	assert.Contains(t, model.GetReleasableTo().GetValues(), "Japan")
	assert.Contains(t, model.GetReleasableTo().GetValues(), "Australia")
	assert.Contains(t, model.GetReleasableTo().GetValues(), "PFP")
}

func Test_Standard_Example4(t *testing.T) {
	parser := NewStanag4774Parser(stanag4774ParserConfigPath)
	model := parser.Parse("NATO/KFOR CONFIDENTIAL NATO, Ireland, Ukraine Only", validatorConfigPath)
	assert.NotNil(t, model)
	assert.Equal(t, "NATO", model.PolicyIdentifier)
	assert.Equal(t, models.Classification_CLASSIFICATION_CONFIDENTIAL, model.Classification)
	assert.Contains(t, model.GetContext().GetValues(), "KFOR")
	assert.Contains(t, model.GetOnly().GetValues(), "NATO")
	assert.Contains(t, model.GetOnly().GetValues(), "Ireland")
	assert.Contains(t, model.GetOnly().GetValues(), "Ukraine")
}

func Test_Standard_Example5(t *testing.T) {
	parser := NewStanag4774Parser(stanag4774ParserConfigPath)
	model := parser.Parse("NATO SECRET Norway, United States Only Releasable To Sweden", validatorConfigPath)
	assert.NotNil(t, model)
	assert.Equal(t, "NATO", model.PolicyIdentifier)
	assert.Equal(t, models.Classification_CLASSIFICATION_SECRET, model.Classification)
	assert.Contains(t, model.GetOnly().GetValues(), "Norway")
	assert.Contains(t, model.GetOnly().GetValues(), "United States")
	assert.Contains(t, model.GetReleasableTo().GetValues(), "Sweden")
}

func Test_Standard_Example6(t *testing.T) {
	parser := NewStanag4774Parser(stanag4774ParserConfigPath)
	model := parser.Parse("NATO/EAPC CONFIDENTIAL Releasable To RESOLUTE SUPPORT", validatorConfigPath)
	assert.NotNil(t, model)
	assert.Equal(t, "NATO", model.PolicyIdentifier)
	assert.Equal(t, models.Classification_CLASSIFICATION_CONFIDENTIAL, model.Classification)
	assert.Contains(t, model.GetContext().GetValues(), "EAPC")
	assert.Contains(t, model.GetReleasableTo().GetValues(), "RESOLUTE SUPPORT")
}

func Test_Standard_Example7(t *testing.T) {
	parser := NewStanag4774Parser(stanag4774ParserConfigPath)
	model := parser.Parse("NATO RESTRICTED Releasable To European Commission, EEAS, INTEROPERABILITY PLATFORM", validatorConfigPath)
	assert.NotNil(t, model)
	assert.Equal(t, "NATO", model.PolicyIdentifier)
	assert.Equal(t, models.Classification_CLASSIFICATION_RESTRICTED, model.Classification)
	assert.Contains(t, model.GetReleasableTo().GetValues(), "European Commission")
	assert.Contains(t, model.GetReleasableTo().GetValues(), "EEAS")
	assert.Contains(t, model.GetReleasableTo().GetValues(), "INTEROPERABILITY PLATFORM")
}

func TestParse_PolicyIdentifier_Success(t *testing.T) {
	parser := NewStanag4774Parser(stanag4774ParserConfigPath)
	model := parser.Parse("NATO RESTRICTED", validatorConfigPath)
	assert.NotNil(t, model)
	assert.Equal(t, "NATO", model.PolicyIdentifier)
}

func TestParse_PolicyIdentifier_Slash_Success(t *testing.T) {
	parser := NewStanag4774Parser(stanag4774ParserConfigPath)
	model := parser.Parse("NATO/KFOR CONFIDENTIAL", validatorConfigPath)
	assert.NotNil(t, model)
	assert.Equal(t, "NATO", model.PolicyIdentifier)
}

func TestParse_Classification_UNCLASSIFIED_Success(t *testing.T) {
	parser := NewStanag4774Parser(stanag4774ParserConfigPath)
	model := parser.Parse("NATO UNCLASSIFIED", validatorConfigPath)
	assert.NotNil(t, model)
	assert.Equal(t, models.Classification_CLASSIFICATION_UNCLASSIFIED, model.Classification)
}

func TestParse_Classification_RESTRICTED_Success(t *testing.T) {
	parser := NewStanag4774Parser(stanag4774ParserConfigPath)
	model := parser.Parse("NATO RESTRICTED", validatorConfigPath)
	assert.NotNil(t, model)
	assert.Equal(t, models.Classification_CLASSIFICATION_RESTRICTED, model.Classification)
}

func TestParse_Classification_CONFIDENTIAL_Success(t *testing.T) {
	parser := NewStanag4774Parser(stanag4774ParserConfigPath)
	model := parser.Parse("NATO CONFIDENTIAL", validatorConfigPath)
	assert.NotNil(t, model)
	assert.Equal(t, models.Classification_CLASSIFICATION_CONFIDENTIAL, model.Classification)
}

func TestParse_Classification_SECRET_Success(t *testing.T) {
	parser := NewStanag4774Parser(stanag4774ParserConfigPath)
	model := parser.Parse("NATO SECRET", validatorConfigPath)
	assert.NotNil(t, model)
	assert.Equal(t, models.Classification_CLASSIFICATION_SECRET, model.Classification)
}

func TestParse_Classification_TOP_SECRET_Success(t *testing.T) {
	parser := NewStanag4774Parser(stanag4774ParserConfigPath)
	model := parser.Parse("NATO TOP SECRET", validatorConfigPath)
	assert.NotNil(t, model)
	assert.Equal(t, models.Classification_CLASSIFICATION_TOP_SECRET, model.Classification)
}

func TestParse_Administrative_COMMERCIAL_Success(t *testing.T) {
	parser := NewStanag4774Parser(stanag4774ParserConfigPath)
	model := parser.Parse("NATO CONFIDENTIAL - COMMERCIAL", validatorConfigPath)
	assert.NotNil(t, model)
	assert.Equal(t, models.Administrative_ADMINISTRATIVE_COMMERCIAL, model.Administrative)
}

func TestParse_Administrative_MANAGEMENT_Success(t *testing.T) {
	parser := NewStanag4774Parser(stanag4774ParserConfigPath)
	model := parser.Parse("NATO CONFIDENTIAL - MANAGEMENT", validatorConfigPath)
	assert.NotNil(t, model)
	assert.Equal(t, models.Administrative_ADMINISTRATIVE_MANAGEMENT, model.Administrative)
}

func TestParse_Administrative_MEDICAL_Success(t *testing.T) {
	parser := NewStanag4774Parser(stanag4774ParserConfigPath)
	model := parser.Parse("NATO CONFIDENTIAL - MEDICAL", validatorConfigPath)
	assert.NotNil(t, model)
	assert.Equal(t, models.Administrative_ADMINISTRATIVE_MEDICAL, model.Administrative)
}

func TestParse_Administrative_PERSONAL_Success(t *testing.T) {
	parser := NewStanag4774Parser(stanag4774ParserConfigPath)
	model := parser.Parse("NATO CONFIDENTIAL - PERSONAL", validatorConfigPath)
	assert.NotNil(t, model)
	assert.Equal(t, models.Administrative_ADMINISTRATIVE_PERSONAL, model.Administrative)
}

func TestParse_Administrative_STAFF_Success(t *testing.T) {
	parser := NewStanag4774Parser(stanag4774ParserConfigPath)
	model := parser.Parse("NATO CONFIDENTIAL - STAFF", validatorConfigPath)
	assert.NotNil(t, model)
	assert.Equal(t, models.Administrative_ADMINISTRATIVE_STAFF, model.Administrative)
}

func TestParse_Administrative_TooManyMatches_Success(t *testing.T) {
	parser := NewStanag4774Parser(stanag4774ParserConfigPath)
	model := parser.Parse("NATO CONFIDENTIAL - STAFF - STAFF", validatorConfigPath)
	assert.NotNil(t, model)
	assert.Equal(t, models.Administrative_ADMINISTRATIVE_NONE, model.Administrative)
}

func TestParse_Administrative_DomainValuesExist_Success(t *testing.T) {
	parser := NewStanag4774Parser(stanag4774ParserConfigPath)
	model := parser.Parse("NATO CONFIDENTIAL Releasable To NATO - STAFF", validatorConfigPath)
	assert.Nil(t, model)
}

func TestParse_SpecialCategoryDesignator_ATOMAL_Success(t *testing.T) {
	parser := NewStanag4774Parser(stanag4774ParserConfigPath)
	model := parser.Parse("NATO CONFIDENTIAL - ATOMAL", validatorConfigPath)
	assert.NotNil(t, model)
	assert.Len(t, model.SpecialCategoryDesignators, 1)
	assert.Contains(t, model.SpecialCategoryDesignators, models.SpecialCategoryDesignator_DESIGNATOR_ATOMAL)
}

func TestParse_SpecialCategoryDesignator_BOHEMIA_Success(t *testing.T) {
	parser := NewStanag4774Parser(stanag4774ParserConfigPath)
	model := parser.Parse("NATO TOP SECRET - BOHEMIA", validatorConfigPath)
	assert.NotNil(t, model)
	assert.Len(t, model.SpecialCategoryDesignators, 1)
	assert.Contains(t, model.SpecialCategoryDesignators, models.SpecialCategoryDesignator_DESIGNATOR_BOHEMIA)
}

func TestParse_SpecialCategoryDesignator_CRYPTO_Success(t *testing.T) {
	parser := NewStanag4774Parser(stanag4774ParserConfigPath)
	model := parser.Parse("NATO CONFIDENTIAL - CRYPTO", validatorConfigPath)
	assert.NotNil(t, model)
	assert.Len(t, model.SpecialCategoryDesignators, 1)
	assert.Contains(t, model.SpecialCategoryDesignators, models.SpecialCategoryDesignator_DESIGNATOR_CRYPTO)
}

func TestParse_SpecialCategoryDesignator_SIOP_Success(t *testing.T) {
	parser := NewStanag4774Parser(stanag4774ParserConfigPath)
	model := parser.Parse("NATO CONFIDENTIAL - SIOP", validatorConfigPath)
	assert.NotNil(t, model)
	assert.Len(t, model.SpecialCategoryDesignators, 1)
	assert.Contains(t, model.SpecialCategoryDesignators, models.SpecialCategoryDesignator_DESIGNATOR_SIOP)
}

func TestParse_SpecialCategoryDesignator_TooManyMatches_Success(t *testing.T) {
	parser := NewStanag4774Parser(stanag4774ParserConfigPath)
	model := parser.Parse("NATO CONFIDENTIAL - ATOMAL - ATOMAL", validatorConfigPath)
	assert.NotNil(t, model)
	assert.Len(t, model.SpecialCategoryDesignators, 1)
	assert.Contains(t, model.SpecialCategoryDesignators, models.SpecialCategoryDesignator_DESIGNATOR_NONE)
}

func TestParse_SpecialCategoryDesignator_ATOMAL_CRYPTO_Success(t *testing.T) {
	parser := NewStanag4774Parser(stanag4774ParserConfigPath)
	model := parser.Parse("NATO CONFIDENTIAL - ATOMAL,CRYPTO", validatorConfigPath)
	assert.NotNil(t, model)
	assert.Len(t, model.SpecialCategoryDesignators, 2)
	assert.Contains(t, model.SpecialCategoryDesignators, models.SpecialCategoryDesignator_DESIGNATOR_ATOMAL)
	assert.Contains(t, model.SpecialCategoryDesignators, models.SpecialCategoryDesignator_DESIGNATOR_CRYPTO)
}

func TestParse_SpecialCategoryDesignator_ATOMAL_SIOP_Success(t *testing.T) {
	parser := NewStanag4774Parser(stanag4774ParserConfigPath)
	model := parser.Parse("NATO CONFIDENTIAL - ATOMAL,SIOP", validatorConfigPath)
	assert.NotNil(t, model)
	assert.Len(t, model.SpecialCategoryDesignators, 2)
	assert.Contains(t, model.SpecialCategoryDesignators, models.SpecialCategoryDesignator_DESIGNATOR_ATOMAL)
	assert.Contains(t, model.SpecialCategoryDesignators, models.SpecialCategoryDesignator_DESIGNATOR_SIOP)
}

func TestParse_SpecialCategoryDesignator_CRYPTO_SIOP_Success(t *testing.T) {
	parser := NewStanag4774Parser(stanag4774ParserConfigPath)
	model := parser.Parse("NATO CONFIDENTIAL - CRYPTO,SIOP", validatorConfigPath)
	assert.NotNil(t, model)
	assert.Len(t, model.SpecialCategoryDesignators, 2)
	assert.Contains(t, model.SpecialCategoryDesignators, models.SpecialCategoryDesignator_DESIGNATOR_CRYPTO)
	assert.Contains(t, model.SpecialCategoryDesignators, models.SpecialCategoryDesignator_DESIGNATOR_SIOP)
}

func TestParse_SpecialCategoryDesignator_ATOMAL_CRYPTO_SIOP_Success(t *testing.T) {
	parser := NewStanag4774Parser(stanag4774ParserConfigPath)
	model := parser.Parse("NATO CONFIDENTIAL - ATOMAL,CRYPTO,SIOP", validatorConfigPath)
	assert.NotNil(t, model)
	assert.Len(t, model.SpecialCategoryDesignators, 3)
	assert.Contains(t, model.SpecialCategoryDesignators, models.SpecialCategoryDesignator_DESIGNATOR_ATOMAL)
	assert.Contains(t, model.SpecialCategoryDesignators, models.SpecialCategoryDesignator_DESIGNATOR_CRYPTO)
	assert.Contains(t, model.SpecialCategoryDesignators, models.SpecialCategoryDesignator_DESIGNATOR_SIOP)
}

func TestParse_SpecialCategoryDesignator_ATOMAL_BOHEMIA_Success(t *testing.T) {
	parser := NewStanag4774Parser(stanag4774ParserConfigPath)
	model := parser.Parse("NATO CONFIDENTIAL - ATOMAL,BOHEMIA", validatorConfigPath)
	assert.Nil(t, model)
}

func TestParse_ReleasableTo_Success(t *testing.T) {
	parser := NewStanag4774Parser(stanag4774ParserConfigPath)
	model := parser.Parse("NATO CONFIDENTIAL Releasable To NATO,USA,GBR", validatorConfigPath)
	assert.NotNil(t, model)
	assert.Contains(t, model.GetReleasableTo().GetValues(), "NATO")
	assert.Contains(t, model.GetReleasableTo().GetValues(), "USA")
	assert.Contains(t, model.GetReleasableTo().GetValues(), "GBR")
}

func TestParse_ReleasableTo_Failure(t *testing.T) {
	parser := NewStanag4774Parser(stanag4774ParserConfigPath)
	model := parser.Parse("NATO CONFIDENTIAL Releasable To NATO,AFG", validatorConfigPath)
	assert.NotNil(t, model)
	assert.Contains(t, model.GetReleasableTo().GetValues(), "NATO")
	assert.Contains(t, model.GetReleasableTo().GetValues(), "AFG")
}

func TestParse_Stanag4774ParserConfigFile_Error(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	parser := NewStanag4774Parser(`bad/file/path/config.yaml`)
	assert.Nil(t, parser)
	assert.Contains(t, buf.String(), "error opening config file: ")
}

func TestParse_Stanag4774ParserConfigDecoder_Error(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	parser := NewStanag4774Parser(`../../test/configs/stanag4774/bad.yaml`)
	assert.Nil(t, parser)
	assert.Contains(t, buf.String(), "error decoding config file: ")
}

func TestParse_Parser_ClassificationRegex_Error(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	parser := NewStanag4774Parser(`../../test/configs/stanag4774/parser.config.bad_classification_regex.yaml`)
	model := parser.Parse("NATO CONFIDENTIAL Releasable To NATO,AFG", validatorConfigPath)
	assert.Nil(t, model)
	assert.Contains(t, buf.String(), "failed to compile classification expression")
}

func TestParse_Parser_UndefinedClassificationResponse(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	parser := NewStanag4774Parser(stanag4774ParserConfigPath)
	model := parser.Parse("NATO NOSPEAK - ATOMAL", validatorConfigPath)
	assert.Nil(t, model)
	assert.Contains(t, buf.String(), "failed to parse classification")
}

func TestParse_Parser_SpecialCategoryDesignatorRegex_Error(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	parser := NewStanag4774Parser(`../../test/configs/stanag4774/parser.config.bad_special_category_designator_regex.yaml`)
	model := parser.Parse("NATO CONFIDENTIAL - ATOMAL", validatorConfigPath)
	assert.Nil(t, model)
	assert.Contains(t, buf.String(), "failed to compile special category designator expression")
}

func TestParse_Parser_AdministrativeRegex_Error(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	parser := NewStanag4774Parser(`../../test/configs/stanag4774/parser.config.bad_administrative_regex.yaml`)
	model := parser.Parse("NATO CONFIDENTIAL - STAFF", validatorConfigPath)
	assert.Nil(t, model)
	assert.Contains(t, buf.String(), "failed to compile administrative expression")
}

func TestParse_Parser_ReleasableToRegex_Error(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	parser := NewStanag4774Parser(`../../test/configs/stanag4774/parser.config.bad_releasable_to_regex.yaml`)
	model := parser.Parse("NATO CONFIDENTIAL Releasable To NATO,AFG", validatorConfigPath)
	assert.Nil(t, model)
	assert.Contains(t, buf.String(), "failed to compile releasable to expression")
}

func TestParse_Parser_OnlyRegex_Error(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	parser := NewStanag4774Parser(`../../test/configs/stanag4774/parser.config.bad_only_regex.yaml`)
	model := parser.Parse("NATO/KFOR CONFIDENTIAL NATO, Ireland, Ukraine Only", validatorConfigPath)
	assert.Nil(t, model)
	assert.Contains(t, buf.String(), "failed to compile only expression")
}

func TestNewStanag4774Validator(t *testing.T) {
	validator := NewStanag4774Validator(validatorConfigPath)
	assert.NotNil(t, validator)
	assert.Len(t, validator.Nations, 37)
}

func TestValidator_ValidatorConfigFile_Error(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	parser := NewStanag4774Validator(`bad/file/path/config.yaml`)
	assert.Nil(t, parser)
	assert.Contains(t, buf.String(), "error opening config file: ")
}

func TestValidator_ValidatorConfigDecoder_Error(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	parser := NewStanag4774Validator(`../../test/configs/stanag4774/bad.yaml`)
	assert.Nil(t, parser)
	assert.Contains(t, buf.String(), "error decoding config file: ")
}

func TestValidate_SpecialCategoryDesignator_DESIGNATOR_BOHEMIA_Success(t *testing.T) {
	validator := NewStanag4774Validator(validatorConfigPath)

	model := &models.Stanag4774{
		SpecialCategoryDesignators: []models.SpecialCategoryDesignator{models.SpecialCategoryDesignator_DESIGNATOR_BOHEMIA},
		Classification:             models.Classification_CLASSIFICATION_TOP_SECRET,
	}

	assert.True(t, validator.Validate(model))
}

func TestValidate_SpecialCategoryDesignator_DESIGNATOR_BOHEMIA_Failure(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	validator := NewStanag4774Validator(validatorConfigPath)

	model := &models.Stanag4774{
		SpecialCategoryDesignators: []models.SpecialCategoryDesignator{models.SpecialCategoryDesignator_DESIGNATOR_BOHEMIA},
		Classification:             models.Classification_CLASSIFICATION_CONFIDENTIAL,
	}

	assert.False(t, validator.Validate(model))
	assert.Contains(t, buf.String(), "failed to validate special category designator(DESIGNATOR_BOHEMIA) for CLASSIFICATION_CONFIDENTIAL: 44")
}

func TestValidate_SpecialCategoryDesignator_DESIGNATOR_ATOMAL_Success(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	validator := NewStanag4774Validator(validatorConfigPath)

	model := &models.Stanag4774{
		SpecialCategoryDesignators: []models.SpecialCategoryDesignator{models.SpecialCategoryDesignator_DESIGNATOR_ATOMAL},
		Classification:             models.Classification_CLASSIFICATION_CONFIDENTIAL,
	}

	assert.True(t, validator.Validate(model))
}

func TestValidate_SpecialCategoryDesignator_DESIGNATOR_ATOMAL_Failure(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	validator := NewStanag4774Validator(validatorConfigPath)

	model := &models.Stanag4774{
		SpecialCategoryDesignators: []models.SpecialCategoryDesignator{models.SpecialCategoryDesignator_DESIGNATOR_ATOMAL},
		Classification:             models.Classification_CLASSIFICATION_TOP_SECRET,
	}

	assert.False(t, validator.Validate(model))
	assert.Contains(t, buf.String(), "failed to validate special category designator(DESIGNATOR_ATOMAL) for CLASSIFICATION_TOP_SECRET: 43")
}

func TestValidate_SpecialCategoryDesignator_DESIGNATOR_CRYPTO_Success(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	validator := NewStanag4774Validator(validatorConfigPath)

	model := &models.Stanag4774{
		SpecialCategoryDesignators: []models.SpecialCategoryDesignator{models.SpecialCategoryDesignator_DESIGNATOR_CRYPTO},
		Classification:             models.Classification_CLASSIFICATION_CONFIDENTIAL,
	}

	assert.True(t, validator.Validate(model))
}

func TestValidate_SpecialCategoryDesignator_DESIGNATOR_CRYPTO_Failure(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	validator := NewStanag4774Validator(validatorConfigPath)

	model := &models.Stanag4774{
		SpecialCategoryDesignators: []models.SpecialCategoryDesignator{models.SpecialCategoryDesignator_DESIGNATOR_CRYPTO},
		Classification:             models.Classification_CLASSIFICATION_TOP_SECRET,
	}

	assert.False(t, validator.Validate(model))
	assert.Contains(t, buf.String(), "failed to validate special category designator(DESIGNATOR_CRYPTO) for CLASSIFICATION_TOP_SECRET: 45")
}

func TestValidate_SpecialCategoryDesignator_DESIGNATOR_SIOP_Success(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	validator := NewStanag4774Validator(validatorConfigPath)

	model := &models.Stanag4774{
		SpecialCategoryDesignators: []models.SpecialCategoryDesignator{models.SpecialCategoryDesignator_DESIGNATOR_SIOP},
		Classification:             models.Classification_CLASSIFICATION_CONFIDENTIAL,
	}

	assert.True(t, validator.Validate(model))
}

func TestValidate_SpecialCategoryDesignator_DESIGNATOR_SIOP_Failure(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	validator := NewStanag4774Validator(validatorConfigPath)

	model := &models.Stanag4774{
		SpecialCategoryDesignators: []models.SpecialCategoryDesignator{models.SpecialCategoryDesignator_DESIGNATOR_SIOP},
		Classification:             models.Classification_CLASSIFICATION_TOP_SECRET,
	}

	assert.False(t, validator.Validate(model))
	assert.Contains(t, buf.String(), "failed to validate special category designator(DESIGNATOR_SIOP) for CLASSIFICATION_TOP_SECRET: 46")
}

func TestValidate_SpecialCategoryDesignator_DESIGNATOR_BOHEMIA_ATOMAL_TS_Failure(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	validator := NewStanag4774Validator(validatorConfigPath)

	model := &models.Stanag4774{
		SpecialCategoryDesignators: []models.SpecialCategoryDesignator{models.SpecialCategoryDesignator_DESIGNATOR_BOHEMIA, models.SpecialCategoryDesignator_DESIGNATOR_ATOMAL},
		Classification:             models.Classification_CLASSIFICATION_TOP_SECRET,
	}

	assert.False(t, validator.Validate(model))
	assert.Contains(t, buf.String(), "failed to validate special category designator(DESIGNATOR_ATOMAL) for CLASSIFICATION_TOP_SECRET: 43")
}

func TestValidate_SpecialCategoryDesignator_DESIGNATOR_BOHEMIA_ATOMAL_C_Failure(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	validator := NewStanag4774Validator(validatorConfigPath)

	model := &models.Stanag4774{
		SpecialCategoryDesignators: []models.SpecialCategoryDesignator{models.SpecialCategoryDesignator_DESIGNATOR_BOHEMIA, models.SpecialCategoryDesignator_DESIGNATOR_ATOMAL},
		Classification:             models.Classification_CLASSIFICATION_CONFIDENTIAL,
	}

	assert.False(t, validator.Validate(model))
	assert.Contains(t, buf.String(), "failed to validate special category designator(DESIGNATOR_BOHEMIA) for CLASSIFICATION_CONFIDENTIAL: 44")
}

func TestValidate_SpecialCategoryDesignator_DESIGNATOR_BOHEMIA_CRYPTO_TS_Failure(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	validator := NewStanag4774Validator(validatorConfigPath)

	model := &models.Stanag4774{
		SpecialCategoryDesignators: []models.SpecialCategoryDesignator{models.SpecialCategoryDesignator_DESIGNATOR_BOHEMIA, models.SpecialCategoryDesignator_DESIGNATOR_CRYPTO},
		Classification:             models.Classification_CLASSIFICATION_TOP_SECRET,
	}

	assert.False(t, validator.Validate(model))
	assert.Contains(t, buf.String(), "failed to validate special category designator(DESIGNATOR_CRYPTO) for CLASSIFICATION_TOP_SECRET: 45")
}

func TestValidate_SpecialCategoryDesignator_DESIGNATOR_BOHEMIA_CRYPTO_C_Failure(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	validator := NewStanag4774Validator(validatorConfigPath)

	model := &models.Stanag4774{
		SpecialCategoryDesignators: []models.SpecialCategoryDesignator{models.SpecialCategoryDesignator_DESIGNATOR_BOHEMIA, models.SpecialCategoryDesignator_DESIGNATOR_CRYPTO},
		Classification:             models.Classification_CLASSIFICATION_CONFIDENTIAL,
	}

	assert.False(t, validator.Validate(model))
	assert.Contains(t, buf.String(), "failed to validate special category designator(DESIGNATOR_BOHEMIA) for CLASSIFICATION_CONFIDENTIAL: 44")
}

func TestValidate_SpecialCategoryDesignator_DESIGNATOR_BOHEMIA_SIOP_TS_Failure(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	validator := NewStanag4774Validator(validatorConfigPath)

	model := &models.Stanag4774{
		SpecialCategoryDesignators: []models.SpecialCategoryDesignator{models.SpecialCategoryDesignator_DESIGNATOR_BOHEMIA, models.SpecialCategoryDesignator_DESIGNATOR_SIOP},
		Classification:             models.Classification_CLASSIFICATION_TOP_SECRET,
	}

	assert.False(t, validator.Validate(model))
	assert.Contains(t, buf.String(), "failed to validate special category designator(DESIGNATOR_SIOP) for CLASSIFICATION_TOP_SECRET: 46")
}

func TestValidate_SpecialCategoryDesignator_DESIGNATOR_BOHEMIA_SIOP_C_Failure(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	validator := NewStanag4774Validator(validatorConfigPath)

	model := &models.Stanag4774{
		SpecialCategoryDesignators: []models.SpecialCategoryDesignator{models.SpecialCategoryDesignator_DESIGNATOR_BOHEMIA, models.SpecialCategoryDesignator_DESIGNATOR_SIOP},
		Classification:             models.Classification_CLASSIFICATION_CONFIDENTIAL,
	}

	assert.False(t, validator.Validate(model))
	assert.Contains(t, buf.String(), "failed to validate special category designator(DESIGNATOR_BOHEMIA) for CLASSIFICATION_CONFIDENTIAL: 44")
}

func TestValidate_SpecialCategoryDesignator_DESIGNATOR_BOHEMIA_ATOMAL_CRYPTO_TS_Failure(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	validator := NewStanag4774Validator(validatorConfigPath)

	model := &models.Stanag4774{
		SpecialCategoryDesignators: []models.SpecialCategoryDesignator{models.SpecialCategoryDesignator_DESIGNATOR_BOHEMIA, models.SpecialCategoryDesignator_DESIGNATOR_ATOMAL, models.SpecialCategoryDesignator_DESIGNATOR_CRYPTO},
		Classification:             models.Classification_CLASSIFICATION_TOP_SECRET,
	}

	assert.False(t, validator.Validate(model))
	assert.Contains(t, buf.String(), "failed to validate special category designator(DESIGNATOR_ATOMAL) for CLASSIFICATION_TOP_SECRET: 43")
	assert.Contains(t, buf.String(), "failed to validate special category designator(DESIGNATOR_CRYPTO) for CLASSIFICATION_TOP_SECRET: 45")
}

func TestValidate_SpecialCategoryDesignator_DESIGNATOR_BOHEMIA_ATOMAL_CRYPTO_C_Failure(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	validator := NewStanag4774Validator(validatorConfigPath)

	model := &models.Stanag4774{
		SpecialCategoryDesignators: []models.SpecialCategoryDesignator{models.SpecialCategoryDesignator_DESIGNATOR_BOHEMIA, models.SpecialCategoryDesignator_DESIGNATOR_ATOMAL, models.SpecialCategoryDesignator_DESIGNATOR_CRYPTO},
		Classification:             models.Classification_CLASSIFICATION_CONFIDENTIAL,
	}

	assert.False(t, validator.Validate(model))
	assert.Contains(t, buf.String(), "failed to validate special category designator(DESIGNATOR_BOHEMIA) for CLASSIFICATION_CONFIDENTIAL: 44")
}

func TestValidate_SpecialCategoryDesignator_DESIGNATOR_BOHEMIA_ATOMAL_SIOP_TS_Failure(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	validator := NewStanag4774Validator(validatorConfigPath)

	model := &models.Stanag4774{
		SpecialCategoryDesignators: []models.SpecialCategoryDesignator{models.SpecialCategoryDesignator_DESIGNATOR_BOHEMIA, models.SpecialCategoryDesignator_DESIGNATOR_ATOMAL, models.SpecialCategoryDesignator_DESIGNATOR_SIOP},
		Classification:             models.Classification_CLASSIFICATION_TOP_SECRET,
	}

	assert.False(t, validator.Validate(model))
	assert.Contains(t, buf.String(), "failed to validate special category designator(DESIGNATOR_ATOMAL) for CLASSIFICATION_TOP_SECRET: 43")
	assert.Contains(t, buf.String(), "failed to validate special category designator(DESIGNATOR_SIOP) for CLASSIFICATION_TOP_SECRET: 46")
}

func TestValidate_SpecialCategoryDesignator_DESIGNATOR_BOHEMIA_ATOMAL_SIOP_C_Failure(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	validator := NewStanag4774Validator(validatorConfigPath)

	model := &models.Stanag4774{
		SpecialCategoryDesignators: []models.SpecialCategoryDesignator{models.SpecialCategoryDesignator_DESIGNATOR_BOHEMIA, models.SpecialCategoryDesignator_DESIGNATOR_ATOMAL, models.SpecialCategoryDesignator_DESIGNATOR_SIOP},
		Classification:             models.Classification_CLASSIFICATION_CONFIDENTIAL,
	}

	assert.False(t, validator.Validate(model))
	assert.Contains(t, buf.String(), "failed to validate special category designator(DESIGNATOR_BOHEMIA) for CLASSIFICATION_CONFIDENTIAL: 44")
}

func TestValidate_SpecialCategoryDesignator_DESIGNATOR_BOHEMIA_CRYPTO_SIOP_TS_Failure(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	validator := NewStanag4774Validator(validatorConfigPath)

	model := &models.Stanag4774{
		SpecialCategoryDesignators: []models.SpecialCategoryDesignator{models.SpecialCategoryDesignator_DESIGNATOR_BOHEMIA, models.SpecialCategoryDesignator_DESIGNATOR_CRYPTO, models.SpecialCategoryDesignator_DESIGNATOR_SIOP},
		Classification:             models.Classification_CLASSIFICATION_TOP_SECRET,
	}

	assert.False(t, validator.Validate(model))
	assert.Contains(t, buf.String(), "failed to validate special category designator(DESIGNATOR_CRYPTO) for CLASSIFICATION_TOP_SECRET: 45")
	assert.Contains(t, buf.String(), "failed to validate special category designator(DESIGNATOR_SIOP) for CLASSIFICATION_TOP_SECRET: 46")
}

func TestValidate_SpecialCategoryDesignator_DESIGNATOR_BOHEMIA_CRYPTO_SIOP_C_Failure(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	validator := NewStanag4774Validator(validatorConfigPath)

	model := &models.Stanag4774{
		SpecialCategoryDesignators: []models.SpecialCategoryDesignator{models.SpecialCategoryDesignator_DESIGNATOR_BOHEMIA, models.SpecialCategoryDesignator_DESIGNATOR_CRYPTO, models.SpecialCategoryDesignator_DESIGNATOR_SIOP},
		Classification:             models.Classification_CLASSIFICATION_CONFIDENTIAL,
	}

	assert.False(t, validator.Validate(model))
	assert.Contains(t, buf.String(), "failed to validate special category designator(DESIGNATOR_BOHEMIA) for CLASSIFICATION_CONFIDENTIAL: 44")
}

func TestValidate_SpecialCategoryDesignator_DESIGNATOR_BOHEMIA_ATOMAL_CRYPTO_SIOP_TS_Failure(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	validator := NewStanag4774Validator(validatorConfigPath)

	model := &models.Stanag4774{
		SpecialCategoryDesignators: []models.SpecialCategoryDesignator{models.SpecialCategoryDesignator_DESIGNATOR_BOHEMIA, models.SpecialCategoryDesignator_DESIGNATOR_ATOMAL, models.SpecialCategoryDesignator_DESIGNATOR_CRYPTO, models.SpecialCategoryDesignator_DESIGNATOR_SIOP},
		Classification:             models.Classification_CLASSIFICATION_TOP_SECRET,
	}

	assert.False(t, validator.Validate(model))
	assert.Contains(t, buf.String(), "failed to validate special category designator(DESIGNATOR_ATOMAL) for CLASSIFICATION_TOP_SECRET: 43")
	assert.Contains(t, buf.String(), "failed to validate special category designator(DESIGNATOR_CRYPTO) for CLASSIFICATION_TOP_SECRET: 45")
	assert.Contains(t, buf.String(), "failed to validate special category designator(DESIGNATOR_SIOP) for CLASSIFICATION_TOP_SECRET: 46")
}

func TestValidate_SpecialCategoryDesignator_DESIGNATOR_BOHEMIA_ATOMAL_CRYPTO_SIOP_C_Failure(t *testing.T) {
	var buf bytes.Buffer

	log.SetOutput(&buf)
	defer func() {
		log.SetOutput(os.Stderr)
	}()

	validator := NewStanag4774Validator(validatorConfigPath)

	model := &models.Stanag4774{
		SpecialCategoryDesignators: []models.SpecialCategoryDesignator{models.SpecialCategoryDesignator_DESIGNATOR_BOHEMIA, models.SpecialCategoryDesignator_DESIGNATOR_ATOMAL, models.SpecialCategoryDesignator_DESIGNATOR_CRYPTO, models.SpecialCategoryDesignator_DESIGNATOR_SIOP},
		Classification:             models.Classification_CLASSIFICATION_CONFIDENTIAL,
	}

	assert.False(t, validator.Validate(model))
	assert.Contains(t, buf.String(), "failed to validate special category designator(DESIGNATOR_BOHEMIA) for CLASSIFICATION_CONFIDENTIAL: 44")
}

func TestValidate_Administrative_Success(t *testing.T) {
	validator := NewStanag4774Validator(validatorConfigPath)

	model := &models.Stanag4774{
		Administrative: models.Administrative_ADMINISTRATIVE_MANAGEMENT,
	}

	assert.True(t, validator.Validate(model))
}

func TestValidate_Administrative_ReleasableTo_Failure(t *testing.T) {
	validator := NewStanag4774Validator(validatorConfigPath)

	model := &models.Stanag4774{
		Administrative: models.Administrative_ADMINISTRATIVE_MANAGEMENT,
		ReleasableTo: &models.Stanag4774_Category{
			Type:   models.Stanag4774_Category_CATEGORY_TYPE_PERMISSIVE,
			Values: []string{"USA"},
		},
	}

	assert.False(t, validator.Validate(model))
}

func TestValidate_Administrative_Only_Failure(t *testing.T) {
	validator := NewStanag4774Validator(validatorConfigPath)

	model := &models.Stanag4774{
		Administrative: models.Administrative_ADMINISTRATIVE_MANAGEMENT,
		Only: &models.Stanag4774_Category{
			Type:   models.Stanag4774_Category_CATEGORY_TYPE_PERMISSIVE,
			Values: []string{"USA"},
		},
	}

	assert.False(t, validator.Validate(model))
}

func TestValidateClassification_CONFIDENTIAL_Success(t *testing.T) {
	assert.True(t, validateClassification(models.Classification_CLASSIFICATION_CONFIDENTIAL, "U"))
}

func TestValidateClassification_RESTRICTED_Success(t *testing.T) {
	assert.True(t, validateClassification(models.Classification_CLASSIFICATION_UNCLASSIFIED, "U"))
}

func TestValidateClassification_U_Success(t *testing.T) {
	assert.True(t, validateClassification(models.Classification_CLASSIFICATION_UNCLASSIFIED, "U"))
}

func TestValidateClassification_U_S_Success(t *testing.T) {
	assert.True(t, validateClassification(models.Classification_CLASSIFICATION_UNCLASSIFIED, "S"))
}

func TestValidateClassification_U_CTS_Success(t *testing.T) {
	assert.True(t, validateClassification(models.Classification_CLASSIFICATION_UNCLASSIFIED, "CTS"))
}

func TestValidateClassification_U_Failure(t *testing.T) {
	assert.False(t, validateClassification(models.Classification_CLASSIFICATION_UNCLASSIFIED, "R"))
}

func TestValidateClassification_S_Success(t *testing.T) {
	assert.True(t, validateClassification(models.Classification_CLASSIFICATION_SECRET, "S"))
}

func TestValidateClassification_S_CTS_Success(t *testing.T) {
	assert.True(t, validateClassification(models.Classification_CLASSIFICATION_SECRET, "CTS"))
}

func TestValidateClassification_S_Failure(t *testing.T) {
	assert.False(t, validateClassification(models.Classification_CLASSIFICATION_SECRET, "R"))
}

func TestValidateClassification_CTS_Success(t *testing.T) {
	assert.True(t, validateClassification(models.Classification_CLASSIFICATION_TOP_SECRET, "CTS"))
}

func TestValidateClassification_CTS_Failure(t *testing.T) {
	assert.False(t, validateClassification(models.Classification_CLASSIFICATION_TOP_SECRET, "C"))
}

func TestValidateClassification_Default_Success(t *testing.T) {
	assert.False(t, validateClassification(models.Classification_CLASSIFICATION_NONE, "U"))
}

func TestGetNation_Success(t *testing.T) {
	validator := NewStanag4774Validator(validatorConfigPath)

	nation := getNation("AFG", validator)
	assert.NotNil(t, nation)
	assert.Equal(t, "AFG", nation.Name)
}

func TestGetNation_FAILURE(t *testing.T) {
	validator := NewStanag4774Validator(validatorConfigPath)

	nation := getNation("ZZZ", validator)
	assert.NotNil(t, nation)
	assert.NotEqual(t, "ZZZ", nation.Name)
}

func TestValidateContextDomainValues_PolicyIdentifier_Failure(t *testing.T) {
	model := &models.Stanag4774{
		PolicyIdentifier: "USA",
	}

	assert.False(t, validateContextValueDomain(model, Nation{}))
}

func TestValidateContextDomainValues_Classification_Failure(t *testing.T) {
	model := &models.Stanag4774{
		PolicyIdentifier: "NATO",
		Classification:   models.Classification_CLASSIFICATION_SECRET,
	}

	assert.False(t, validateContextValueDomain(model, Nation{}))
}

func TestValidateReleasableToDomainValues_Classification_Failure(t *testing.T) {
	model := &models.Stanag4774{
		Classification: models.Classification_CLASSIFICATION_SECRET,
	}

	assert.False(t, validateValueDomain(model, Nation{}))
}

func TestValidateContextDomainValues_Success(t *testing.T) {
	tests := []struct {
		name           string
		classification models.Classification
	}{
		{"AFG", models.Classification_CLASSIFICATION_UNCLASSIFIED},
		{"ALB", models.Classification_CLASSIFICATION_TOP_SECRET},
		{"ALG", models.Classification_CLASSIFICATION_SECRET},
		{"ARM", models.Classification_CLASSIFICATION_SECRET},
		{"AUS", models.Classification_CLASSIFICATION_SECRET},
		{"AUT", models.Classification_CLASSIFICATION_SECRET},
		{"AZE", models.Classification_CLASSIFICATION_SECRET},
		{"BAH", models.Classification_CLASSIFICATION_SECRET},
		{"BLR", models.Classification_CLASSIFICATION_UNCLASSIFIED},
		{"BEL", models.Classification_CLASSIFICATION_TOP_SECRET},
		{"BIH", models.Classification_CLASSIFICATION_SECRET},
		{"BGR", models.Classification_CLASSIFICATION_TOP_SECRET},
		{"CAN", models.Classification_CLASSIFICATION_TOP_SECRET},
		{"HRV", models.Classification_CLASSIFICATION_TOP_SECRET},
		{"CZE", models.Classification_CLASSIFICATION_TOP_SECRET},
		{"DNK", models.Classification_CLASSIFICATION_TOP_SECRET},
		{"EGY", models.Classification_CLASSIFICATION_SECRET},
		{"EST", models.Classification_CLASSIFICATION_TOP_SECRET},
		{"FIN", models.Classification_CLASSIFICATION_SECRET},
		{"FRA", models.Classification_CLASSIFICATION_TOP_SECRET},
		{"GEO", models.Classification_CLASSIFICATION_SECRET},
		{"DEU", models.Classification_CLASSIFICATION_TOP_SECRET},
		{"GRC", models.Classification_CLASSIFICATION_TOP_SECRET},
		{"HUN", models.Classification_CLASSIFICATION_TOP_SECRET},
		{"ISL", models.Classification_CLASSIFICATION_TOP_SECRET},
		{"IRQ", models.Classification_CLASSIFICATION_UNCLASSIFIED},
		{"IRE", models.Classification_CLASSIFICATION_SECRET},
		{"GBR", models.Classification_CLASSIFICATION_TOP_SECRET},
		{"USA", models.Classification_CLASSIFICATION_TOP_SECRET},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := &models.Stanag4774{
				PolicyIdentifier: "NATO",
				Classification:   tt.classification,
				Context: &models.Stanag4774_Category{
					Type:   models.Stanag4774_Category_CATEGORY_TYPE_PERMISSIVE,
					Values: []string{tt.name},
				},
			}

			validator := NewStanag4774Validator(validatorConfigPath)

			nation := getNation(tt.name, validator)

			assert.True(t, validateContextValueDomain(model, nation))
		})
	}
}

func TestValidateContextDomainValues_NATO_Failure(t *testing.T) {
	model := &models.Stanag4774{
		PolicyIdentifier: "NATO",
		Classification:   models.Classification_CLASSIFICATION_UNCLASSIFIED,
		Context: &models.Stanag4774_Category{
			Type:   models.Stanag4774_Category_CATEGORY_TYPE_PERMISSIVE,
			Values: []string{"NATO"},
		},
	}

	validator := NewStanag4774Validator(validatorConfigPath)

	nation := getNation("AFG", validator)

	assert.False(t, validateContextValueDomain(model, nation))
}

func TestValidateContextDomainValues_Failures(t *testing.T) {
	tests := []struct {
		name string
	}{
		{"EAPC"},
		{"GEORGIA"},
		{"KFOR"},
		{"PFP"},
		{"RESOLUTE SUPPORT"},
		{"RUSSIA"},
		{"UKRAINE"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := &models.Stanag4774{
				PolicyIdentifier: "NATO",
				Classification:   models.Classification_CLASSIFICATION_UNCLASSIFIED,
				Context: &models.Stanag4774_Category{
					Type:   models.Stanag4774_Category_CATEGORY_TYPE_PERMISSIVE,
					Values: []string{tt.name},
				},
			}

			validator := NewStanag4774Validator(validatorConfigPath)

			nation := getNation("USA", validator)

			assert.False(t, validateContextValueDomain(model, nation))
		})
	}
}

func TestValidateReleasableToDomainValues_NATO(t *testing.T) {
	tests := []struct {
		name           string
		classification models.Classification
		expected       bool
	}{
		{"AFG", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"ALB", models.Classification_CLASSIFICATION_TOP_SECRET, true},
		{"ALG", models.Classification_CLASSIFICATION_SECRET, false},
		{"ARM", models.Classification_CLASSIFICATION_SECRET, false},
		{"AUS", models.Classification_CLASSIFICATION_SECRET, false},
		{"AUT", models.Classification_CLASSIFICATION_SECRET, false},
		{"AZE", models.Classification_CLASSIFICATION_SECRET, false},
		{"BAH", models.Classification_CLASSIFICATION_SECRET, false},
		{"BLR", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"BEL", models.Classification_CLASSIFICATION_SECRET, true},
		{"BIH", models.Classification_CLASSIFICATION_SECRET, false},
		{"BGR", models.Classification_CLASSIFICATION_TOP_SECRET, true},
		{"CAN", models.Classification_CLASSIFICATION_TOP_SECRET, true},
		{"HRV", models.Classification_CLASSIFICATION_TOP_SECRET, true},
		{"CZE", models.Classification_CLASSIFICATION_TOP_SECRET, true},
		{"DNK", models.Classification_CLASSIFICATION_TOP_SECRET, true},
		{"EGY", models.Classification_CLASSIFICATION_SECRET, false},
		{"EST", models.Classification_CLASSIFICATION_TOP_SECRET, true},
		{"FIN", models.Classification_CLASSIFICATION_SECRET, false},
		{"FRA", models.Classification_CLASSIFICATION_TOP_SECRET, true},
		{"GEO", models.Classification_CLASSIFICATION_SECRET, false},
		{"DEU", models.Classification_CLASSIFICATION_TOP_SECRET, true},
		{"GRC", models.Classification_CLASSIFICATION_TOP_SECRET, true},
		{"HUN", models.Classification_CLASSIFICATION_TOP_SECRET, true},
		{"ISL", models.Classification_CLASSIFICATION_TOP_SECRET, true},
		{"IRQ", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"IRE", models.Classification_CLASSIFICATION_SECRET, false},
		{"ISR", models.Classification_CLASSIFICATION_SECRET, false},
		{"ITA", models.Classification_CLASSIFICATION_TOP_SECRET, true},
		{"JAP", models.Classification_CLASSIFICATION_SECRET, false},
		{"GBR", models.Classification_CLASSIFICATION_TOP_SECRET, true},
		{"USA", models.Classification_CLASSIFICATION_TOP_SECRET, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := &models.Stanag4774{
				Classification: tt.classification,
				ReleasableTo: &models.Stanag4774_Category{
					Type:   models.Stanag4774_Category_CATEGORY_TYPE_PERMISSIVE,
					Values: []string{tt.name, "NATO"},
				},
			}

			validator := NewStanag4774Validator(validatorConfigPath)

			nation := getNation(tt.name, validator)

			result := validateValueDomain(model, nation)

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestValidateReleasableToDomainValues_EAPC(t *testing.T) {
	tests := []struct {
		name           string
		classification models.Classification
		expected       bool
	}{
		{"AFG", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"ALB", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"ALG", models.Classification_CLASSIFICATION_SECRET, false},
		{"ARM", models.Classification_CLASSIFICATION_SECRET, true},
		{"AUS", models.Classification_CLASSIFICATION_SECRET, false},
		{"AUT", models.Classification_CLASSIFICATION_SECRET, true},
		{"AZE", models.Classification_CLASSIFICATION_SECRET, true},
		{"BAH", models.Classification_CLASSIFICATION_SECRET, false},
		{"BLR", models.Classification_CLASSIFICATION_UNCLASSIFIED, true},
		{"BEL", models.Classification_CLASSIFICATION_SECRET, false},
		{"BIH", models.Classification_CLASSIFICATION_SECRET, true},
		{"BGR", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"CAN", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"HRV", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"CZE", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"DNK", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"EGY", models.Classification_CLASSIFICATION_SECRET, false},
		{"EST", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"FIN", models.Classification_CLASSIFICATION_SECRET, true},
		{"FRA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"GEO", models.Classification_CLASSIFICATION_SECRET, true},
		{"DEU", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"GRC", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"HUN", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"ISL", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"IRQ", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"IRE", models.Classification_CLASSIFICATION_SECRET, true},
		{"ISR", models.Classification_CLASSIFICATION_SECRET, false},
		{"ITA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"JAP", models.Classification_CLASSIFICATION_SECRET, false},
		{"GBR", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"USA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := &models.Stanag4774{
				Classification: tt.classification,
				ReleasableTo: &models.Stanag4774_Category{
					Type:   models.Stanag4774_Category_CATEGORY_TYPE_PERMISSIVE,
					Values: []string{tt.name, "EAPC"},
				},
			}

			validator := NewStanag4774Validator(validatorConfigPath)

			nation := getNation(tt.name, validator)

			result := validateValueDomain(model, nation)

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestValidateReleasableToDomainValues_GEORGIA(t *testing.T) {
	tests := []struct {
		name           string
		classification models.Classification
		expected       bool
	}{
		{"AFG", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"ALB", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"ALG", models.Classification_CLASSIFICATION_SECRET, false},
		{"ARM", models.Classification_CLASSIFICATION_SECRET, false},
		{"AUS", models.Classification_CLASSIFICATION_SECRET, false},
		{"AUT", models.Classification_CLASSIFICATION_SECRET, false},
		{"AZE", models.Classification_CLASSIFICATION_SECRET, false},
		{"BAH", models.Classification_CLASSIFICATION_SECRET, false},
		{"BLR", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"BEL", models.Classification_CLASSIFICATION_SECRET, false},
		{"BIH", models.Classification_CLASSIFICATION_SECRET, false},
		{"BGR", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"CAN", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"HRV", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"CZE", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"DNK", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"EGY", models.Classification_CLASSIFICATION_SECRET, false},
		{"EST", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"FIN", models.Classification_CLASSIFICATION_SECRET, false},
		{"FRA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"GEO", models.Classification_CLASSIFICATION_SECRET, true},
		{"DEU", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"GRC", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"HUN", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"ISL", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"IRQ", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"IRE", models.Classification_CLASSIFICATION_SECRET, false},
		{"ISR", models.Classification_CLASSIFICATION_SECRET, false},
		{"ITA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"JAP", models.Classification_CLASSIFICATION_SECRET, false},
		{"GBR", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"USA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := &models.Stanag4774{
				Classification: tt.classification,
				ReleasableTo: &models.Stanag4774_Category{
					Type:   models.Stanag4774_Category_CATEGORY_TYPE_PERMISSIVE,
					Values: []string{tt.name, "GEORGIA"},
				},
			}

			validator := NewStanag4774Validator(validatorConfigPath)

			nation := getNation(tt.name, validator)

			result := validateValueDomain(model, nation)

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestValidateReleasableToDomainValues_KFOR(t *testing.T) {
	tests := []struct {
		name           string
		classification models.Classification
		expected       bool
	}{
		{"AFG", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"ALB", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"ALG", models.Classification_CLASSIFICATION_SECRET, false},
		{"ARM", models.Classification_CLASSIFICATION_SECRET, true},
		{"AUS", models.Classification_CLASSIFICATION_SECRET, false},
		{"AUT", models.Classification_CLASSIFICATION_SECRET, true},
		{"AZE", models.Classification_CLASSIFICATION_SECRET, false},
		{"BAH", models.Classification_CLASSIFICATION_SECRET, false},
		{"BLR", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"BEL", models.Classification_CLASSIFICATION_SECRET, false},
		{"BIH", models.Classification_CLASSIFICATION_SECRET, false},
		{"BGR", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"CAN", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"HRV", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"CZE", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"DNK", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"EGY", models.Classification_CLASSIFICATION_SECRET, false},
		{"EST", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"FIN", models.Classification_CLASSIFICATION_SECRET, true},
		{"FRA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"GEO", models.Classification_CLASSIFICATION_SECRET, false},
		{"DEU", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"GRC", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"HUN", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"ISL", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"IRQ", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"IRE", models.Classification_CLASSIFICATION_SECRET, true},
		{"ISR", models.Classification_CLASSIFICATION_SECRET, false},
		{"ITA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"JAP", models.Classification_CLASSIFICATION_SECRET, false},
		{"GBR", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"USA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := &models.Stanag4774{
				Classification: tt.classification,
				ReleasableTo: &models.Stanag4774_Category{
					Type:   models.Stanag4774_Category_CATEGORY_TYPE_PERMISSIVE,
					Values: []string{tt.name, "KFOR"},
				},
			}

			validator := NewStanag4774Validator(validatorConfigPath)

			nation := getNation(tt.name, validator)

			result := validateValueDomain(model, nation)

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestValidateReleasableToDomainValues_PFP(t *testing.T) {
	tests := []struct {
		name           string
		classification models.Classification
		expected       bool
	}{
		{"AFG", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"ALB", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"ALG", models.Classification_CLASSIFICATION_SECRET, false},
		{"ARM", models.Classification_CLASSIFICATION_SECRET, true},
		{"AUS", models.Classification_CLASSIFICATION_SECRET, false},
		{"AUT", models.Classification_CLASSIFICATION_SECRET, true},
		{"AZE", models.Classification_CLASSIFICATION_SECRET, true},
		{"BAH", models.Classification_CLASSIFICATION_SECRET, false},
		{"BLR", models.Classification_CLASSIFICATION_UNCLASSIFIED, true},
		{"BEL", models.Classification_CLASSIFICATION_SECRET, false},
		{"BIH", models.Classification_CLASSIFICATION_SECRET, true},
		{"BGR", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"CAN", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"HRV", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"CZE", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"DNK", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"EGY", models.Classification_CLASSIFICATION_SECRET, false},
		{"EST", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"FIN", models.Classification_CLASSIFICATION_SECRET, true},
		{"FRA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"GEO", models.Classification_CLASSIFICATION_SECRET, true},
		{"DEU", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"GRC", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"HUN", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"ISL", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"IRQ", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"IRE", models.Classification_CLASSIFICATION_SECRET, true},
		{"ISR", models.Classification_CLASSIFICATION_SECRET, false},
		{"ITA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"JAP", models.Classification_CLASSIFICATION_SECRET, false},
		{"GBR", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"USA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := &models.Stanag4774{
				Classification: tt.classification,
				ReleasableTo: &models.Stanag4774_Category{
					Type:   models.Stanag4774_Category_CATEGORY_TYPE_PERMISSIVE,
					Values: []string{tt.name, "PFP"},
				},
			}

			validator := NewStanag4774Validator(validatorConfigPath)

			nation := getNation(tt.name, validator)

			result := validateValueDomain(model, nation)

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestValidateReleasableToDomainValues_RESOLUTE_SUPPORT(t *testing.T) {
	tests := []struct {
		name           string
		classification models.Classification
		expected       bool
	}{
		{"AFG", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"ALB", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"ALG", models.Classification_CLASSIFICATION_SECRET, false},
		{"ARM", models.Classification_CLASSIFICATION_SECRET, true},
		{"AUS", models.Classification_CLASSIFICATION_SECRET, true},
		{"AUT", models.Classification_CLASSIFICATION_SECRET, true},
		{"AZE", models.Classification_CLASSIFICATION_SECRET, true},
		{"BAH", models.Classification_CLASSIFICATION_SECRET, false},
		{"BLR", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"BEL", models.Classification_CLASSIFICATION_SECRET, false},
		{"BIH", models.Classification_CLASSIFICATION_SECRET, true},
		{"BGR", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"CAN", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"HRV", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"CZE", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"DNK", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"EGY", models.Classification_CLASSIFICATION_SECRET, false},
		{"EST", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"FIN", models.Classification_CLASSIFICATION_SECRET, true},
		{"FRA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"GEO", models.Classification_CLASSIFICATION_SECRET, true},
		{"DEU", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"GRC", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"HUN", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"ISL", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"IRQ", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"IRE", models.Classification_CLASSIFICATION_SECRET, false},
		{"ISR", models.Classification_CLASSIFICATION_SECRET, false},
		{"ITA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"JAP", models.Classification_CLASSIFICATION_SECRET, false},
		{"GBR", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"USA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := &models.Stanag4774{
				Classification: tt.classification,
				ReleasableTo: &models.Stanag4774_Category{
					Type:   models.Stanag4774_Category_CATEGORY_TYPE_PERMISSIVE,
					Values: []string{tt.name, "RESOLUTE SUPPORT"},
				},
			}

			validator := NewStanag4774Validator(validatorConfigPath)

			nation := getNation(tt.name, validator)

			result := validateValueDomain(model, nation)

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestValidateReleasableToDomainValues_RUSSIA(t *testing.T) {
	tests := []struct {
		name           string
		classification models.Classification
		expected       bool
	}{
		{"AFG", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"ALB", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"ALG", models.Classification_CLASSIFICATION_SECRET, false},
		{"ARM", models.Classification_CLASSIFICATION_SECRET, false},
		{"AUS", models.Classification_CLASSIFICATION_SECRET, false},
		{"AUT", models.Classification_CLASSIFICATION_SECRET, false},
		{"AZE", models.Classification_CLASSIFICATION_SECRET, false},
		{"BAH", models.Classification_CLASSIFICATION_SECRET, false},
		{"BLR", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"BEL", models.Classification_CLASSIFICATION_SECRET, false},
		{"BIH", models.Classification_CLASSIFICATION_SECRET, false},
		{"BGR", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"CAN", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"HRV", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"CZE", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"DNK", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"EGY", models.Classification_CLASSIFICATION_SECRET, false},
		{"EST", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"FIN", models.Classification_CLASSIFICATION_SECRET, false},
		{"FRA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"GEO", models.Classification_CLASSIFICATION_SECRET, false},
		{"DEU", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"GRC", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"HUN", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"ISL", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"IRQ", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"IRE", models.Classification_CLASSIFICATION_SECRET, false},
		{"ISR", models.Classification_CLASSIFICATION_SECRET, false},
		{"ITA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"JAP", models.Classification_CLASSIFICATION_SECRET, false},
		{"GBR", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"USA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := &models.Stanag4774{
				Classification: tt.classification,
				ReleasableTo: &models.Stanag4774_Category{
					Type:   models.Stanag4774_Category_CATEGORY_TYPE_PERMISSIVE,
					Values: []string{tt.name, "RUSSIA"},
				},
			}

			validator := NewStanag4774Validator(validatorConfigPath)

			nation := getNation(tt.name, validator)

			result := validateValueDomain(model, nation)

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestValidateReleasableToDomainValues_UKRAINE(t *testing.T) {
	tests := []struct {
		name           string
		classification models.Classification
		expected       bool
	}{
		{"AFG", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"ALB", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"ALG", models.Classification_CLASSIFICATION_SECRET, false},
		{"ARM", models.Classification_CLASSIFICATION_SECRET, false},
		{"AUS", models.Classification_CLASSIFICATION_SECRET, false},
		{"AUT", models.Classification_CLASSIFICATION_SECRET, false},
		{"AZE", models.Classification_CLASSIFICATION_SECRET, false},
		{"BAH", models.Classification_CLASSIFICATION_SECRET, false},
		{"BLR", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"BEL", models.Classification_CLASSIFICATION_SECRET, false},
		{"BIH", models.Classification_CLASSIFICATION_SECRET, false},
		{"BGR", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"CAN", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"HRV", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"CZE", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"DNK", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"EGY", models.Classification_CLASSIFICATION_SECRET, false},
		{"EST", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"FIN", models.Classification_CLASSIFICATION_SECRET, false},
		{"FRA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"GEO", models.Classification_CLASSIFICATION_SECRET, false},
		{"DEU", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"GRC", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"HUN", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"ISL", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"IRQ", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"IRE", models.Classification_CLASSIFICATION_SECRET, false},
		{"ISR", models.Classification_CLASSIFICATION_SECRET, false},
		{"ITA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"JAP", models.Classification_CLASSIFICATION_SECRET, false},
		{"GBR", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"USA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := &models.Stanag4774{
				Classification: tt.classification,
				ReleasableTo: &models.Stanag4774_Category{
					Type:   models.Stanag4774_Category_CATEGORY_TYPE_PERMISSIVE,
					Values: []string{tt.name, "UKRAINE"},
				},
			}

			validator := NewStanag4774Validator(validatorConfigPath)

			nation := getNation(tt.name, validator)

			result := validateValueDomain(model, nation)

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestValidateReleasableToDomainValues_GLOBAL_COALITION(t *testing.T) {
	tests := []struct {
		name           string
		classification models.Classification
		expected       bool
	}{
		{"AFG", models.Classification_CLASSIFICATION_UNCLASSIFIED, true},
		{"ALB", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"ALG", models.Classification_CLASSIFICATION_SECRET, false},
		{"ARM", models.Classification_CLASSIFICATION_SECRET, false},
		{"AUS", models.Classification_CLASSIFICATION_SECRET, true},
		{"AUT", models.Classification_CLASSIFICATION_SECRET, true},
		{"AZE", models.Classification_CLASSIFICATION_SECRET, false},
		{"BAH", models.Classification_CLASSIFICATION_SECRET, true},
		{"BLR", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"BEL", models.Classification_CLASSIFICATION_SECRET, false},
		{"BIH", models.Classification_CLASSIFICATION_SECRET, true},
		{"BGR", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"CAN", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"HRV", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"CZE", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"DNK", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"EGY", models.Classification_CLASSIFICATION_SECRET, true},
		{"EST", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"FIN", models.Classification_CLASSIFICATION_SECRET, true},
		{"FRA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"GEO", models.Classification_CLASSIFICATION_SECRET, true},
		{"DEU", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"GRC", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"HUN", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"ISL", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"IRQ", models.Classification_CLASSIFICATION_UNCLASSIFIED, true},
		{"IRE", models.Classification_CLASSIFICATION_SECRET, false},
		{"ISR", models.Classification_CLASSIFICATION_SECRET, false},
		{"ITA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"JAP", models.Classification_CLASSIFICATION_SECRET, false},
		{"GBR", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"USA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := &models.Stanag4774{
				Classification: tt.classification,
				ReleasableTo: &models.Stanag4774_Category{
					Type:   models.Stanag4774_Category_CATEGORY_TYPE_PERMISSIVE,
					Values: []string{tt.name, "GLOBAL COALITION"},
				},
			}

			validator := NewStanag4774Validator(validatorConfigPath)

			nation := getNation(tt.name, validator)

			result := validateValueDomain(model, nation)

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestValidateReleasableToDomainValues_CFE(t *testing.T) {
	tests := []struct {
		name           string
		classification models.Classification
		expected       bool
	}{
		{"AFG", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"ALB", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"ALG", models.Classification_CLASSIFICATION_SECRET, false},
		{"ARM", models.Classification_CLASSIFICATION_SECRET, true},
		{"AUS", models.Classification_CLASSIFICATION_SECRET, false},
		{"AUT", models.Classification_CLASSIFICATION_SECRET, false},
		{"AZE", models.Classification_CLASSIFICATION_SECRET, true},
		{"BAH", models.Classification_CLASSIFICATION_SECRET, false},
		{"BLR", models.Classification_CLASSIFICATION_UNCLASSIFIED, true},
		{"BEL", models.Classification_CLASSIFICATION_SECRET, false},
		{"BIH", models.Classification_CLASSIFICATION_SECRET, false},
		{"BGR", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"CAN", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"HRV", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"CZE", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"DNK", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"EGY", models.Classification_CLASSIFICATION_SECRET, false},
		{"EST", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"FIN", models.Classification_CLASSIFICATION_SECRET, false},
		{"FRA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"GEO", models.Classification_CLASSIFICATION_SECRET, true},
		{"DEU", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"GRC", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"HUN", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"ISL", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"IRQ", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"IRE", models.Classification_CLASSIFICATION_SECRET, false},
		{"ISR", models.Classification_CLASSIFICATION_SECRET, false},
		{"ITA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"JAP", models.Classification_CLASSIFICATION_SECRET, false},
		{"GBR", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"USA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := &models.Stanag4774{
				Classification: tt.classification,
				ReleasableTo: &models.Stanag4774_Category{
					Type:   models.Stanag4774_Category_CATEGORY_TYPE_PERMISSIVE,
					Values: []string{tt.name, "CFE"},
				},
			}

			validator := NewStanag4774Validator(validatorConfigPath)

			nation := getNation(tt.name, validator)

			result := validateValueDomain(model, nation)

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestValidateReleasableToDomainValues_ICI(t *testing.T) {
	tests := []struct {
		name           string
		classification models.Classification
		expected       bool
	}{
		{"AFG", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"ALB", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"ALG", models.Classification_CLASSIFICATION_SECRET, false},
		{"ARM", models.Classification_CLASSIFICATION_SECRET, false},
		{"AUS", models.Classification_CLASSIFICATION_SECRET, false},
		{"AUT", models.Classification_CLASSIFICATION_SECRET, false},
		{"AZE", models.Classification_CLASSIFICATION_SECRET, false},
		{"BAH", models.Classification_CLASSIFICATION_SECRET, true},
		{"BLR", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"BEL", models.Classification_CLASSIFICATION_SECRET, false},
		{"BIH", models.Classification_CLASSIFICATION_SECRET, false},
		{"BGR", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"CAN", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"HRV", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"CZE", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"DNK", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"EGY", models.Classification_CLASSIFICATION_SECRET, false},
		{"EST", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"FIN", models.Classification_CLASSIFICATION_SECRET, false},
		{"FRA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"GEO", models.Classification_CLASSIFICATION_SECRET, false},
		{"DEU", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"GRC", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"HUN", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"ISL", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"IRQ", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"IRE", models.Classification_CLASSIFICATION_SECRET, false},
		{"ISR", models.Classification_CLASSIFICATION_SECRET, false},
		{"ITA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"JAP", models.Classification_CLASSIFICATION_SECRET, false},
		{"GBR", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"USA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := &models.Stanag4774{
				Classification: tt.classification,
				ReleasableTo: &models.Stanag4774_Category{
					Type:   models.Stanag4774_Category_CATEGORY_TYPE_PERMISSIVE,
					Values: []string{tt.name, "ICI"},
				},
			}

			validator := NewStanag4774Validator(validatorConfigPath)

			nation := getNation(tt.name, validator)

			result := validateValueDomain(model, nation)

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestValidateReleasableToDomainValues_INTEROPERABILITY_PLATFORM(t *testing.T) {
	tests := []struct {
		name           string
		classification models.Classification
		expected       bool
	}{
		{"AFG", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"ALB", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"ALG", models.Classification_CLASSIFICATION_SECRET, false},
		{"ARM", models.Classification_CLASSIFICATION_SECRET, true},
		{"AUS", models.Classification_CLASSIFICATION_SECRET, true},
		{"AUT", models.Classification_CLASSIFICATION_SECRET, true},
		{"AZE", models.Classification_CLASSIFICATION_SECRET, true},
		{"BAH", models.Classification_CLASSIFICATION_SECRET, true},
		{"BLR", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"BEL", models.Classification_CLASSIFICATION_SECRET, false},
		{"BIH", models.Classification_CLASSIFICATION_SECRET, true},
		{"BGR", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"CAN", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"HRV", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"CZE", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"DNK", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"EGY", models.Classification_CLASSIFICATION_SECRET, false},
		{"EST", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"FIN", models.Classification_CLASSIFICATION_SECRET, true},
		{"FRA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"GEO", models.Classification_CLASSIFICATION_SECRET, true},
		{"DEU", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"GRC", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"HUN", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"ISL", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"IRQ", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"IRE", models.Classification_CLASSIFICATION_SECRET, true},
		{"ISR", models.Classification_CLASSIFICATION_SECRET, false},
		{"ITA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"JAP", models.Classification_CLASSIFICATION_SECRET, true},
		{"GBR", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"USA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := &models.Stanag4774{
				Classification: tt.classification,
				ReleasableTo: &models.Stanag4774_Category{
					Type:   models.Stanag4774_Category_CATEGORY_TYPE_PERMISSIVE,
					Values: []string{tt.name, "INTEROPERABILITY PLATFORM"},
				},
			}

			validator := NewStanag4774Validator(validatorConfigPath)

			nation := getNation(tt.name, validator)

			result := validateValueDomain(model, nation)

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestValidateReleasableToDomainValues_MD(t *testing.T) {
	tests := []struct {
		name           string
		classification models.Classification
		expected       bool
	}{
		{"AFG", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"ALB", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"ALG", models.Classification_CLASSIFICATION_SECRET, true},
		{"ARM", models.Classification_CLASSIFICATION_SECRET, false},
		{"AUS", models.Classification_CLASSIFICATION_SECRET, false},
		{"AUT", models.Classification_CLASSIFICATION_SECRET, false},
		{"AZE", models.Classification_CLASSIFICATION_SECRET, false},
		{"BAH", models.Classification_CLASSIFICATION_SECRET, false},
		{"BLR", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"BEL", models.Classification_CLASSIFICATION_SECRET, false},
		{"BIH", models.Classification_CLASSIFICATION_SECRET, false},
		{"BGR", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"CAN", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"HRV", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"CZE", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"DNK", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"EGY", models.Classification_CLASSIFICATION_SECRET, true},
		{"EST", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"FIN", models.Classification_CLASSIFICATION_SECRET, false},
		{"FRA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"GEO", models.Classification_CLASSIFICATION_SECRET, false},
		{"DEU", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"GRC", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"HUN", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"ISL", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"IRQ", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"IRE", models.Classification_CLASSIFICATION_SECRET, false},
		{"ISR", models.Classification_CLASSIFICATION_SECRET, true},
		{"ITA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"JAP", models.Classification_CLASSIFICATION_SECRET, false},
		{"GBR", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"USA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := &models.Stanag4774{
				Classification: tt.classification,
				ReleasableTo: &models.Stanag4774_Category{
					Type:   models.Stanag4774_Category_CATEGORY_TYPE_PERMISSIVE,
					Values: []string{tt.name, "MD"},
				},
			}

			validator := NewStanag4774Validator(validatorConfigPath)

			nation := getNation(tt.name, validator)

			result := validateValueDomain(model, nation)

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestValidateReleasableToDomainValues_NMI(t *testing.T) {
	tests := []struct {
		name           string
		classification models.Classification
		expected       bool
	}{
		{"AFG", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"ALB", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"ALG", models.Classification_CLASSIFICATION_SECRET, false},
		{"ARM", models.Classification_CLASSIFICATION_SECRET, false},
		{"AUS", models.Classification_CLASSIFICATION_SECRET, true},
		{"AUT", models.Classification_CLASSIFICATION_SECRET, false},
		{"AZE", models.Classification_CLASSIFICATION_SECRET, false},
		{"BAH", models.Classification_CLASSIFICATION_SECRET, false},
		{"BLR", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"BEL", models.Classification_CLASSIFICATION_SECRET, false},
		{"BIH", models.Classification_CLASSIFICATION_SECRET, false},
		{"BGR", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"CAN", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"HRV", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"CZE", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"DNK", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"EGY", models.Classification_CLASSIFICATION_SECRET, false},
		{"EST", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"FIN", models.Classification_CLASSIFICATION_SECRET, true},
		{"FRA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"GEO", models.Classification_CLASSIFICATION_SECRET, false},
		{"DEU", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"GRC", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"HUN", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"ISL", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"IRQ", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"IRE", models.Classification_CLASSIFICATION_SECRET, false},
		{"ISR", models.Classification_CLASSIFICATION_SECRET, false},
		{"ITA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"JAP", models.Classification_CLASSIFICATION_SECRET, false},
		{"GBR", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"USA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := &models.Stanag4774{
				Classification: tt.classification,
				ReleasableTo: &models.Stanag4774_Category{
					Type:   models.Stanag4774_Category_CATEGORY_TYPE_PERMISSIVE,
					Values: []string{tt.name, "NMI"},
				},
			}

			validator := NewStanag4774Validator(validatorConfigPath)

			nation := getNation(tt.name, validator)

			result := validateValueDomain(model, nation)

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestValidateReleasableToDomainValues_NATO_RESPONSE_FORCE(t *testing.T) {
	tests := []struct {
		name           string
		classification models.Classification
		expected       bool
	}{
		{"AFG", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"ALB", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"ALG", models.Classification_CLASSIFICATION_SECRET, false},
		{"ARM", models.Classification_CLASSIFICATION_SECRET, false},
		{"AUS", models.Classification_CLASSIFICATION_SECRET, false},
		{"AUT", models.Classification_CLASSIFICATION_SECRET, false},
		{"AZE", models.Classification_CLASSIFICATION_SECRET, false},
		{"BAH", models.Classification_CLASSIFICATION_SECRET, false},
		{"BLR", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"BEL", models.Classification_CLASSIFICATION_SECRET, false},
		{"BIH", models.Classification_CLASSIFICATION_SECRET, false},
		{"BGR", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"CAN", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"HRV", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"CZE", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"DNK", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"EGY", models.Classification_CLASSIFICATION_SECRET, false},
		{"EST", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"FIN", models.Classification_CLASSIFICATION_SECRET, true},
		{"FRA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"GEO", models.Classification_CLASSIFICATION_SECRET, true},
		{"DEU", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"GRC", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"HUN", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"ISL", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"IRQ", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"IRE", models.Classification_CLASSIFICATION_SECRET, false},
		{"ISR", models.Classification_CLASSIFICATION_SECRET, false},
		{"ITA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"JAP", models.Classification_CLASSIFICATION_SECRET, false},
		{"GBR", models.Classification_CLASSIFICATION_TOP_SECRET, false},
		{"USA", models.Classification_CLASSIFICATION_TOP_SECRET, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := &models.Stanag4774{
				Classification: tt.classification,
				ReleasableTo: &models.Stanag4774_Category{
					Type:   models.Stanag4774_Category_CATEGORY_TYPE_PERMISSIVE,
					Values: []string{tt.name, "NATO RESPONSE FORCE"},
				},
			}

			validator := NewStanag4774Validator(validatorConfigPath)

			nation := getNation(tt.name, validator)

			result := validateValueDomain(model, nation)

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestValidateReleasableTo_Success(t *testing.T) {
	tests := []struct {
		name           string
		classification models.Classification
		expected       bool
	}{
		{"AFG", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"ALB", models.Classification_CLASSIFICATION_TOP_SECRET, true},
		{"ALG", models.Classification_CLASSIFICATION_SECRET, false},
		{"ARM", models.Classification_CLASSIFICATION_SECRET, false},
		{"AUS", models.Classification_CLASSIFICATION_SECRET, false},
		{"AUT", models.Classification_CLASSIFICATION_SECRET, false},
		{"AZE", models.Classification_CLASSIFICATION_SECRET, false},
		{"BAH", models.Classification_CLASSIFICATION_SECRET, false},
		{"BLR", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"BEL", models.Classification_CLASSIFICATION_SECRET, true},
		{"BIH", models.Classification_CLASSIFICATION_SECRET, false},
		{"BGR", models.Classification_CLASSIFICATION_TOP_SECRET, true},
		{"CAN", models.Classification_CLASSIFICATION_TOP_SECRET, true},
		{"HRV", models.Classification_CLASSIFICATION_TOP_SECRET, true},
		{"CZE", models.Classification_CLASSIFICATION_TOP_SECRET, true},
		{"DNK", models.Classification_CLASSIFICATION_TOP_SECRET, true},
		{"EGY", models.Classification_CLASSIFICATION_SECRET, false},
		{"EST", models.Classification_CLASSIFICATION_TOP_SECRET, true},
		{"FIN", models.Classification_CLASSIFICATION_SECRET, false},
		{"FRA", models.Classification_CLASSIFICATION_TOP_SECRET, true},
		{"GEO", models.Classification_CLASSIFICATION_SECRET, false},
		{"DEU", models.Classification_CLASSIFICATION_TOP_SECRET, true},
		{"GRC", models.Classification_CLASSIFICATION_TOP_SECRET, true},
		{"HUN", models.Classification_CLASSIFICATION_TOP_SECRET, true},
		{"ISL", models.Classification_CLASSIFICATION_TOP_SECRET, true},
		{"IRQ", models.Classification_CLASSIFICATION_UNCLASSIFIED, false},
		{"IRE", models.Classification_CLASSIFICATION_SECRET, false},
		{"GBR", models.Classification_CLASSIFICATION_TOP_SECRET, true},
		{"USA", models.Classification_CLASSIFICATION_TOP_SECRET, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model := &models.Stanag4774{
				Classification: tt.classification,
				ReleasableTo: &models.Stanag4774_Category{
					Type:   models.Stanag4774_Category_CATEGORY_TYPE_PERMISSIVE,
					Values: []string{tt.name, "NATO"},
				},
			}

			validator := NewStanag4774Validator(validatorConfigPath)

			result := validateReleasableTo(model, validator)

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestValidateNationMask_Success(t *testing.T) {
	validator := NewStanag4774Validator(validatorConfigPath)

	assert.True(t, validateNationMask(getNation("USA", validator), getNation("USA", validator)))
}

func TestValidateNationMask_Failures(t *testing.T) {
	tests := []struct {
		name   string
		nation Nation
	}{
		{"NATO False", Nation{
			Nato:                      false,
			Eapc:                      false,
			Georgia:                   false,
			Kfor:                      false,
			Pfp:                       false,
			Resolute_support:          false,
			Russia:                    false,
			Ukraine:                   false,
			Global_coalition:          false,
			Cfe:                       false,
			Ici:                       false,
			Interoperability_platform: false,
			Md:                        false,
			Nmi:                       false,
			Response_force:            false,
		}},
		{"EAPC True", Nation{
			Nato:                      false,
			Eapc:                      true,
			Georgia:                   false,
			Kfor:                      false,
			Pfp:                       false,
			Resolute_support:          false,
			Russia:                    false,
			Ukraine:                   false,
			Global_coalition:          false,
			Cfe:                       false,
			Ici:                       false,
			Interoperability_platform: false,
			Md:                        false,
			Nmi:                       false,
			Response_force:            false,
		}},
		{"GEORGIA True", Nation{
			Nato:                      false,
			Eapc:                      false,
			Georgia:                   true,
			Kfor:                      false,
			Pfp:                       false,
			Resolute_support:          false,
			Russia:                    false,
			Ukraine:                   false,
			Global_coalition:          false,
			Cfe:                       false,
			Ici:                       false,
			Interoperability_platform: false,
			Md:                        false,
			Nmi:                       false,
			Response_force:            false,
		}},
		{"KFOR True", Nation{
			Nato:                      false,
			Eapc:                      false,
			Georgia:                   false,
			Kfor:                      true,
			Pfp:                       false,
			Resolute_support:          false,
			Russia:                    false,
			Ukraine:                   false,
			Global_coalition:          false,
			Cfe:                       false,
			Ici:                       false,
			Interoperability_platform: false,
			Md:                        false,
			Nmi:                       false,
			Response_force:            false,
		}},
		{"PFP True", Nation{
			Nato:                      false,
			Eapc:                      false,
			Georgia:                   false,
			Kfor:                      false,
			Pfp:                       true,
			Resolute_support:          false,
			Russia:                    false,
			Ukraine:                   false,
			Global_coalition:          false,
			Cfe:                       false,
			Ici:                       false,
			Interoperability_platform: false,
			Md:                        false,
			Nmi:                       false,
			Response_force:            false,
		}},
		{"RESOLUTE SUPPORT True", Nation{
			Nato:                      false,
			Eapc:                      false,
			Georgia:                   false,
			Kfor:                      false,
			Pfp:                       false,
			Resolute_support:          true,
			Russia:                    false,
			Ukraine:                   false,
			Global_coalition:          false,
			Cfe:                       false,
			Ici:                       false,
			Interoperability_platform: false,
			Md:                        false,
			Nmi:                       false,
			Response_force:            false,
		}},
		{"RUSSIA True", Nation{
			Nato:                      false,
			Eapc:                      false,
			Georgia:                   false,
			Kfor:                      false,
			Pfp:                       false,
			Resolute_support:          false,
			Russia:                    true,
			Ukraine:                   false,
			Global_coalition:          false,
			Cfe:                       false,
			Ici:                       false,
			Interoperability_platform: false,
			Md:                        false,
			Nmi:                       false,
			Response_force:            false,
		}},
		{"UKRAINE True", Nation{
			Nato:                      false,
			Eapc:                      false,
			Georgia:                   false,
			Kfor:                      false,
			Pfp:                       false,
			Resolute_support:          false,
			Russia:                    false,
			Ukraine:                   true,
			Global_coalition:          false,
			Cfe:                       false,
			Ici:                       false,
			Interoperability_platform: false,
			Md:                        false,
			Nmi:                       false,
			Response_force:            false,
		}},
		{"GLOBAL COALITION True", Nation{
			Nato:                      false,
			Eapc:                      false,
			Georgia:                   false,
			Kfor:                      false,
			Pfp:                       false,
			Resolute_support:          false,
			Russia:                    false,
			Ukraine:                   false,
			Global_coalition:          true,
			Cfe:                       false,
			Ici:                       false,
			Interoperability_platform: false,
			Md:                        false,
			Nmi:                       false,
			Response_force:            false,
		}},
		{"CFE True", Nation{
			Nato:                      false,
			Eapc:                      false,
			Georgia:                   false,
			Kfor:                      false,
			Pfp:                       false,
			Resolute_support:          false,
			Russia:                    false,
			Ukraine:                   false,
			Global_coalition:          false,
			Cfe:                       true,
			Ici:                       false,
			Interoperability_platform: false,
			Md:                        false,
			Nmi:                       false,
			Response_force:            false,
		}},
		{"ICI True", Nation{
			Nato:                      false,
			Eapc:                      false,
			Georgia:                   false,
			Kfor:                      false,
			Pfp:                       false,
			Resolute_support:          false,
			Russia:                    false,
			Ukraine:                   false,
			Global_coalition:          false,
			Cfe:                       false,
			Ici:                       true,
			Interoperability_platform: false,
			Md:                        false,
			Nmi:                       false,
			Response_force:            false,
		}},
		{"INTEROPERABILITY PLATFORM True", Nation{
			Nato:                      false,
			Eapc:                      false,
			Georgia:                   false,
			Kfor:                      false,
			Pfp:                       false,
			Resolute_support:          false,
			Russia:                    false,
			Ukraine:                   false,
			Global_coalition:          false,
			Cfe:                       false,
			Ici:                       false,
			Interoperability_platform: true,
			Md:                        false,
			Nmi:                       false,
			Response_force:            false,
		}},
		{"MD True", Nation{
			Nato:                      false,
			Eapc:                      false,
			Georgia:                   false,
			Kfor:                      false,
			Pfp:                       false,
			Resolute_support:          false,
			Russia:                    false,
			Ukraine:                   false,
			Global_coalition:          false,
			Cfe:                       false,
			Ici:                       false,
			Interoperability_platform: false,
			Md:                        true,
			Nmi:                       false,
			Response_force:            false,
		}},
		{"NMI True", Nation{
			Nato:                      false,
			Eapc:                      false,
			Georgia:                   false,
			Kfor:                      false,
			Pfp:                       false,
			Resolute_support:          false,
			Russia:                    false,
			Ukraine:                   false,
			Global_coalition:          false,
			Cfe:                       false,
			Ici:                       false,
			Interoperability_platform: false,
			Md:                        false,
			Nmi:                       true,
			Response_force:            false,
		}},
		{"RESPONSE FORCE True", Nation{
			Nato:                      false,
			Eapc:                      false,
			Georgia:                   false,
			Kfor:                      false,
			Pfp:                       false,
			Resolute_support:          false,
			Russia:                    false,
			Ukraine:                   false,
			Global_coalition:          false,
			Cfe:                       false,
			Ici:                       false,
			Interoperability_platform: false,
			Md:                        false,
			Nmi:                       false,
			Response_force:            true,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator := NewStanag4774Validator(validatorConfigPath)

			assert.False(t, validateNationMask(getNation("USA", validator), tt.nation))
		})
	}
}
