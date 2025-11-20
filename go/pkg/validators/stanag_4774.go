package validators

import (
	"errors"
	"github.com/samber/lo"
	"gopkg.in/yaml.v3"
	"log"
	"os"
	"regexp"
	"stratium/pkg/models"
	"strings"
	"unicode"
)

type Stanag4774ParserConfigRegex struct {
	Administrative              string "yaml:administrative"
	Classification              string "yaml:classification"
	Only                        string "yaml:only"
	Releasable_to               string "yaml:releasable_to"
	Special_category_designator string "yaml:special_category_designator"
}

type Stanag4774ParserConfig struct {
	Regex Stanag4774ParserConfigRegex "yaml:regex"
}

type Stanag4774Parser struct {
	Config Stanag4774ParserConfig
}

func NewStanag4774Parser(configFile string) *Stanag4774Parser {
	file, err := os.Open(configFile)
	if err != nil {
		log.Printf("error opening config file: %v", err)
		return nil
	}
	defer file.Close()

	var config Stanag4774ParserConfig
	err = yaml.NewDecoder(file).Decode(&config)
	if err != nil {
		log.Printf("error decoding config file: %v", err)
		return nil
	}

	return &Stanag4774Parser{
		Config: config,
	}
}

func (parser *Stanag4774Parser) Parse(label string, validatorConfig string) *models.Stanag4774 {
	stanag4774 := &models.Stanag4774{}

	stanag4774.PolicyIdentifier = parsePolicyIdentifier(label)

	stanag4774.Context = parseContext(label)

	classification, err := parser.parseClassification(label)
	if err != nil {
		return nil
	}
	stanag4774.Classification = classification

	specialCategoryDesignators, err := parser.parseSpecialCategoryDesignators(label)
	if err != nil {
		return nil
	}
	stanag4774.SpecialCategoryDesignators = specialCategoryDesignators

	administrative, err := parser.parseAdministrative(label)
	if err != nil {
		return nil
	}
	stanag4774.Administrative = administrative

	releasableTo, err := parser.parseReleasableTo(label)
	if err != nil {
		return nil
	}
	stanag4774.ReleasableTo = releasableTo

	only, err := parser.parseOnly(label)
	if err != nil {
		return nil
	}
	stanag4774.Only = only

	if !NewStanag4774Validator(validatorConfig).Validate(stanag4774) {
		return nil
	}

	return stanag4774
}

func parsePolicyIdentifier(label string) string {
	firstWhitespaceIndex := strings.IndexFunc(label, unicode.IsSpace)
	policyIdentifier := label[:firstWhitespaceIndex]
	if strings.Contains(policyIdentifier, "/") {
		slashIndex := strings.Index(policyIdentifier, "/")
		return policyIdentifier[:slashIndex]
	} else {
		return policyIdentifier
	}
}

func parseContext(label string) *models.Stanag4774_Category {
	firstWhitespaceIndex := strings.IndexFunc(label, unicode.IsSpace)
	context := label[:firstWhitespaceIndex]
	if strings.Contains(context, "/") {
		slashIndex := strings.Index(context, "/")
		return &models.Stanag4774_Category{
			Type:   models.Stanag4774_Category_CATEGORY_TYPE_PERMISSIVE,
			Values: []string{context[slashIndex+1:]},
		}
	} else {
		return nil
	}
}

func (parser *Stanag4774Parser) parseClassification(label string) (models.Classification, error) {
	re, err := regexp.Compile(parser.Config.Regex.Classification)
	if err != nil {
		msg := "failed to compile classification expression"
		log.Println(msg)
		return models.Classification_CLASSIFICATION_NONE, errors.New(msg)
	}

	matches := re.FindAllString(label, -1)

	if len(matches) == 1 {
		switch matches[0] {
		case "UNCLASSIFIED":
			return models.Classification_CLASSIFICATION_UNCLASSIFIED, nil
		case "RESTRICTED":
			return models.Classification_CLASSIFICATION_RESTRICTED, nil
		case "CONFIDENTIAL":
			return models.Classification_CLASSIFICATION_CONFIDENTIAL, nil
		case "SECRET":
			return models.Classification_CLASSIFICATION_SECRET, nil
		case "TOP SECRET":
			return models.Classification_CLASSIFICATION_TOP_SECRET, nil
		}
	}

	log.Println("failed to parse classification")
	return models.Classification_CLASSIFICATION_NONE, nil
}

func (parser *Stanag4774Parser) parseSpecialCategoryDesignators(label string) ([]models.SpecialCategoryDesignator, error) {
	re, err := regexp.Compile(parser.Config.Regex.Special_category_designator)
	if err != nil {
		msg := "failed to compile special category designator expression"
		log.Println(msg)
		return []models.SpecialCategoryDesignator{models.SpecialCategoryDesignator_DESIGNATOR_NONE}, errors.New(msg)
	}

	matches := re.FindAllString(label, -1)

	if len(matches) == 1 {
		splits := strings.Split(matches[0][3:], ",")
		specialCategoryDesignators := []models.SpecialCategoryDesignator{}

		for _, check := range splits {
			switch check {
			case "ATOMAL":
				specialCategoryDesignators = append(specialCategoryDesignators, models.SpecialCategoryDesignator_DESIGNATOR_ATOMAL)
			case "BOHEMIA":
				specialCategoryDesignators = append(specialCategoryDesignators, models.SpecialCategoryDesignator_DESIGNATOR_BOHEMIA)
			case "CRYPTO":
				specialCategoryDesignators = append(specialCategoryDesignators, models.SpecialCategoryDesignator_DESIGNATOR_CRYPTO)
			case "SIOP":
				specialCategoryDesignators = append(specialCategoryDesignators, models.SpecialCategoryDesignator_DESIGNATOR_SIOP)
			}
		}

		return specialCategoryDesignators, nil
	}

	log.Println("failed to parse special category designator")
	return []models.SpecialCategoryDesignator{models.SpecialCategoryDesignator_DESIGNATOR_NONE}, nil
}

func (parser *Stanag4774Parser) parseAdministrative(label string) (models.Administrative, error) {
	re, err := regexp.Compile(parser.Config.Regex.Administrative)
	if err != nil {
		msg := "failed to compile administrative expression"
		log.Println(msg)
		return models.Administrative_ADMINISTRATIVE_NONE, errors.New(msg)
	}

	matches := re.FindAllString(label, -1)

	if len(matches) == 1 {
		check := matches[0][3:]
		switch check {
		case "COMMERCIAL":
			return models.Administrative_ADMINISTRATIVE_COMMERCIAL, nil
		case "MANAGEMENT":
			return models.Administrative_ADMINISTRATIVE_MANAGEMENT, nil
		case "MEDICAL":
			return models.Administrative_ADMINISTRATIVE_MEDICAL, nil
		case "PERSONAL":
			return models.Administrative_ADMINISTRATIVE_PERSONAL, nil
		case "STAFF":
			return models.Administrative_ADMINISTRATIVE_STAFF, nil
		}
	}

	log.Println("failed to parse administrative")
	return models.Administrative_ADMINISTRATIVE_NONE, nil
}

func (parser *Stanag4774Parser) parseReleasableTo(label string) (*models.Stanag4774_Category, error) {
	re, err := regexp.Compile(parser.Config.Regex.Releasable_to)
	if err != nil {
		msg := "failed to compile releasable to expression"
		log.Println(msg)
		return nil, errors.New(msg)
	}

	matches := re.FindAllString(label, -1)

	if matches == nil {
		return nil, nil
	}

	index := strings.Index(label, matches[0])

	subLabel := label[index+len(matches[0]):]

	values := strings.Split(subLabel, ",")

	lo.ForEach(values, func(value string, idx int) {
		values[idx] = strings.TrimSpace(value)
	})

	category := &models.Stanag4774_Category{
		Type:   models.Stanag4774_Category_CATEGORY_TYPE_PERMISSIVE,
		Values: values,
	}
	return category, nil
}

func (parser *Stanag4774Parser) parseOnly(label string) (*models.Stanag4774_Category, error) {
	re, err := regexp.Compile(parser.Config.Regex.Only)
	if err != nil {
		msg := "failed to compile only expression"
		log.Println(msg)
		return nil, errors.New(msg)
	}

	matches := re.FindAllString(label, -1)

	if matches == nil {
		return nil, errors.New("failed to find only tag")
	}

	index := strings.Index(label, matches[0])
	newLabel := label[index:]
	onlyIndex := strings.Index(newLabel, "Only")

	if index == -1 || onlyIndex == -1 {
		return nil, nil
	}

	subLabel := newLabel[len(matches[0]):onlyIndex]

	values := strings.Split(subLabel, ",")

	lo.ForEach(values, func(value string, idx int) {
		values[idx] = strings.TrimSpace(value)
	})

	category := &models.Stanag4774_Category{
		Type:   models.Stanag4774_Category_CATEGORY_TYPE_PERMISSIVE,
		Values: values,
	}

	return category, nil
}

type Nation struct {
	Name                      string "yaml:name"
	Full_name                 string "yaml:full_name"
	Classification            string "yaml:classification"
	Nato                      bool   "yaml:nato"
	Eapc                      bool   "yaml:eapc"
	Georgia                   bool   "yaml:georgia"
	Kfor                      bool   "yaml:kfor"
	Pfp                       bool   "yaml:pfp"
	Resolute_support          bool   "yaml:resolute_support"
	Russia                    bool   "yaml:russia"
	Ukraine                   bool   "yaml:ukraine"
	Global_coalition          bool   "yaml:global_coalition"
	Cfe                       bool   "yaml:cfe"
	Ici                       bool   "yaml:ici"
	Interoperability_platform bool   "yaml:interoperability_platform"
	Md                        bool   "yaml:md"
	Nmi                       bool   "yaml:nmi"
	Response_force            bool   "yaml:response_force"
}

type Stanag4774Validator struct {
	Contexts []string "yaml:contexts"
	Nations  []Nation "yaml:nations"
}

func NewStanag4774Validator(configFile string) *Stanag4774Validator {
	file, err := os.Open(configFile)
	if err != nil {
		log.Printf("error opening config file: %v", err)
		return nil
	}
	defer file.Close()

	var validator Stanag4774Validator
	err = yaml.NewDecoder(file).Decode(&validator)
	if err != nil {
		log.Printf("error decoding config file: %v", err)
		return nil
	}

	return &validator
}

func (validator *Stanag4774Validator) Validate(model *models.Stanag4774) bool {
	valid := validateContext(model, validator)
	//valid = valid && validateReleasableTo(model, validator)
	valid = valid && validateSpecialCategoryDesignators(model)
	valid = valid && validateAdministrative(model)
	return valid
}

func validateContext(model *models.Stanag4774, validator *Stanag4774Validator) bool {
	return model.GetContext() == nil || lo.Contains(validator.Contexts, model.GetContext().GetValues()[0])
}

func validateReleasableTo(model *models.Stanag4774, validator *Stanag4774Validator) bool {
	valid := true

	releasableNations := []Nation{}

	lo.ForEach(model.GetReleasableTo().GetValues(), func(value string, idx int) {
		if getNation(value, validator).Name != "" {
			releasableNations = append(releasableNations, getNation(value, validator))
		}
	})

	for _, nation := range releasableNations {
		valid = valid && validateValueDomain(model, nation)
	}

	return valid
}

func getNation(valueDomain string, validator *Stanag4774Validator) Nation {
	nation, _ := lo.Find(validator.Nations, func(n Nation) bool {
		return n.Name == valueDomain
	})

	if nation.Name == "" {
		nation, _ = lo.Find(validator.Nations, func(n Nation) bool {
			return n.Full_name == valueDomain
		})
	}

	return nation
}

func validateContextValueDomain(model *models.Stanag4774, nation Nation) bool {
	validPolicyIdentifier := model.PolicyIdentifier == "NATO"
	if !validPolicyIdentifier {
		return false
	}

	validClassification := validateClassification(model.Classification, nation.Classification)
	if !validClassification {
		return false
	}

	for _, context := range model.GetContext().GetValues() {
		switch context {
		case "NATO":
			if !nation.Nato {
				return false
			}
		case "EAPC":
			if !nation.Eapc {
				return false
			}
		case "GEORGIA":
			if !nation.Georgia {
				return false
			}
		case "KFOR":
			if !nation.Kfor {
				return false
			}
		case "PFP":
			if !nation.Pfp {
				return false
			}
		case "RESOLUTE SUPPORT":
			if !nation.Resolute_support {
				return false
			}
		case "RUSSIA":
			if !nation.Russia {
				return false
			}
		case "UKRAINE":
			if !nation.Ukraine {
				return false
			}
		}
	}

	return true
}

func validateNationMask(nation Nation, maskNation Nation) bool {
	return nation.Nato == maskNation.Nato &&
		nation.Eapc == maskNation.Eapc &&
		nation.Georgia == maskNation.Georgia &&
		nation.Kfor == maskNation.Kfor &&
		nation.Pfp == maskNation.Pfp &&
		nation.Resolute_support == maskNation.Resolute_support &&
		nation.Russia == maskNation.Russia &&
		nation.Ukraine == maskNation.Ukraine &&
		nation.Global_coalition == maskNation.Global_coalition &&
		nation.Cfe == maskNation.Cfe &&
		nation.Ici == maskNation.Ici &&
		nation.Interoperability_platform == maskNation.Interoperability_platform &&
		nation.Md == maskNation.Md &&
		nation.Nmi == maskNation.Nmi &&
		nation.Response_force == maskNation.Response_force
}

func validateValueDomain(model *models.Stanag4774, nation Nation) bool {
	validClassification := validateClassification(model.Classification, nation.Classification)
	if !validClassification {
		return false
	}

	for _, releasableTo := range model.GetReleasableTo().GetValues() {
		switch releasableTo {
		case "NATO":
			if !nation.Nato {
				return false
			}
		case "EAPC":
			if !nation.Eapc {
				return false
			}
		case "GEORGIA":
			if !nation.Georgia {
				return false
			}
		case "KFOR":
			if !nation.Kfor {
				return false
			}
		case "PFP":
			if !nation.Pfp {
				return false
			}
		case "RESOLUTE SUPPORT":
			if !nation.Resolute_support {
				return false
			}
		case "RUSSIA":
			if !nation.Russia {
				return false
			}
		case "UKRAINE":
			if !nation.Ukraine {
				return false
			}
		case "GLOBAL COALITION":
			if !nation.Global_coalition {
				return false
			}
		case "CFE":
			if !nation.Cfe {
				return false
			}
		case "ICI":
			if !nation.Ici {
				return false
			}
		case "INTEROPERABILITY PLATFORM":
			if !nation.Interoperability_platform {
				return false
			}
		case "MD":
			if !nation.Md {
				return false
			}
		case "NMI":
			if !nation.Nmi {
				return false
			}
		case "NATO RESPONSE FORCE":
			if !nation.Response_force {
				return false
			}
		}
	}

	return true
}

func validateClassification(classification models.Classification, nationClassification string) bool {
	switch classification {
	case models.Classification_CLASSIFICATION_CONFIDENTIAL:
		fallthrough
	case models.Classification_CLASSIFICATION_RESTRICTED:
		fallthrough
	case models.Classification_CLASSIFICATION_UNCLASSIFIED:
		return lo.Contains([]string{"U", "S", "CTS"}, nationClassification)
	case models.Classification_CLASSIFICATION_SECRET:
		return lo.Contains([]string{"S", "CTS"}, nationClassification)
	case models.Classification_CLASSIFICATION_TOP_SECRET:
		return lo.Contains([]string{"CTS"}, nationClassification)
	default:
		return false
	}
}

func validateSpecialCategoryDesignators(model *models.Stanag4774) bool {
	if len(model.GetSpecialCategoryDesignators()) == 1 && model.GetSpecialCategoryDesignators()[0] == models.SpecialCategoryDesignator_DESIGNATOR_NONE {
		return true
	}

	valid := true

	for _, designator := range model.GetSpecialCategoryDesignators() {
		switch designator {
		case models.SpecialCategoryDesignator_DESIGNATOR_BOHEMIA:
			v := model.GetClassification() == models.Classification_CLASSIFICATION_TOP_SECRET
			if !v {
				log.Printf("failed to validate special category designator(%s) for %s: 44\n", designator, model.GetClassification())
			}
			valid = valid && v
		case models.SpecialCategoryDesignator_DESIGNATOR_ATOMAL:
			v := model.GetClassification() == models.Classification_CLASSIFICATION_CONFIDENTIAL
			if !v {
				log.Printf("failed to validate special category designator(%s) for %s: 43\n", designator, model.GetClassification())
			}
			valid = valid && v
		case models.SpecialCategoryDesignator_DESIGNATOR_CRYPTO:
			v := model.GetClassification() == models.Classification_CLASSIFICATION_CONFIDENTIAL
			if !v {
				log.Printf("failed to validate special category designator(%s) for %s: 45\n", designator, model.GetClassification())
			}
			valid = valid && v
		case models.SpecialCategoryDesignator_DESIGNATOR_SIOP:
			v := model.GetClassification() == models.Classification_CLASSIFICATION_CONFIDENTIAL
			if !v {
				log.Printf("failed to validate special category designator(%s) for %s: 46\n", designator, model.GetClassification())
			}
			valid = valid && v
		}
	}

	return valid
}

func validateAdministrative(model *models.Stanag4774) bool {
	if model.Administrative == models.Administrative_ADMINISTRATIVE_NONE {
		return true
	}

	return model.Administrative != models.Administrative_ADMINISTRATIVE_NONE && len(model.GetReleasableTo().GetValues()) == 0 && len(model.GetOnly().GetValues()) == 0
}
