package xacml

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"stratium/internal/policy"
	"stratium/pkg/models"
)

// The fixed AttributeDesignator vocabulary this engine understands — see
// the package doc's "Attribute designators" section for the full mapping
// and the reasoning behind it. subjectAttrPrefix and resourceAttrPrefix are
// the open forms: any AttributeId starting with one of these prefixes names
// an arbitrary key in the corresponding EvaluationInput map, the same
// "attr" openness jsonpolicy's subject.attr has, extended to resource for
// the same reason (both Principal.Attributes and Resource are tenant-
// supplied free-form maps with no fixed field set to enumerate).
const (
	attrSubjectID         = "subject-id"
	attrResourceID        = "resource-id"
	attrActionID          = "action-id"
	attrAgentTrustTier    = "agent-trust-tier"
	attrDelegationPurpose = "delegation-purpose"
	attrDelegationMaxTier = "delegation-max-tier"
	attrDerivedTier       = "derived-tier"

	subjectAttrPrefix  = "subject:"
	resourceAttrPrefix = "resource:"
)

// The four standard XACML 3.0 attribute-category URNs. Every
// AttributeDesignator's Category must equal the one categoryFor derives
// from its AttributeId — review found this engine accepted Category as an
// unchecked attribute, which is exactly the "reads as configurable, isn't
// really checked" failure this package exists to close off, one level
// below an outright unsupported construct: a designator whose Category
// disagrees with its own AttributeId (a subject attribute labeled with the
// resource category, say) still resolves and compares correctly today,
// since resolveAttr dispatches on AttributeId alone and never reads
// Category — but nothing stops the value from becoming semantically
// meaningless to a human or a future consumer of this text, and a
// generic-purpose XACML authoring tool emits Category unconditionally, so
// silently ignoring it would make this engine reject some schema-valid
// documents (see Important 3, engine.go's package doc) while quietly
// mis-recording others.
const (
	categorySubject     = "urn:oasis:names:tc:xacml:1.0:subject-category:access-subject"
	categoryResource    = "urn:oasis:names:tc:xacml:3.0:attribute-category:resource"
	categoryAction      = "urn:oasis:names:tc:xacml:3.0:attribute-category:action"
	categoryEnvironment = "urn:oasis:names:tc:xacml:3.0:attribute-category:environment"
)

// categoryFor returns the Category an AttributeDesignator naming
// attributeID must carry. subject-id and subject:<key> are the access-
// subject category; resource-id and resource:<key> are the resource
// category; action-id is the action category. The four Stratium-specific
// dimensions (agent-trust-tier, derived-tier, and the two delegation
// designators) have no natural home in subject/resource/action — none of
// them describe the subject, the resource, or the action itself, they
// describe the surrounding circumstances of the request — so they take
// the environment category, XACML's own catch-all for exactly that kind
// of contextual attribute. Called only after attributeIDKnown has already
// confirmed attributeID is one this engine recognizes; an unknown id
// reaching this function is a caller bug, not a case this function itself
// guards against.
func categoryFor(attributeID string) string {
	switch {
	case attributeID == attrSubjectID, strings.HasPrefix(attributeID, subjectAttrPrefix):
		return categorySubject
	case attributeID == attrResourceID, strings.HasPrefix(attributeID, resourceAttrPrefix):
		return categoryResource
	case attributeID == attrActionID:
		return categoryAction
	default:
		return categoryEnvironment
	}
}

// agentTrustTierValues and actionTierValues are the closed vocabularies an
// AttributeValue compared against a tier-valued designator must belong to
// — agent-trust-tier reads models.AgentTrustTier.String(); derived-tier
// and delegation-max-tier both read models.ActionTier.String() (see
// resolveAttr). Built by calling each enum member's own String() rather
// than copying its spelling as a second literal, so a future tier added to
// either enum is picked up here automatically instead of this vocabulary
// silently going stale relative to models' own definition — review found
// this check missing entirely: "Certified", "3", "EXTERNAL-COMMS", and
// "READONLY" all validated and prepared cleanly, and could never match any
// value resolveAttr actually produces, the same defect BASE commit 6abf998
// fixed for jsonpolicy one commit before this engine existed.
var (
	agentTrustTierValues = []string{
		models.TrustTierUnverified.String(), models.TrustTierRegistered.String(),
		models.TrustTierCertified.String(), models.TrustTierPlatformTrusted.String(),
	}
	actionTierValues = []string{
		models.ActionTierReasoning.String(), models.ActionTierReadOnly.String(),
		models.ActionTierInternalModify.String(), models.ActionTierExternalComms.String(),
		models.ActionTierDestructive.String(),
	}
)

// xmlPolicy is the root element's typed shape — the values parseAndValidate
// extracts once validateStructure has already confirmed the document uses
// no unsupported element or attribute name anywhere. Every field below is a
// literal transcription of the package doc's grammar, not an approximation
// of it.
type xmlPolicy struct {
	PolicyID           string     `xml:"PolicyId,attr"`
	RuleCombiningAlgID string     `xml:"RuleCombiningAlgId,attr"`
	Target             *xmlTarget `xml:"Target"`
	Rules              []xmlRule  `xml:"Rule"`
}

// validate checks the semantic constraints validateStructure's element/
// attribute whitelist cannot express by itself: exact values,
// cardinalities, and the closed AttributeId vocabulary. Called once, from
// parseAndValidate, after both validateStructure and xml.Unmarshal have
// already succeeded.
func (p xmlPolicy) validate() error {
	if p.PolicyID == "" {
		return errors.New("policy is missing its required PolicyId attribute")
	}
	if p.RuleCombiningAlgID != ruleCombiningAlgDenyOverrides {
		return fmt.Errorf("policy's RuleCombiningAlgId %q is not supported — only %q is (permit-overrides and every other algorithm are rejected: see the package doc's \"rule combining\" section)", p.RuleCombiningAlgID, ruleCombiningAlgDenyOverrides)
	}
	if err := p.Target.validate(); err != nil {
		return fmt.Errorf("policy target: %w", err)
	}
	if len(p.Rules) == 0 {
		return errors.New("policy has zero Rule elements — at least one is required (a Policy with none can never produce a verdict for any request)")
	}
	for i, r := range p.Rules {
		if err := r.validate(); err != nil {
			return fmt.Errorf("policy rule[%d] (%s): %w", i, r.RuleID, err)
		}
	}
	return nil
}

// xmlRule is one <Rule>. Target is a pointer, distinct from xmlPolicy's own
// Target field only in that Go requires a pointer either way to
// distinguish "absent" from "present but empty" — both Policy- and
// Rule-level Target share the identical optional-and-possibly-empty
// semantics (see (*xmlTarget).evaluate).
type xmlRule struct {
	RuleID string     `xml:"RuleId,attr"`
	Effect string     `xml:"Effect,attr"`
	Target *xmlTarget `xml:"Target"`
}

func (r xmlRule) validate() error {
	if r.RuleID == "" {
		return errors.New("rule is missing its required RuleId attribute")
	}
	if r.Effect != effectPermit && r.Effect != effectDeny {
		return fmt.Errorf("rule's Effect must be %q or %q, got %q", effectPermit, effectDeny, r.Effect)
	}
	if err := r.Target.validate(); err != nil {
		return fmt.Errorf("rule target: %w", err)
	}
	return nil
}

// xmlTarget is <Target>, at either Policy or Rule level. A nil *xmlTarget
// (the element absent) and a non-nil one with zero AnyOf (the element
// present but empty, <Target/>) are two different XML shapes that mean the
// identical thing — see (*xmlTarget).evaluate — so validate does not need
// to, and does not, tell them apart.
type xmlTarget struct {
	AnyOf []xmlAnyOf `xml:"AnyOf"`
}

// validate is a pointer receiver so a nil *xmlTarget — Target entirely
// absent, the common case for an unconditional Rule — validates as
// trivially fine without its caller needing a separate nil check first.
func (t *xmlTarget) validate() error {
	if t == nil {
		return nil
	}
	for i, a := range t.AnyOf {
		if err := a.validate(); err != nil {
			return fmt.Errorf("at AnyOf[%d]: %w", i, err)
		}
	}
	return nil
}

// xmlAnyOf is <AnyOf>. Real XACML's own schema requires at least one AllOf
// per AnyOf (unlike Target, which may legitimately be empty — see the
// package doc); this engine holds that same line rather than inventing a
// meaning XACML itself does not define for an empty disjunction.
type xmlAnyOf struct {
	AllOf []xmlAllOf `xml:"AllOf"`
}

func (a xmlAnyOf) validate() error {
	if len(a.AllOf) == 0 {
		return errors.New("at least one AllOf is required (an AnyOf with none has no defined meaning in XACML and can never match)")
	}
	for i, all := range a.AllOf {
		if err := all.validate(); err != nil {
			return fmt.Errorf("at AllOf[%d]: %w", i, err)
		}
	}
	return nil
}

// xmlAllOf is <AllOf>. Same reasoning as xmlAnyOf: at least one Match is
// required, matching real XACML's own schema cardinality.
type xmlAllOf struct {
	Match []xmlMatch `xml:"Match"`
}

func (a xmlAllOf) validate() error {
	if len(a.Match) == 0 {
		return errors.New("at least one Match is required (an AllOf with none has no defined meaning in XACML and can never match)")
	}
	for i, m := range a.Match {
		if err := m.validate(); err != nil {
			return fmt.Errorf("at Match[%d]: %w", i, err)
		}
	}
	return nil
}

// xmlMatch is <Match>: one string-equal comparison between a literal
// AttributeValue and whatever an AttributeDesignator resolves to against a
// real request. validateStructure has already guaranteed exactly these two
// children exist (an AttributeSelector, XACML's XPath-based alternative to
// AttributeDesignator, is not in grammar's allowed-children set for Match
// and so is rejected before this type is ever populated) — validate here
// checks the values those two children carry, not their shape.
type xmlMatch struct {
	MatchID    string                 `xml:"MatchId,attr"`
	Value      xmlAttributeValue      `xml:"AttributeValue"`
	Designator xmlAttributeDesignator `xml:"AttributeDesignator"`
}

func (m xmlMatch) validate() error {
	if m.MatchID != matchIDStringEqual {
		return fmt.Errorf("match's MatchId %q is not supported — only %q is (string equality only; no other function, including near-miss variants like ignore-case matching)", m.MatchID, matchIDStringEqual)
	}
	if m.Value.DataType != dataTypeString {
		return fmt.Errorf("match's AttributeValue DataType %q is not supported — only %q is", m.Value.DataType, dataTypeString)
	}
	if m.Designator.DataType != dataTypeString {
		return fmt.Errorf("match's AttributeDesignator DataType %q is not supported — only %q is", m.Designator.DataType, dataTypeString)
	}
	// xs:string preserves surrounding whitespace verbatim, so
	// "<AttributeValue>\n  alice\n</AttributeValue>" (the natural result of
	// writing XML across multiple lines, the one authoring style every
	// fixture in this package used to write inline as ">value<" to avoid)
	// compares against "\n  alice\n", never "alice" — a rule that reads as
	// comparing against alice and can never actually match alice. Rejecting
	// the padded form, by name, is the same "reject anything that reads as
	// configurable but isn't" instinct behind rejecting an empty "in" list
	// in jsonpolicy; the comparison semantics themselves are untouched.
	if trimmed := strings.TrimSpace(m.Value.Text); trimmed != m.Value.Text {
		return fmt.Errorf("match's AttributeValue %q has leading or trailing whitespace, which xs:string preserves verbatim — it can never equal the value %q an author most likely intended; write it inline with no surrounding whitespace", m.Value.Text, trimmed)
	}
	if m.Designator.AttributeID == "" {
		return errors.New("match's AttributeDesignator is missing its required AttributeId attribute")
	}
	if !attributeIDKnown(m.Designator.AttributeID) {
		return fmt.Errorf("match's AttributeDesignator has unknown AttributeId %q — see the package doc for the complete supported list", m.Designator.AttributeID)
	}
	if want := categoryFor(m.Designator.AttributeID); m.Designator.Category != want {
		return fmt.Errorf("match's AttributeDesignator has Category %q, want %q for AttributeId %q", m.Designator.Category, want, m.Designator.AttributeID)
	}
	// Three of the seven designators have a closed value space of their
	// own (see resolveAttr): agent-trust-tier reads an AgentTrustTier,
	// derived-tier and delegation-max-tier both read an ActionTier. A
	// value outside that enum's real String() spellings — a typo, a wrong
	// case, an ordinal digit instead of the name — validates as an
	// ordinary string comparison and can never match anything resolveAttr
	// actually produces.
	switch m.Designator.AttributeID {
	case attrAgentTrustTier:
		if !slices.Contains(agentTrustTierValues, m.Value.Text) {
			return fmt.Errorf("match's AttributeValue %q is not a valid agent-trust-tier — must be one of %s", m.Value.Text, strings.Join(agentTrustTierValues, ", "))
		}
	case attrDerivedTier, attrDelegationMaxTier:
		if !slices.Contains(actionTierValues, m.Value.Text) {
			return fmt.Errorf("match's AttributeValue %q is not a valid %s — must be one of %s", m.Value.Text, m.Designator.AttributeID, strings.Join(actionTierValues, ", "))
		}
	}
	return nil
}

// xmlAttributeValue is <AttributeValue>: a DataType attribute plus the
// literal string to compare, carried as element text content.
type xmlAttributeValue struct {
	DataType string `xml:"DataType,attr"`
	Text     string `xml:",chardata"`
}

// xmlAttributeDesignator is <AttributeDesignator>: a leaf element (always
// self-closed) naming which EvaluationInput dimension to read. Category is
// required and checked against categoryFor(AttributeID) in
// (xmlMatch).validate, not merely accepted — see categoryFor's own doc
// comment for why an unchecked Category would be a silent-drift risk of
// its own.
type xmlAttributeDesignator struct {
	AttributeID string `xml:"AttributeId,attr"`
	DataType    string `xml:"DataType,attr"`
	Category    string `xml:"Category,attr"`
}

// attributeIDKnown reports whether id is an AttributeId this engine
// understands — the fixed vocabulary the package doc lists, plus the open
// subject:/resource: prefixes. It is a pure name check with no
// EvaluationInput involved: unlike resolveAttr's ok return (which answers
// "does *this* request carry a value here"), attributeIDKnown answers "does
// this engine have any idea what to do with this AttributeId at all,"
// which is what validate needs to catch a typo at authoring time, before
// any request exists to evaluate it against.
func attributeIDKnown(id string) bool {
	switch id {
	case attrSubjectID, attrResourceID, attrActionID, attrAgentTrustTier, attrDelegationPurpose, attrDelegationMaxTier, attrDerivedTier:
		return true
	}
	// len(id) > len(prefix), not merely HasPrefix: a bare "subject:" or
	// "resource:" with nothing after the colon has the right shape but
	// names no key at all — Principal.Attributes[""] / Resource[""] can
	// never be what an author meant, and unlike a typo'd real key (which
	// fails only in the safe direction, never matching), an empty key is
	// permanently dead by construction, the same defect class as an empty
	// "in" list. Review found this: the old HasPrefix-only check accepted
	// it.
	if strings.HasPrefix(id, subjectAttrPrefix) {
		return len(id) > len(subjectAttrPrefix)
	}
	if strings.HasPrefix(id, resourceAttrPrefix) {
		return len(id) > len(resourceAttrPrefix)
	}
	return false
}

// resolveAttr reads attributeID's value out of in. ok is false exactly when
// attributeID names a key in one of EvaluationInput's free-form maps
// (Principal.Attributes or Resource) that in does not carry — see the
// package doc's "Indeterminate" section for why only those two dimensions
// can ever fail to resolve, and what this engine does when one does.
func resolveAttr(in policy.EvaluationInput, attributeID string) (value string, ok bool) {
	switch {
	case attributeID == attrSubjectID:
		return in.Principal.Subject, true
	case attributeID == attrActionID:
		return in.Action.Tool, true
	case attributeID == attrAgentTrustTier:
		return in.Agent.TrustTier.String(), true
	case attributeID == attrDelegationPurpose:
		return in.Delegation.Purpose, true
	case attributeID == attrDelegationMaxTier:
		return in.Delegation.MaxActionTier.String(), true
	case attributeID == attrDerivedTier:
		return in.DerivedTier.String(), true
	case attributeID == attrResourceID:
		v, ok := in.Resource["id"]
		return v, ok
	case strings.HasPrefix(attributeID, subjectAttrPrefix):
		v, ok := in.Principal.Attributes[strings.TrimPrefix(attributeID, subjectAttrPrefix)]
		return v, ok
	case strings.HasPrefix(attributeID, resourceAttrPrefix):
		v, ok := in.Resource[strings.TrimPrefix(attributeID, resourceAttrPrefix)]
		return v, ok
	default:
		// Unreachable for any policy this engine's own Validate accepted —
		// attributeIDKnown rejects every other AttributeId at authoring
		// time. Kept fail-closed (Indeterminate, not a panic) rather than
		// trusting that invariant to hold, the same defensive posture
		// jsonpolicy's agentAttrValue documents for its own default case.
		return "", false
	}
}
