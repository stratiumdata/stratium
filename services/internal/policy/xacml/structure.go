package xacml

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

// elementRule is what validateStructure allows one element name to contain:
// which child element names may appear inside it, and which attribute
// names it may carry. A name — element or attribute — absent from the
// relevant set is rejected, by that name, wherever it is found.
type elementRule struct {
	children map[string]bool
	attrs    map[string]bool
}

// grammar is the complete, closed list of element names this engine
// understands and what each may contain — the structural half of "the
// supported subset" documented in the package doc. An element name absent
// from this map entirely (Condition, ObligationExpressions,
// AdviceExpressions, PolicySet, PolicyIdReference, PolicySetIdReference,
// VariableDefinition, AttributeSelector, Apply, Function, ...) can never
// appear anywhere in a document validateStructure accepts, regardless of
// where it is nested — see validateStructure for how that is enforced.
//
// This is the mechanism that stands in for encoding/json's
// DisallowUnknownFields: encoding/xml has no built-in "reject anything I
// don't have a struct field for" mode, so xml.Unmarshal alone would
// silently drop an unrecognized element or attribute rather than error on
// it — exactly the accept-and-ignore failure this task's brief names as
// its defining risk. grammar plus validateStructure is this package's own
// version of that strictness, applied before any typed unmarshal runs.
var grammar = map[string]elementRule{
	"Policy": {
		children: map[string]bool{"Target": true, "Rule": true},
		attrs:    map[string]bool{"PolicyId": true, "RuleCombiningAlgId": true},
	},
	"Rule": {
		children: map[string]bool{"Target": true},
		attrs:    map[string]bool{"RuleId": true, "Effect": true},
	},
	"Target": {
		children: map[string]bool{"AnyOf": true},
		attrs:    map[string]bool{},
	},
	"AnyOf": {
		children: map[string]bool{"AllOf": true},
		attrs:    map[string]bool{},
	},
	"AllOf": {
		children: map[string]bool{"Match": true},
		attrs:    map[string]bool{},
	},
	"Match": {
		children: map[string]bool{"AttributeValue": true, "AttributeDesignator": true},
		attrs:    map[string]bool{"MatchId": true},
	},
	"AttributeValue": {
		children: map[string]bool{}, // leaf: text content only
		attrs:    map[string]bool{"DataType": true},
	},
	"AttributeDesignator": {
		children: map[string]bool{}, // leaf: always empty (<.../>)
		attrs:    map[string]bool{"AttributeId": true, "DataType": true},
	},
}

// validateStructure walks text's raw token stream and confirms every
// element and attribute name in it is one grammar recognizes, in a
// position grammar allows. It is the first step of parseAndValidate,
// deliberately run before any typed unmarshal: rejecting an unsupported
// construct here means it is named in the error and never reaches a Go
// value at all, rather than being silently dropped by a struct tag that
// has no field for it.
//
// A namespace on the document (a real-world XACML document's usual
// xmlns="urn:oasis:names:tc:xacml:3.0:core:schema:wd-17") is accepted but
// not required or inspected: every element and attribute name below is
// matched on its local name only, the same matching xml.Unmarshal itself
// performs against an unprefixed struct tag such as `xml:"Policy"`. This
// engine does not use namespace to distinguish one meaning of "Policy"
// from another, so there is nothing namespace-qualified for a stricter
// check to buy.
func validateStructure(text string) error {
	dec := xml.NewDecoder(strings.NewReader(text))

	var stack []string
	rootSeen := false
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("parse: %w", err)
		}

		switch t := tok.(type) {
		case xml.StartElement:
			name := t.Name.Local
			if len(stack) == 0 {
				// A second top-level element after the first has already
				// closed is content with no single attributable meaning —
				// the XML analogue of jsonpolicy's parseDoc rejecting
				// trailing JSON after one value: a StoredPolicy is one
				// policy, not "the first element, ignoring the rest."
				if rootSeen {
					return fmt.Errorf("unexpected content after the policy's root element: <%s>", name)
				}
				if name != "Policy" {
					return fmt.Errorf("root element is <%s>, only <Policy> is supported here (no <PolicySet>, no policy or policy-set reference)", name)
				}
				rootSeen = true
			} else {
				parent := stack[len(stack)-1]
				// parent is guaranteed to be a grammar key: it was only
				// ever pushed onto stack after passing this same check (or
				// as "Policy", checked above).
				if !grammar[parent].children[name] {
					return fmt.Errorf("<%s> may not contain <%s>: unsupported construct (this engine's supported elements are Policy, Target, AnyOf, AllOf, Match, AttributeValue, AttributeDesignator, and Rule — see the package doc)", parent, name)
				}
			}

			rule, known := grammar[name]
			if !known {
				// Unreachable: name just passed either the root check
				// (name == "Policy", a grammar key) or the parent-children
				// check above, whose true branches only fire for names
				// grammar itself lists as an allowed child — and every
				// value grammar's children sets contain is itself a
				// grammar key. Kept as an explicit error rather than a
				// silent zero-value elementRule (an empty attrs set would
				// then reject every attribute unconditionally) so a future
				// edit that lets children and the top-level map keys drift
				// apart fails loudly instead of misreporting the cause.
				return fmt.Errorf("internal: %q is an allowed child but has no grammar entry of its own", name)
			}
			for _, a := range t.Attr {
				if !rule.attrs[a.Name.Local] {
					return fmt.Errorf("<%s> has unsupported attribute %q", name, a.Name.Local)
				}
			}
			stack = append(stack, name)

		case xml.EndElement:
			stack = stack[:len(stack)-1]
		}
	}

	if !rootSeen {
		return errors.New("empty document: no <Policy> root element found")
	}
	return nil
}
