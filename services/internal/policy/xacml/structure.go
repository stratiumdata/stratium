package xacml

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strings"
)

// elementRule is what validateStructure allows one element name to contain:
// which child element names may appear inside it, which of those children
// are bounded to at most one occurrence, and which attribute names the
// element itself may carry. A name — element or attribute — absent from
// the relevant set is rejected, by that name, wherever it is found.
type elementRule struct {
	children map[string]bool
	attrs    map[string]bool

	// atMostOnce is the subset of children that may appear zero or one
	// times. A name absent from this set (including every entry that
	// leaves it nil) is unbounded — Rule under Policy, and AnyOf/AllOf/
	// Match under their respective parents, are meant to repeat and must
	// never be added here. A nil map reads as "nothing bounded" for any
	// lookup, so entries that need no bound simply omit this field.
	atMostOnce map[string]bool
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
//
// atMostOnce bounds Policy's and Rule's Target, and Match's AttributeValue
// and AttributeDesignator — review found a second review pass this
// package's own enumeration had missed: a name being *allowed* as a child
// says nothing about how many times it may repeat, and xml.Unmarshal binds
// each of those four to a non-slice Go field, which silently keeps only
// one occurrence (Target: the last one written; AttributeValue/
// AttributeDesignator: the same) or, worse, for Target specifically,
// evaluates as if a second one had never been written at all while a
// hand-authored document visibly has two — see xmlTarget's own doc
// comment on why a duplicate Target is not merely "silently dropped" but
// "silently OR-ed," which can widen a Policy's or Rule's applicability
// rather than narrow it.
var grammar = map[string]elementRule{
	"Policy": {
		children:   map[string]bool{"Target": true, "Rule": true},
		attrs:      map[string]bool{"PolicyId": true, "RuleCombiningAlgId": true},
		atMostOnce: map[string]bool{"Target": true},
	},
	"Rule": {
		children:   map[string]bool{"Target": true},
		attrs:      map[string]bool{"RuleId": true, "Effect": true},
		atMostOnce: map[string]bool{"Target": true},
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
		children:   map[string]bool{"AttributeValue": true, "AttributeDesignator": true},
		attrs:      map[string]bool{"MatchId": true},
		atMostOnce: map[string]bool{"AttributeValue": true, "AttributeDesignator": true},
	},
	"AttributeValue": {
		children: map[string]bool{}, // leaf: text content only
		attrs:    map[string]bool{"DataType": true},
	},
	"AttributeDesignator": {
		children: map[string]bool{}, // leaf: always empty (<.../>)
		// Category is required and semantically checked against the
		// dimension AttributeId names — see (xmlMatch).validate in
		// schema.go — not merely accepted-and-ignored: a Category naming
		// the wrong dimension is exactly the "reads as configurable, isn't
		// really checked" shape this whole engine exists to close off.
		attrs: map[string]bool{"AttributeId": true, "DataType": true, "Category": true},
	},
}

// openElement is one still-open element on validateStructure's stack: its
// name, and which of its atMostOnce-bounded children have been seen so
// far. seenOnce is allocated lazily (nil until the first bounded child
// arrives) since most open elements (Target, AnyOf, AllOf, AttributeValue,
// AttributeDesignator) have nothing bounded to track.
type openElement struct {
	name     string
	seenOnce map[string]bool
}

// isNamespaceDecl reports whether name is an XML namespace declaration
// attribute — xmlns="..." (Space "", Local "xmlns") or xmlns:prefix="..."
// (Space "xmlns", Local the prefix) — confirmed against this exact
// encoding/xml release rather than assumed: both shapes were probed
// directly before writing this check. These carry no policy semantics of
// their own; skipping them here is what makes a properly namespaced,
// schema-valid XACML document (<Policy xmlns="urn:oasis:...">) parse
// identically to an unprefixed one, rather than failing on "unsupported
// attribute \"xmlns\"" — which used to make the more spec-conformant
// document the one this engine rejected.
func isNamespaceDecl(name xml.Name) bool {
	return name.Local == "xmlns" || name.Space == "xmlns"
}

// validateStructure walks text's raw token stream and confirms every
// element and attribute name in it is one grammar recognizes, in a
// position and quantity grammar allows, with no non-whitespace text
// outside <AttributeValue>. It is the first step of parseAndValidate,
// deliberately run before any typed unmarshal: rejecting an unsupported
// construct here means it is named in the error and never reaches a Go
// value at all, rather than being silently dropped by a struct tag that
// has no field for it.
//
// Namespace declarations (xmlns, xmlns:prefix) are recognized and skipped
// — see isNamespaceDecl — so declaring one never triggers the unsupported-
// attribute rejection. Every element and attribute name below is matched
// on its local name only (xml.StartElement.Name.Local), the same matching
// xml.Unmarshal itself performs against an unprefixed struct tag such as
// `xml:"Policy"`: confirmed directly that this makes a prefixed element
// match identically whether or not its prefix is actually declared
// (<x:Policy> alone and <x:Policy xmlns:x="..."> both resolve to the local
// name "Policy" either way) — deliberately symmetric, not merely
// untested, since a validating XML processor would treat only the second
// as well-formed and this one treats both the same. This engine does not
// use namespace to distinguish one meaning of "Policy" from another, so
// there is nothing namespace-qualified for a stricter check to buy.
func validateStructure(text string) error {
	dec := xml.NewDecoder(strings.NewReader(text))

	var stack []openElement
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
				parentIdx := len(stack) - 1
				parent := &stack[parentIdx]
				// parent.name is guaranteed to be a grammar key: it was
				// only ever pushed onto stack after passing this same
				// check (or as "Policy", checked above).
				if !grammar[parent.name].children[name] {
					return fmt.Errorf("<%s> may not contain <%s>: unsupported construct (this engine's supported elements are Policy, Target, AnyOf, AllOf, Match, AttributeValue, AttributeDesignator, and Rule — see the package doc)", parent.name, name)
				}
				if grammar[parent.name].atMostOnce[name] {
					if parent.seenOnce[name] {
						return fmt.Errorf("<%s> may contain at most one <%s>, found a second — a duplicate here can silently change meaning (e.g. a second <Target> is OR-ed with the first, which can only widen, never narrow, what a Policy or Rule applies to)", parent.name, name)
					}
					if parent.seenOnce == nil {
						parent.seenOnce = make(map[string]bool)
					}
					parent.seenOnce[name] = true
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
				if isNamespaceDecl(a.Name) {
					continue
				}
				if !rule.attrs[a.Name.Local] {
					return fmt.Errorf("<%s> has unsupported attribute %q", name, a.Name.Local)
				}
			}
			stack = append(stack, openElement{name: name})

		case xml.EndElement:
			stack = stack[:len(stack)-1]

		case xml.CharData:
			// Only <AttributeValue> carries a real comparison value; every
			// other element in this grammar is either a leaf with no text
			// (AttributeDesignator) or a pure container (Policy, Rule,
			// Target, AnyOf, AllOf, Match). Non-whitespace text found
			// while any of those is the innermost open element has
			// nowhere to attach any meaning and would otherwise be
			// silently dropped by xml.Unmarshal, the same accept-and-
			// ignore shape as an unsupported element — whitespace itself
			// (indentation, newlines between elements) is not an error.
			if len(stack) == 0 {
				continue
			}
			top := stack[len(stack)-1]
			if top.name == "AttributeValue" {
				continue
			}
			if trimmed := strings.TrimSpace(string(t)); trimmed != "" {
				return fmt.Errorf("<%s> may not contain text content %q — only <AttributeValue> carries a comparison value", top.name, trimmed)
			}
		}
	}

	if !rootSeen {
		return errors.New("empty document: no <Policy> root element found")
	}
	return nil
}
