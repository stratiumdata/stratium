package authz

import (
	"bytes"
	"encoding/json"
	"strings"
)

// AmbiguousJSONKeys reports whether any object in data, at any depth,
// has two keys that differ at most in capitalization. Data that is not valid
// JSON reports false: it has no keys to read two ways.
//
// encoding/json keeps the last of several equal keys and, decoding into a
// struct, matches a key whatever its case. Other parsers do neither, so such
// input can mean one thing to the PDP and another to whatever runs the call.
func AmbiguousJSONKeys(data []byte) bool {
	dec := json.NewDecoder(bytes.NewReader(data))
	// One entry per open object or array: an object's keys so far, nil for
	// an array. wantKey is whether the next token in the innermost object
	// is a key.
	var open []map[string]bool
	wantKey := false
	for {
		t, err := dec.Token()
		if err != nil {
			return false // io.EOF at the end, or invalid JSON
		}
		inObject := len(open) > 0 && open[len(open)-1] != nil
		if key, ok := t.(string); ok && inObject && wantKey {
			// Upper then lower folds every pair encoding/json would match.
			folded := strings.ToLower(strings.ToUpper(key))
			if open[len(open)-1][folded] {
				return true
			}
			open[len(open)-1][folded] = true
			wantKey = false
			continue
		}
		switch t {
		case json.Delim('{'):
			open = append(open, map[string]bool{})
			wantKey = true
			continue
		case json.Delim('['):
			open = append(open, nil)
			continue
		case json.Delim('}'), json.Delim(']'):
			open = open[:len(open)-1]
		}
		// A value has just ended, so the enclosing object wants a key next.
		wantKey = true
	}
}
