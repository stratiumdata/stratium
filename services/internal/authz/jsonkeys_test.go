package authz

import "testing"

func TestAmbiguousJSONKeys(t *testing.T) {
	// Built here so the escapes reach the decoder as escapes.
	escaped := `{"p` + `\` + `u0061th":"/a","path":"/b"}`
	kelvin := `{"k":1,"` + `\` + `u212a":2}` // the Kelvin sign folds to k

	for in, want := range map[string]bool{
		`{"path":"/a","path":"/b"}`:           true,
		`{"path":"/a","Path":"/b"}`:           true,
		`{"a":{"b":[1,{"x":1,"X":2}]}}`:       true,
		escaped:                               true,
		kelvin:                                true,
		`{"path":"/a","other":{"path":"/b"}}`: false,
		`{"a":["path","path",{"path":1},{"path":2}],"b":"a"}`: false,
		`{"command":"ls"}`: false,
		`"a string"`:       false,
		`not json`:         false,
		``:                 false,
	} {
		if got := AmbiguousJSONKeys([]byte(in)); got != want {
			t.Errorf("AmbiguousJSONKeys(%s) = %v, want %v", in, got, want)
		}
	}
}
