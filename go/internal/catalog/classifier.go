// go/internal/catalog/classifier.go
package catalog

import "errors"

// ErrUnclassified is returned when a resource has no mapped classification and
// no default is configured. Callers MUST treat this as a denial (fail-closed).
var ErrUnclassified = errors.New("resource classification unknown and no default configured")

// Classification is the resource label evaluated by the policy engine.
type Classification struct {
	Classification string `json:"classification"`
	Hierarchy      string `json:"hierarchy"`
}

// Classifier resolves a resource identifier (e.g. "owner/repo") to a Classification.
type Classifier struct {
	repos map[string]Classification
	deflt *Classification
}

// NewClassifier builds a Classifier. A nil deflt means "fail closed on unknown".
func NewClassifier(repos map[string]Classification, deflt *Classification) *Classifier {
	if repos == nil {
		repos = map[string]Classification{}
	}
	return &Classifier{repos: repos, deflt: deflt}
}

// Resolve returns the classification for a resource. It returns ErrUnclassified
// when the resource is unknown and no default is configured — never a permissive
// default.
func (c *Classifier) Resolve(resource string) (Classification, error) {
	if v, ok := c.repos[resource]; ok {
		return v, nil
	}
	if c.deflt != nil {
		return *c.deflt, nil
	}
	return Classification{}, ErrUnclassified
}
