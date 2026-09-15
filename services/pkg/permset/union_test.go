package permset

import (
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"stratium/pkg/models"
)

func TestUnion_TakesTheWeakestOfEachDimension(t *testing.T) {
	read, ext := models.ActionTierReadOnly, models.ActionTierExternalComms
	early := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)

	a := Set{
		Tools: []string{"Read"}, MaxTier: models.ActionTierReadOnly, EscalateAt: &read,
		ClassificationCaps: map[string]string{"nato": "CONFIDENTIAL"},
		ExpiresAt:          early,
	}
	b := Set{
		Tools: []string{"Bash"}, MaxTier: models.ActionTierDestructive, EscalateAt: &ext,
		ClassificationCaps: map[string]string{"nato": "SECRET"},
		ExpiresAt:          early.Add(time.Hour),
	}

	got, reasons := Union(a, b)

	if got.MaxTier != models.ActionTierDestructive {
		t.Errorf("MaxTier = %s, want DESTRUCTIVE", got.MaxTier)
	}
	if got.EscalateAt == nil || *got.EscalateAt != ext {
		t.Errorf("EscalateAt = %v, want EXTERNAL_COMMS (the weaker threshold)", got.EscalateAt)
	}
	want := []string{"Bash", "Read"}
	sorted := slices.Clone(got.Tools)
	slices.Sort(sorted)
	if !slices.Equal(sorted, want) {
		t.Errorf("Tools = %v, want %v", sorted, want)
	}
	if got.ClassificationCaps["nato"] != "SECRET" {
		t.Errorf("cap = %s, want SECRET", got.ClassificationCaps["nato"])
	}
	if !got.ExpiresAt.Equal(early.Add(time.Hour)) {
		t.Errorf("ExpiresAt = %v, want the later", got.ExpiresAt)
	}
	if len(reasons) != 0 {
		t.Errorf("no dimension needed widening here, got reasons %v", reasons)
	}
}

// An unrestricted tool list and a nil EscalateAt are each the weakest
// possible value of their dimension, so each absorbs everything else.
func TestUnion_WeakestValuesAbsorb(t *testing.T) {
	read := models.ActionTierReadOnly
	restricted := Set{Tools: []string{"Read"}, EscalateAt: &read}
	unrestricted := Set{Tools: nil, EscalateAt: nil}

	got, _ := Union(restricted, unrestricted)
	if len(got.Tools) != 0 {
		t.Errorf("Tools = %v, want empty (unrestricted absorbs)", got.Tools)
	}
	if got.EscalateAt != nil {
		t.Errorf("EscalateAt = %v, want nil (never-escalates absorbs)", got.EscalateAt)
	}
}

// A hierarchy only one member caps is UNCAPPED in the union: the other
// member's holder has unrestricted access to it.
func TestUnion_HierarchyCappedByOnlyOneMemberBecomesUncapped(t *testing.T) {
	a := Set{ClassificationCaps: map[string]string{"nato": "SECRET"}}
	b := Set{ClassificationCaps: map[string]string{}}

	got, reasons := Union(a, b)
	if _, capped := got.ClassificationCaps["nato"]; capped {
		t.Error("a hierarchy only one member caps must be uncapped in the union")
	}
	if len(reasons) == 0 {
		t.Error("dropping a cap is a widening and must be named in reasons")
	}
}

// The one honest imprecision. The union of two differing prefixes is not a
// prefix, and Set holds one string -- so it widens to unconstrained and says
// so. Sound ONLY because Union is advisory (see permset.go's package doc).
func TestUnion_DifferingPrefixesWidenToUnconstrainedAndSayWhich(t *testing.T) {
	a := Set{ResourceConstraints: map[string]string{models.ResourceIDPrefixKey: "/workspace/"}}
	b := Set{ResourceConstraints: map[string]string{models.ResourceIDPrefixKey: "/tmp/"}}

	got, reasons := Union(a, b)
	if _, constrained := got.ResourceConstraints[models.ResourceIDPrefixKey]; constrained {
		t.Error("differing prefixes must widen to unconstrained")
	}
	var named bool
	for _, r := range reasons {
		if strings.Contains(r, "/workspace/") && strings.Contains(r, "/tmp/") {
			named = true
		}
	}
	if !named {
		t.Errorf("the reason must name both prefixes that disagreed; got %v", reasons)
	}
}

// Identical constraint values survive the union exactly.
func TestUnion_AgreeingConstraintsSurvive(t *testing.T) {
	a := Set{ResourceConstraints: map[string]string{models.ResourceIDPrefixKey: "/workspace/"}}
	got, reasons := Union(a, a)
	if got.ResourceConstraints[models.ResourceIDPrefixKey] != "/workspace/" {
		t.Errorf("agreeing constraints must survive, got %v", got.ResourceConstraints)
	}
	if len(reasons) != 0 {
		t.Errorf("nothing widened, got %v", reasons)
	}
}

func TestUnion_NoSetsIsTheEmptyGrant(t *testing.T) {
	got, reasons := Union()
	if len(got.Tools) != 0 || got.MaxTier != models.ActionTierReasoning || len(reasons) != 0 {
		t.Errorf("Union() of nothing must be the zero Set, got %+v", got)
	}
}

// TestUnion_DoesNotMutateInputs guards against the failure mode Task 1's
// review found in FromDelegation: a Set's ClassificationCaps and
// ResourceConstraints maps are shallow-copied from the source
// models.Delegation, so a Union that wrote INTO an input's maps -- rather
// than allocating its own -- would silently corrupt a live delegation
// record. This snapshots every input's maps before the call and asserts
// they are byte-for-byte identical after, across a mix of branches
// (agreeing and disagreeing dimensions) so both the copy-through and the
// widen-and-name paths are exercised.
func TestUnion_DoesNotMutateInputs(t *testing.T) {
	a := Set{
		Tools:               []string{"Read"},
		ClassificationCaps:  map[string]string{"nato": "CONFIDENTIAL"},
		ResourceConstraints: map[string]string{models.ResourceIDPrefixKey: "/workspace/"},
	}
	b := Set{
		Tools:               []string{"Bash"},
		ClassificationCaps:  map[string]string{"nato": "SECRET"},
		ResourceConstraints: map[string]string{models.ResourceIDPrefixKey: "/tmp/"},
	}

	wantATools := slices.Clone(a.Tools)
	wantACaps := maps.Clone(a.ClassificationCaps)
	wantAConstraints := maps.Clone(a.ResourceConstraints)
	wantBTools := slices.Clone(b.Tools)
	wantBCaps := maps.Clone(b.ClassificationCaps)
	wantBConstraints := maps.Clone(b.ResourceConstraints)

	Union(a, b)

	if !slices.Equal(a.Tools, wantATools) {
		t.Errorf("a.Tools mutated: got %v, want %v", a.Tools, wantATools)
	}
	if !maps.Equal(a.ClassificationCaps, wantACaps) {
		t.Errorf("a.ClassificationCaps mutated: got %v, want %v", a.ClassificationCaps, wantACaps)
	}
	if !maps.Equal(a.ResourceConstraints, wantAConstraints) {
		t.Errorf("a.ResourceConstraints mutated: got %v, want %v", a.ResourceConstraints, wantAConstraints)
	}
	if !slices.Equal(b.Tools, wantBTools) {
		t.Errorf("b.Tools mutated: got %v, want %v", b.Tools, wantBTools)
	}
	if !maps.Equal(b.ClassificationCaps, wantBCaps) {
		t.Errorf("b.ClassificationCaps mutated: got %v, want %v", b.ClassificationCaps, wantBCaps)
	}
	if !maps.Equal(b.ResourceConstraints, wantBConstraints) {
		t.Errorf("b.ResourceConstraints mutated: got %v, want %v", b.ResourceConstraints, wantBConstraints)
	}
}
