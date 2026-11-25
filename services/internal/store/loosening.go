package store

import (
	"errors"
	"strings"

	"github.com/stratiumdata/stratium/pkg/classification"
	"github.com/stratiumdata/stratium/pkg/models"
)

// ErrAdminRequired is returned when an operator below admin asks for an
// update that relaxes something an admin-only ceiling is measured against:
// a resource's classification label, a tool's action tier, or an agent's
// trust tier and running state. The caller passes mayLoosen = true for an
// admin, and the check is skipped.
//
// Each check below is deliberately narrower than "does this lower anything":
// a change it cannot rank (a moved prefix, a renamed tool, a different input
// field) is refused too, so an editor's update is always "the same thing,
// rated at least as strictly".
var ErrAdminRequired = errors.New("store: this change needs the admin role")

// agentLoosens reports why an agent update needs an admin, or "".
// allowed_tools is not looked at: widening it is an editor's write, recorded
// by the containment audit entry.
func agentLoosens(oldTier, newTier models.AgentTrustTier, oldEnabled, newEnabled, oldSuspended, newSuspended bool) string {
	switch {
	case newTier > oldTier:
		return "it raises the agent's trust tier"
	case oldSuspended && !newSuspended:
		return "it resumes a suspended agent"
	case !oldEnabled && newEnabled:
		return "it enables a disabled agent"
	}
	return ""
}

// labelRuleLoosens reports why a label rule update needs an admin, or "".
func labelRuleLoosens(old, updated models.ResourceLabelRule) string {
	switch {
	case updated.Prefix != old.Prefix:
		return "it moves the rule to another prefix"
	case !strings.EqualFold(updated.Hierarchy, old.Hierarchy):
		return "it changes the rule's hierarchy"
	case classification.Index(updated.Hierarchy, updated.Level) < classification.Index(old.Hierarchy, old.Level):
		return "it lowers the level"
	}
	return ""
}

// catalogEntryLoosens reports why a tool catalog update needs an admin, or "".
func catalogEntryLoosens(old, updated models.ToolCatalogEntry) string {
	switch {
	case updated.ToolName != old.ToolName:
		return "it renames the tool"
	case updated.Verb != old.Verb:
		return "it changes the tool's verb"
	case !equalPtr(updated.ResourceField, old.ResourceField), !equalPtr(updated.CommandField, old.CommandField):
		return "it changes which input fields are read"
	case (updated.ActionTier == nil) != (old.ActionTier == nil):
		return "it changes whether the tool has a fixed action tier"
	case updated.ActionTier != nil && *updated.ActionTier < *old.ActionTier:
		return "it lowers the action tier"
	}
	return ""
}

func equalPtr[T comparable](a, b *T) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
