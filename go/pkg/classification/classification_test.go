package classification_test

import (
	"testing"

	"stratium/pkg/classification"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIndex(t *testing.T) {
	tests := []struct {
		name      string
		hierarchy string
		level     string
		want      int
	}{
		{"nato unclassified is 0", "nato", "UNCLASSIFIED", 0},
		{"nato top-secret is highest", "nato", "TOP-SECRET", 4},
		{"nato secret", "nato", "SECRET", 3},
		{"nato confidential", "nato", "CONFIDENTIAL", 2},
		{"case-insensitive level", "nato", "secret", 3},
		{"case-insensitive hierarchy", "NATO", "SECRET", 3},
		{"commercial public is 0", "commercial", "PUBLIC", 0},
		{"commercial highly-confidential is highest", "commercial", "HIGHLY-CONFIDENTIAL", 4},
		{"unknown hierarchy returns -1", "unknown", "SECRET", -1},
		{"unknown level returns -1", "nato", "ULTRA-SECRET", -1},
		{"empty level returns -1", "nato", "", -1},
		{"empty hierarchy returns -1", "", "SECRET", -1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := classification.Index(tc.hierarchy, tc.level)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestCheckCap(t *testing.T) {
	tests := []struct {
		name               string
		caps               map[string]string
		resourceAttr       map[string]string
		wantAllowed        bool
		wantReasonContains string
	}{
		{
			name:         "no caps → allow",
			caps:         map[string]string{},
			resourceAttr: map[string]string{"classification": "SECRET", "hierarchy": "nato"},
			wantAllowed:  true,
		},
		{
			name:         "nil caps → allow",
			caps:         nil,
			resourceAttr: map[string]string{"classification": "SECRET", "hierarchy": "nato"},
			wantAllowed:  true,
		},
		{
			name:         "no resource classification → allow",
			caps:         map[string]string{"nato": "CONFIDENTIAL"},
			resourceAttr: map[string]string{},
			wantAllowed:  true,
		},
		{
			name:               "classification without hierarchy → DENY",
			caps:               map[string]string{"nato": "CONFIDENTIAL"},
			resourceAttr:       map[string]string{"classification": "SECRET"},
			wantAllowed:        false,
			wantReasonContains: "ambiguous",
		},
		{
			name:               "nato SECRET vs cap CONFIDENTIAL → DENY",
			caps:               map[string]string{"nato": "CONFIDENTIAL"},
			resourceAttr:       map[string]string{"classification": "SECRET", "hierarchy": "nato"},
			wantAllowed:        false,
			wantReasonContains: "exceeds delegation cap",
		},
		{
			name:         "nato CONFIDENTIAL vs cap SECRET → allow",
			caps:         map[string]string{"nato": "SECRET"},
			resourceAttr: map[string]string{"classification": "CONFIDENTIAL", "hierarchy": "nato"},
			wantAllowed:  true,
		},
		{
			name:         "nato SECRET vs cap SECRET (exact match) → allow",
			caps:         map[string]string{"nato": "SECRET"},
			resourceAttr: map[string]string{"classification": "SECRET", "hierarchy": "nato"},
			wantAllowed:  true,
		},
		{
			name:               "unknown resource level → DENY",
			caps:               map[string]string{"nato": "SECRET"},
			resourceAttr:       map[string]string{"classification": "ULTRA-SECRET", "hierarchy": "nato"},
			wantAllowed:        false,
			wantReasonContains: "unknown classification level",
		},
		{
			name:               "unknown cap level → DENY",
			caps:               map[string]string{"nato": "LEVEL-X"},
			resourceAttr:       map[string]string{"classification": "SECRET", "hierarchy": "nato"},
			wantAllowed:        false,
			wantReasonContains: "not a known level",
		},
		{
			name:         "cap only for different hierarchy → allow",
			caps:         map[string]string{"commercial": "INTERNAL"},
			resourceAttr: map[string]string{"classification": "TOP-SECRET", "hierarchy": "nato"},
			wantAllowed:  true,
		},
		{
			name:               "case-insensitive cap lookup (lowercase hierarchy in resource) → enforced",
			caps:               map[string]string{"nato": "CONFIDENTIAL"},
			resourceAttr:       map[string]string{"classification": "secret", "hierarchy": "NATO"},
			wantAllowed:        false,
			wantReasonContains: "exceeds delegation cap",
		},
		{
			name:         "case-insensitive level matching: 'secret' vs cap 'SECRET' → allow (same)",
			caps:         map[string]string{"nato": "SECRET"},
			resourceAttr: map[string]string{"classification": "secret", "hierarchy": "nato"},
			wantAllowed:  true,
		},
		{
			name:         "commercial INTERNAL vs cap HIGHLY-CONFIDENTIAL → allow",
			caps:         map[string]string{"commercial": "HIGHLY-CONFIDENTIAL"},
			resourceAttr: map[string]string{"classification": "INTERNAL", "hierarchy": "commercial"},
			wantAllowed:  true,
		},
		{
			name:               "commercial HIGHLY-CONFIDENTIAL vs cap INTERNAL → DENY",
			caps:               map[string]string{"commercial": "INTERNAL"},
			resourceAttr:       map[string]string{"classification": "HIGHLY-CONFIDENTIAL", "hierarchy": "commercial"},
			wantAllowed:        false,
			wantReasonContains: "exceeds delegation cap",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			allowed, reason := classification.CheckCap(tc.caps, tc.resourceAttr)
			assert.Equal(t, tc.wantAllowed, allowed, "allowed mismatch")
			if tc.wantReasonContains != "" {
				require.False(t, allowed, "expected DENY but got allow")
				assert.Contains(t, reason, tc.wantReasonContains, "reason mismatch")
			}
			if allowed {
				assert.Empty(t, reason, "allowed result should have empty reason")
			}
		})
	}
}
