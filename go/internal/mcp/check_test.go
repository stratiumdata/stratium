package mcp

import (
	"encoding/json"
	"testing"
)

func TestCheckRequest_Unmarshal(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantTool string
		wantAct  string
		wantTier int32
		wantRes  string
		wantErr  bool
	}{
		{
			name:     "full request",
			input:    `{"tool_name":"Bash","action":"write","action_tier":2,"resource_id":"src/auth.go","resource_classification":"INTERNAL"}`,
			wantTool: "Bash",
			wantAct:  "write",
			wantTier: 2,
			wantRes:  "src/auth.go",
		},
		{
			name:     "minimal request",
			input:    `{"tool_name":"Bash","action":"read","action_tier":1}`,
			wantTool: "Bash",
			wantAct:  "read",
			wantTier: 1,
		},
		{
			name:     "destructive tier",
			input:    `{"tool_name":"Bash","action":"execute","action_tier":4,"resource_id":"rm -rf /"}`,
			wantTool: "Bash",
			wantAct:  "execute",
			wantTier: 4,
			wantRes:  "rm -rf /",
		},
		{
			name:    "invalid json",
			input:   `not json`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var req CheckRequest
			err := json.Unmarshal([]byte(tt.input), &req)
			if tt.wantErr {
				if err == nil {
					t.Error("expected unmarshal error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected unmarshal error: %v", err)
			}
			if req.ToolName != tt.wantTool {
				t.Errorf("ToolName = %q, want %q", req.ToolName, tt.wantTool)
			}
			if req.Action != tt.wantAct {
				t.Errorf("Action = %q, want %q", req.Action, tt.wantAct)
			}
			if req.ActionTier != tt.wantTier {
				t.Errorf("ActionTier = %d, want %d", req.ActionTier, tt.wantTier)
			}
			if req.ResourceID != tt.wantRes {
				t.Errorf("ResourceID = %q, want %q", req.ResourceID, tt.wantRes)
			}
		})
	}
}

func TestCheckResponse_Marshal(t *testing.T) {
	tests := []struct {
		name string
		resp CheckResponse
		want map[string]any
	}{
		{
			name: "authorized",
			resp: CheckResponse{
				Authorized: true,
				Decision: &CheckDecision{
					UserDecision:       "ALLOW",
					AgentDecision:      "ALLOW",
					DelegationDecision: "ALLOW",
					DelegationReason:   "within scope",
				},
			},
			want: map[string]any{
				"authorized": true,
			},
		},
		{
			name: "denied with reason",
			resp: CheckResponse{
				Authorized: false,
				Decision: &CheckDecision{
					UserDecision:       "ALLOW",
					AgentDecision:      "ALLOW",
					DelegationDecision: "DENY",
					DelegationReason:   "classification CONFIDENTIAL > cap INTERNAL",
				},
			},
			want: map[string]any{
				"authorized": false,
			},
		},
		{
			name: "error",
			resp: CheckResponse{
				Authorized: false,
				Error:      "gateway unreachable",
			},
			want: map[string]any{
				"authorized": false,
				"error":      "gateway unreachable",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.resp)
			if err != nil {
				t.Fatalf("marshal error: %v", err)
			}

			var got map[string]any
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("unmarshal error: %v", err)
			}

			if got["authorized"] != tt.want["authorized"] {
				t.Errorf("authorized = %v, want %v", got["authorized"], tt.want["authorized"])
			}

			if wantErr, ok := tt.want["error"]; ok {
				if got["error"] != wantErr {
					t.Errorf("error = %v, want %v", got["error"], wantErr)
				}
			}
		})
	}
}

func TestCheckResponse_DeniedHasDecision(t *testing.T) {
	resp := CheckResponse{
		Authorized: false,
		Decision: &CheckDecision{
			DelegationDecision: "DENY",
			DelegationReason:   "tool 'delete_file' not in approved_tools",
		},
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal error: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	decision, ok := got["decision"].(map[string]any)
	if !ok {
		t.Fatal("expected decision field in response")
	}

	if decision["delegation_decision"] != "DENY" {
		t.Errorf("delegation_decision = %v, want DENY", decision["delegation_decision"])
	}

	if decision["delegation_reason"] != "tool 'delete_file' not in approved_tools" {
		t.Errorf("delegation_reason = %v, want tool reason", decision["delegation_reason"])
	}
}
