package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// agentRecord is the subset of models.Agent this program round-trips
// through PUT /v1/agents/{id}. classification_caps and resource_constraints
// are deliberately absent: updateAgentQuery (internal/store/agent.go) never
// writes either column — they are set only by their own dedicated,
// RoleAdmin-gated routes — so a caller's request body value for either is
// ignored server-side, and there is nothing this struct needs to carry for
// them to round-trip correctly.
type agentRecord struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Provider     string   `json:"provider"`
	ModelID      string   `json:"model_id"`
	TrustTier    int      `json:"trust_tier"`
	Enabled      bool     `json:"enabled"`
	Suspended    bool     `json:"suspended"`
	AllowedTools []string `json:"allowed_tools"`
}

// ensureAgent registers this example's agent restricted to [Read] on
// create, or finds the one a previous run already created — UNIQUE(tenant_id,
// name) makes the second POST 409, so this run is idempotent across repeats
// too. Deliberately restricted, unlike example/depth/hook's own ensureAgent
// (allowed_tools: []): an unrestricted agent has no allowlist for step 1's
// denial to come from at all — see this example's own package doc.
func ensureAgent(papAddr, token string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"name": agentName, "provider": "example", "model_id": "n/a",
		"trust_tier": 3, "enabled": true, "suspended": false, "allowed_tools": []string{"Read"},
	})
	req, err := http.NewRequest(http.MethodPost, "http://"+papAddr+"/v1/agents", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("agents: create %q: %w", agentName, err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch resp.StatusCode {
	case http.StatusCreated:
		var out struct {
			ID string `json:"id"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
			return "", fmt.Errorf("agents: decode create response: %w", err)
		}
		return out.ID, nil
	case http.StatusConflict:
		return findAgentByName(papAddr, token)
	default:
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("agents: create %q: %s: %s", agentName, resp.Status, b)
	}
}

func findAgentByName(papAddr, token string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, "http://"+papAddr+"/v1/agents", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("agents: list: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var agents []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&agents); err != nil {
		return "", fmt.Errorf("agents: decode list: %w", err)
	}
	for _, a := range agents {
		if a.Name == agentName {
			return a.ID, nil
		}
	}
	return "", fmt.Errorf("agents: %q reported a conflict on create but is not in the list", agentName)
}

// resetAgentTools GETs the current row and PUTs it back with AllowedTools
// replaced by tools, leaving every other field untouched — the same
// GET-edit-PUT an operator's admin console does for a full replace
// (updateAgent, cmd/stratium-pap/agents.go: "a PUT-shaped full replace").
func resetAgentTools(papAddr, token, agentID string, tools []string) error {
	rec, err := getAgent(papAddr, token, agentID)
	if err != nil {
		return err
	}
	rec.AllowedTools = tools
	return putAgent(papAddr, token, agentID, rec)
}

func getAgent(papAddr, token, agentID string) (agentRecord, error) {
	req, err := http.NewRequest(http.MethodGet, "http://"+papAddr+"/v1/agents/"+agentID, nil)
	if err != nil {
		return agentRecord{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return agentRecord{}, fmt.Errorf("agents: get %s: %w", agentID, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return agentRecord{}, fmt.Errorf("agents: get %s: %s: %s", agentID, resp.Status, b)
	}
	var rec agentRecord
	if err := json.NewDecoder(resp.Body).Decode(&rec); err != nil {
		return agentRecord{}, fmt.Errorf("agents: decode get %s: %w", agentID, err)
	}
	return rec, nil
}

func putAgent(papAddr, token, agentID string, rec agentRecord) error {
	body, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("agents: encode put %s: %w", agentID, err)
	}
	req, err := http.NewRequest(http.MethodPut, "http://"+papAddr+"/v1/agents/"+agentID, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("agents: put %s: %w", agentID, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("agents: put %s: %s: %s", agentID, resp.Status, b)
	}
	return nil
}

// auditEntry mirrors the fields models.AuditEntryView puts on the wire.
// Declared here rather than imported so this example stays a CLIENT of the
// API's JSON contract: if a field is renamed on the server, this example
// should fail the way any other consumer would, not silently follow the
// rename through a shared Go type.
type auditEntry struct {
	Seq        int64     `json:"seq"`
	PrevHash   []byte    `json:"prev_hash"`
	EntryHash  []byte    `json:"entry_hash"`
	OccurredAt time.Time `json:"occurred_at"`
	EventType  string    `json:"event_type"`
	Actor      string    `json:"actor"`
	Decision   string    `json:"decision"`
	Reason     string    `json:"reason"`
}

type auditPage struct {
	Entries       []auditEntry `json:"entries"`
	NextBeforeSeq *int64       `json:"next_before_seq,omitempty"`
}

// readContainmentViaAPI fetches this agent's containment rows through
// GET /v1/audit and returns the single one this run produced.
//
// It asserts exactly one. More than one would mean a write this example did
// not intend also widened the grant, and reporting the newest without
// noticing would hide that.
func readContainmentViaAPI(papAddr, token, agentID string) (auditEntry, error) {
	req, err := http.NewRequest(http.MethodGet,
		"http://"+papAddr+"/v1/audit?event_type=containment&agent_id="+agentID, nil)
	if err != nil {
		return auditEntry{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return auditEntry{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return auditEntry{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return auditEntry{}, fmt.Errorf("GET /v1/audit → %d: %s", resp.StatusCode, raw)
	}
	var page auditPage
	if err := json.Unmarshal(raw, &page); err != nil {
		return auditEntry{}, fmt.Errorf("decode audit page: %w; body: %s", err, raw)
	}
	if len(page.Entries) != 1 {
		return auditEntry{}, fmt.Errorf("audit route returned %d containment entries for agent %s, want exactly 1",
			len(page.Entries), agentID)
	}
	return page.Entries[0], nil
}
