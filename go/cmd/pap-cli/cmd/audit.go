package cmd

import (
	"encoding/json"
	"fmt"

	"github.com/spf13/cobra"
)

var auditCmd = &cobra.Command{
	Use:     "audit",
	Aliases: []string{"audit-logs", "logs"},
	Short:   "View audit logs",
	Long:    `View and query audit logs from the PAP.`,
}

var auditListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List audit logs",
	Long:    `List audit logs with optional filtering.`,
	RunE:    runAuditList,
}

var auditGetCmd = &cobra.Command{
	Use:     "get <log-id>",
	Aliases: []string{"show"},
	Short:   "Get an audit log entry by ID",
	Args:    cobra.ExactArgs(1),
	RunE:    runAuditGet,
}

// Flags
var (
	auditEntityType string
	auditEntityID   string
	auditAction     string
	auditActor      string
	auditLimit      int
	auditOffset     int
	auditStartTime  string
	auditEndTime    string
)

func init() {
	// List flags
	auditListCmd.Flags().StringVar(&auditEntityType, "entity-type", "", "Filter by entity type (policy, entitlement)")
	auditListCmd.Flags().StringVar(&auditEntityID, "entity-id", "", "Filter by entity ID")
	auditListCmd.Flags().StringVar(&auditAction, "action", "", "Filter by action (create, update, delete, evaluate)")
	auditListCmd.Flags().StringVar(&auditActor, "actor", "", "Filter by actor (username)")
	auditListCmd.Flags().StringVar(&auditStartTime, "start-time", "", "Filter by start time (RFC3339 format)")
	auditListCmd.Flags().StringVar(&auditEndTime, "end-time", "", "Filter by end time (RFC3339 format)")
	auditListCmd.Flags().IntVar(&auditLimit, "limit", 50, "Maximum number of logs to return")
	auditListCmd.Flags().IntVar(&auditOffset, "offset", 0, "Offset for pagination")

	// Add subcommands
	auditCmd.AddCommand(auditListCmd)
	auditCmd.AddCommand(auditGetCmd)
}

func runAuditList(cmd *cobra.Command, args []string) error {
	client := NewAPIClient(serverURL, token)

	// Build query parameters
	path := fmt.Sprintf("/api/v1/audit-logs?limit=%d&offset=%d", auditLimit, auditOffset)
	if auditEntityType != "" {
		path += fmt.Sprintf("&entity_type=%s", auditEntityType)
	}
	if auditEntityID != "" {
		path += fmt.Sprintf("&entity_id=%s", auditEntityID)
	}
	if auditAction != "" {
		path += fmt.Sprintf("&action=%s", auditAction)
	}
	if auditActor != "" {
		path += fmt.Sprintf("&actor=%s", auditActor)
	}
	if auditStartTime != "" {
		path += fmt.Sprintf("&start_time=%s", auditStartTime)
	}
	if auditEndTime != "" {
		path += fmt.Sprintf("&end_time=%s", auditEndTime)
	}

	resp, err := client.Get(path)
	if err != nil {
		return err
	}

	if err := CheckResponse(resp); err != nil {
		return err
	}

	body, err := ReadResponseBody(resp)
	if err != nil {
		return err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	// Extract audit logs list
	if logs, ok := result["audit_logs"].([]interface{}); ok {
		if len(logs) == 0 {
			fmt.Println("No audit logs found.")
			return nil
		}
		if output == "table" {
			return OutputData(logs)
		}
	}

	return OutputData(result)
}

func runAuditGet(cmd *cobra.Command, args []string) error {
	client := NewAPIClient(serverURL, token)
	logID := args[0]

	resp, err := client.Get(fmt.Sprintf("/api/v1/audit-logs/%s", logID))
	if err != nil {
		return err
	}

	if err := CheckResponse(resp); err != nil {
		return err
	}

	body, err := ReadResponseBody(resp)
	if err != nil {
		return err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return fmt.Errorf("failed to parse response: %w", err)
	}

	return OutputData(result)
}
