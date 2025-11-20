package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var entitlementCmd = &cobra.Command{
	Use:     "entitlement",
	Aliases: []string{"entitlements", "ent"},
	Short:   "Manage entitlements",
	Long:    `Create, read, update, and delete entitlements in the PAP.`,
}

var entitlementListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List entitlements",
	Long:    `List all entitlements with optional filtering.`,
	RunE:    runEntitlementList,
}

var entitlementGetCmd = &cobra.Command{
	Use:     "get <entitlement-id>",
	Aliases: []string{"show"},
	Short:   "Get an entitlement by ID",
	Args:    cobra.ExactArgs(1),
	RunE:    runEntitlementGet,
}

var entitlementCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new entitlement",
	Long: `Create a new entitlement from a JSON file or inline JSON.

Examples:
  # Create from file
  pap-cli entitlement create --file entitlement.json

  # Create with inline JSON
  pap-cli entitlement create --data '{"name":"my-entitlement",...}'`,
	RunE: runEntitlementCreate,
}

var entitlementUpdateCmd = &cobra.Command{
	Use:   "update <entitlement-id>",
	Short: "Update an existing entitlement",
	Long: `Update an existing entitlement with new values.

Examples:
  # Update from file
  pap-cli entitlement update <id> --file entitlement.json

  # Update specific fields
  pap-cli entitlement update <id> --data '{"enabled":false}'`,
	Args: cobra.ExactArgs(1),
	RunE: runEntitlementUpdate,
}

var entitlementDeleteCmd = &cobra.Command{
	Use:     "delete <entitlement-id>",
	Aliases: []string{"rm", "remove"},
	Short:   "Delete an entitlement",
	Args:    cobra.ExactArgs(1),
	RunE:    runEntitlementDelete,
}

var entitlementMatchCmd = &cobra.Command{
	Use:   "match",
	Short: "Find matching entitlements",
	Long: `Find entitlements that match given subject attributes and action.

Examples:
  # Match from file
  pap-cli entitlement match --file match-request.json

  # Match inline
  pap-cli entitlement match --data '{"subject_attributes":{"role":"admin"},"action":"read"}'`,
	RunE: runEntitlementMatch,
}

// Flags
var (
	entitlementFile    string
	entitlementData    string
	entitlementEnabled string
	entitlementAction  string
	entitlementLimit   int
	entitlementOffset  int
	entitlementForce   bool
)

func init() {
	// List flags
	entitlementListCmd.Flags().StringVar(&entitlementEnabled, "enabled", "", "Filter by enabled status (true, false)")
	entitlementListCmd.Flags().StringVar(&entitlementAction, "action", "", "Filter by action")
	entitlementListCmd.Flags().IntVar(&entitlementLimit, "limit", 50, "Maximum number of entitlements to return")
	entitlementListCmd.Flags().IntVar(&entitlementOffset, "offset", 0, "Offset for pagination")

	// Create flags
	entitlementCreateCmd.Flags().StringVarP(&entitlementFile, "file", "f", "", "JSON file containing entitlement data")
	entitlementCreateCmd.Flags().StringVarP(&entitlementData, "data", "d", "", "Inline JSON entitlement data")

	// Update flags
	entitlementUpdateCmd.Flags().StringVarP(&entitlementFile, "file", "f", "", "JSON file containing entitlement updates")
	entitlementUpdateCmd.Flags().StringVarP(&entitlementData, "data", "d", "", "Inline JSON entitlement updates")

	// Delete flags
	entitlementDeleteCmd.Flags().BoolVarP(&entitlementForce, "force", "y", false, "Force deletion without confirmation")

	// Match flags
	entitlementMatchCmd.Flags().StringVarP(&entitlementFile, "file", "f", "", "JSON file containing match request")
	entitlementMatchCmd.Flags().StringVarP(&entitlementData, "data", "d", "", "Inline JSON match request")

	// Add subcommands
	entitlementCmd.AddCommand(entitlementListCmd)
	entitlementCmd.AddCommand(entitlementGetCmd)
	entitlementCmd.AddCommand(entitlementCreateCmd)
	entitlementCmd.AddCommand(entitlementUpdateCmd)
	entitlementCmd.AddCommand(entitlementDeleteCmd)
	entitlementCmd.AddCommand(entitlementMatchCmd)
}

func runEntitlementList(cmd *cobra.Command, args []string) error {
	client := NewAPIClient(serverURL, token)

	// Build query parameters
	path := fmt.Sprintf("/api/v1/entitlements?limit=%d&offset=%d", entitlementLimit, entitlementOffset)
	if entitlementEnabled != "" {
		path += fmt.Sprintf("&enabled=%s", entitlementEnabled)
	}
	if entitlementAction != "" {
		path += fmt.Sprintf("&action=%s", entitlementAction)
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

	// Extract entitlements list
	if entitlements, ok := result["entitlements"].([]interface{}); ok {
		if len(entitlements) == 0 {
			fmt.Println("No entitlements found.")
			return nil
		}
		if output == "table" {
			return OutputData(entitlements)
		}
	}

	return OutputData(result)
}

func runEntitlementGet(cmd *cobra.Command, args []string) error {
	client := NewAPIClient(serverURL, token)
	entitlementID := args[0]

	resp, err := client.Get(fmt.Sprintf("/api/v1/entitlements/%s", entitlementID))
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

func runEntitlementCreate(cmd *cobra.Command, args []string) error {
	client := NewAPIClient(serverURL, token)

	var entitlementReq map[string]interface{}

	// Load entitlement data from file or inline
	if entitlementFile != "" {
		data, err := os.ReadFile(entitlementFile)
		if err != nil {
			return fmt.Errorf("failed to read file: %w", err)
		}
		if err := json.Unmarshal(data, &entitlementReq); err != nil {
			return fmt.Errorf("failed to parse JSON: %w", err)
		}
	} else if entitlementData != "" {
		if err := json.Unmarshal([]byte(entitlementData), &entitlementReq); err != nil {
			return fmt.Errorf("failed to parse JSON: %w", err)
		}
	} else {
		return fmt.Errorf("either --file or --data must be provided")
	}

	resp, err := client.Post("/api/v1/entitlements", entitlementReq)
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

	PrintSuccess("Entitlement created successfully")
	return OutputData(result)
}

func runEntitlementUpdate(cmd *cobra.Command, args []string) error {
	client := NewAPIClient(serverURL, token)
	entitlementID := args[0]

	var updateReq map[string]interface{}

	// Load update data from file or inline
	if entitlementFile != "" {
		data, err := os.ReadFile(entitlementFile)
		if err != nil {
			return fmt.Errorf("failed to read file: %w", err)
		}
		if err := json.Unmarshal(data, &updateReq); err != nil {
			return fmt.Errorf("failed to parse JSON: %w", err)
		}
	} else if entitlementData != "" {
		if err := json.Unmarshal([]byte(entitlementData), &updateReq); err != nil {
			return fmt.Errorf("failed to parse JSON: %w", err)
		}
	} else {
		return fmt.Errorf("either --file or --data must be provided")
	}

	resp, err := client.Put(fmt.Sprintf("/api/v1/entitlements/%s", entitlementID), updateReq)
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

	PrintSuccess("Entitlement updated successfully")
	return OutputData(result)
}

func runEntitlementDelete(cmd *cobra.Command, args []string) error {
	client := NewAPIClient(serverURL, token)
	entitlementID := args[0]

	if !entitlementForce {
		fmt.Printf("Are you sure you want to delete entitlement %s? (y/N): ", entitlementID)
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			fmt.Println("Deletion cancelled.")
			return nil
		}
	}

	resp, err := client.Delete(fmt.Sprintf("/api/v1/entitlements/%s", entitlementID))
	if err != nil {
		return err
	}

	if err := CheckResponse(resp); err != nil {
		return err
	}

	PrintSuccess(fmt.Sprintf("Entitlement %s deleted successfully", entitlementID))
	return nil
}

func runEntitlementMatch(cmd *cobra.Command, args []string) error {
	client := NewAPIClient(serverURL, token)

	var matchReq map[string]interface{}

	// Load match request from file or inline
	if entitlementFile != "" {
		data, err := os.ReadFile(entitlementFile)
		if err != nil {
			return fmt.Errorf("failed to read file: %w", err)
		}
		if err := json.Unmarshal(data, &matchReq); err != nil {
			return fmt.Errorf("failed to parse JSON: %w", err)
		}
	} else if entitlementData != "" {
		if err := json.Unmarshal([]byte(entitlementData), &matchReq); err != nil {
			return fmt.Errorf("failed to parse JSON: %w", err)
		}
	} else {
		return fmt.Errorf("either --file or --data must be provided")
	}

	resp, err := client.Post("/api/v1/entitlements/match", matchReq)
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

	// Extract entitlements list
	if entitlements, ok := result["entitlements"].([]interface{}); ok {
		if len(entitlements) == 0 {
			fmt.Println("No matching entitlements found.")
			return nil
		}
		if output == "table" {
			return OutputData(entitlements)
		}
	}

	return OutputData(result)
}
