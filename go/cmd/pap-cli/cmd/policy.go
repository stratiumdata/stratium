package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var policyCmd = &cobra.Command{
	Use:     "policy",
	Aliases: []string{"policies", "pol"},
	Short:   "Manage policies",
	Long:    `Create, read, update, delete, and evaluate policies in the PAP.`,
}

var policyListCmd = &cobra.Command{
	Use:     "list",
	Aliases: []string{"ls"},
	Short:   "List policies",
	Long:    `List all policies with optional filtering.`,
	RunE:    runPolicyList,
}

var policyGetCmd = &cobra.Command{
	Use:     "get <policy-id>",
	Aliases: []string{"show"},
	Short:   "Get a policy by ID",
	Args:    cobra.ExactArgs(1),
	RunE:    runPolicyGet,
}

var policyCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new policy",
	Long: `Create a new policy from a JSON file or inline JSON.

Examples:
  # Create from file
  pap-cli policy create --file policy.json

  # Create with inline JSON
  pap-cli policy create --data '{"name":"my-policy","language":"opa",...}'`,
	RunE: runPolicyCreate,
}

var policyUpdateCmd = &cobra.Command{
	Use:   "update <policy-id>",
	Short: "Update an existing policy",
	Long: `Update an existing policy with new values.

Examples:
  # Update from file
  pap-cli policy update <id> --file policy.json

  # Update specific fields
  pap-cli policy update <id> --data '{"enabled":false}'`,
	Args: cobra.ExactArgs(1),
	RunE: runPolicyUpdate,
}

var policyDeleteCmd = &cobra.Command{
	Use:     "delete <policy-id>",
	Aliases: []string{"rm", "remove"},
	Short:   "Delete a policy",
	Args:    cobra.ExactArgs(1),
	RunE:    runPolicyDelete,
}

var policyEvalCmd = &cobra.Command{
	Use:     "evaluate",
	Aliases: []string{"eval", "test"},
	Short:   "Evaluate a policy",
	Long: `Evaluate or test a policy against a set of attributes.

Examples:
  # Evaluate from file
  pap-cli policy evaluate --file eval-request.json

  # Evaluate inline
  pap-cli policy evaluate --data '{"policy_id":"...","subject_attributes":{...}}'`,
	RunE: runPolicyEvaluate,
}

// Flags
var (
	policyFile         string
	policyData         string
	policyLanguage     string
	policyEnabled      string
	policyCreateEnabled bool
	policyEffect       string
	policyLimit        int
	policyOffset       int
	policyName         string
	policyDescription  string
	policyContent      string
	policyPriority     int
	policyForce        bool
)

func init() {
	// List flags
	policyListCmd.Flags().StringVar(&policyLanguage, "language", "", "Filter by language (opa, xacml)")
	policyListCmd.Flags().StringVar(&policyEnabled, "enabled", "", "Filter by enabled status (true, false)")
	policyListCmd.Flags().StringVar(&policyEffect, "effect", "", "Filter by effect (allow, deny)")
	policyListCmd.Flags().IntVar(&policyLimit, "limit", 50, "Maximum number of policies to return")
	policyListCmd.Flags().IntVar(&policyOffset, "offset", 0, "Offset for pagination")

	// Create flags
	policyCreateCmd.Flags().StringVarP(&policyFile, "file", "f", "", "JSON file containing policy data")
	policyCreateCmd.Flags().StringVarP(&policyData, "data", "d", "", "Inline JSON policy data")
	policyCreateCmd.Flags().StringVar(&policyName, "name", "", "Policy name")
	policyCreateCmd.Flags().StringVar(&policyDescription, "description", "", "Policy description")
	policyCreateCmd.Flags().StringVar(&policyLanguage, "language", "opa", "Policy language (opa, xacml)")
	policyCreateCmd.Flags().StringVar(&policyContent, "content", "", "Policy content")
	policyCreateCmd.Flags().StringVar(&policyEffect, "effect", "allow", "Policy effect (allow, deny)")
	policyCreateCmd.Flags().IntVar(&policyPriority, "priority", 50, "Policy priority")
	policyCreateCmd.Flags().BoolVar(&policyCreateEnabled, "enabled", true, "Enable policy")

	// Update flags
	policyUpdateCmd.Flags().StringVarP(&policyFile, "file", "f", "", "JSON file containing policy updates")
	policyUpdateCmd.Flags().StringVarP(&policyData, "data", "d", "", "Inline JSON policy updates")

	// Delete flags
	policyDeleteCmd.Flags().BoolVarP(&policyForce, "force", "y", false, "Force deletion without confirmation")

	// Evaluate flags
	policyEvalCmd.Flags().StringVarP(&policyFile, "file", "f", "", "JSON file containing evaluation request")
	policyEvalCmd.Flags().StringVarP(&policyData, "data", "d", "", "Inline JSON evaluation request")

	// Add subcommands
	policyCmd.AddCommand(policyListCmd)
	policyCmd.AddCommand(policyGetCmd)
	policyCmd.AddCommand(policyCreateCmd)
	policyCmd.AddCommand(policyUpdateCmd)
	policyCmd.AddCommand(policyDeleteCmd)
	policyCmd.AddCommand(policyEvalCmd)
}

func runPolicyList(cmd *cobra.Command, args []string) error {
	client := NewAPIClient(serverURL, token)

	// Build query parameters
	path := fmt.Sprintf("/api/v1/policies?limit=%d&offset=%d", policyLimit, policyOffset)
	if policyLanguage != "" {
		path += fmt.Sprintf("&language=%s", policyLanguage)
	}
	if policyEnabled != "" {
		path += fmt.Sprintf("&enabled=%s", policyEnabled)
	}
	if policyEffect != "" {
		path += fmt.Sprintf("&effect=%s", policyEffect)
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

	// Extract policies list
	if policies, ok := result["policies"].([]interface{}); ok {
		if len(policies) == 0 {
			fmt.Println("No policies found.")
			return nil
		}
		if output == "table" {
			return OutputData(policies)
		}
	}

	return OutputData(result)
}

func runPolicyGet(cmd *cobra.Command, args []string) error {
	client := NewAPIClient(serverURL, token)
	policyID := args[0]

	resp, err := client.Get(fmt.Sprintf("/api/v1/policies/%s", policyID))
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

func runPolicyCreate(cmd *cobra.Command, args []string) error {
	client := NewAPIClient(serverURL, token)

	var policyReq map[string]interface{}

	// Load policy data from file or inline
	if policyFile != "" {
		data, err := os.ReadFile(policyFile)
		if err != nil {
			return fmt.Errorf("failed to read file: %w", err)
		}
		if err := json.Unmarshal(data, &policyReq); err != nil {
			return fmt.Errorf("failed to parse JSON: %w", err)
		}
	} else if policyData != "" {
		if err := json.Unmarshal([]byte(policyData), &policyReq); err != nil {
			return fmt.Errorf("failed to parse JSON: %w", err)
		}
	} else {
		// Build from flags
		if policyName == "" || policyContent == "" {
			return fmt.Errorf("either --file, --data, or --name and --content must be provided")
		}
		policyReq = map[string]interface{}{
			"name":           policyName,
			"description":    policyDescription,
			"language":       policyLanguage,
			"policy_content": policyContent,
			"effect":         policyEffect,
			"priority":       policyPriority,
			"enabled":        policyCreateEnabled,
		}
	}

	resp, err := client.Post("/api/v1/policies", policyReq)
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

	PrintSuccess("Policy created successfully")
	return OutputData(result)
}

func runPolicyUpdate(cmd *cobra.Command, args []string) error {
	client := NewAPIClient(serverURL, token)
	policyID := args[0]

	var updateReq map[string]interface{}

	// Load update data from file or inline
	if policyFile != "" {
		data, err := os.ReadFile(policyFile)
		if err != nil {
			return fmt.Errorf("failed to read file: %w", err)
		}
		if err := json.Unmarshal(data, &updateReq); err != nil {
			return fmt.Errorf("failed to parse JSON: %w", err)
		}
	} else if policyData != "" {
		if err := json.Unmarshal([]byte(policyData), &updateReq); err != nil {
			return fmt.Errorf("failed to parse JSON: %w", err)
		}
	} else {
		return fmt.Errorf("either --file or --data must be provided")
	}

	resp, err := client.Put(fmt.Sprintf("/api/v1/policies/%s", policyID), updateReq)
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

	PrintSuccess("Policy updated successfully")
	return OutputData(result)
}

func runPolicyDelete(cmd *cobra.Command, args []string) error {
	client := NewAPIClient(serverURL, token)
	policyID := args[0]

	if !policyForce {
		fmt.Printf("Are you sure you want to delete policy %s? (y/N): ", policyID)
		var response string
		fmt.Scanln(&response)
		if response != "y" && response != "Y" {
			fmt.Println("Deletion cancelled.")
			return nil
		}
	}

	resp, err := client.Delete(fmt.Sprintf("/api/v1/policies/%s", policyID))
	if err != nil {
		return err
	}

	if err := CheckResponse(resp); err != nil {
		return err
	}

	PrintSuccess(fmt.Sprintf("Policy %s deleted successfully", policyID))
	return nil
}

func runPolicyEvaluate(cmd *cobra.Command, args []string) error {
	client := NewAPIClient(serverURL, token)

	var evalReq map[string]interface{}

	// Load evaluation request from file or inline
	if policyFile != "" {
		data, err := os.ReadFile(policyFile)
		if err != nil {
			return fmt.Errorf("failed to read file: %w", err)
		}
		if err := json.Unmarshal(data, &evalReq); err != nil {
			return fmt.Errorf("failed to parse JSON: %w", err)
		}
	} else if policyData != "" {
		if err := json.Unmarshal([]byte(policyData), &evalReq); err != nil {
			return fmt.Errorf("failed to parse JSON: %w", err)
		}
	} else {
		return fmt.Errorf("either --file or --data must be provided")
	}

	resp, err := client.Post("/api/v1/policies/evaluate", evalReq)
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
