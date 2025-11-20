package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"text/tabwriter"

	"gopkg.in/yaml.v3"
)

var debugWriter io.Writer = os.Stderr

// OutputData prints data in the specified format
func OutputData(data interface{}) error {
	switch output {
	case "json":
		return outputJSON(data)
	case "yaml":
		return outputYAML(data)
	case "table":
		return outputTable(data)
	default:
		return fmt.Errorf("unsupported output format: %s", output)
	}
}

func outputJSON(data interface{}) error {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(data)
}

func outputYAML(data interface{}) error {
	encoder := yaml.NewEncoder(os.Stdout)
	defer encoder.Close()
	return encoder.Encode(data)
}

func outputTable(data interface{}) error {
	// Handle different data types
	switch v := data.(type) {
	case []interface{}:
		if len(v) == 0 {
			fmt.Println("No results found.")
			return nil
		}
		return printTableFromSlice(v)
	case map[string]interface{}:
		return printTableFromMap(v)
	default:
		// Fallback to JSON if we can't determine how to print as table
		return outputJSON(data)
	}
}

func printTableFromSlice(items []interface{}) error {
	if len(items) == 0 {
		return nil
	}

	// Get the first item to determine columns
	firstItem := items[0]
	headers, err := extractHeaders(firstItem)
	if err != nil {
		return err
	}

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	defer w.Flush()

	// Print headers
	fmt.Fprintln(w, strings.Join(headers, "\t"))
	fmt.Fprintln(w, strings.Repeat("-", len(headers)*20))

	// Print rows
	for _, item := range items {
		values, err := extractValues(item, headers)
		if err != nil {
			return err
		}
		fmt.Fprintln(w, strings.Join(values, "\t"))
	}

	return nil
}

func printTableFromMap(m map[string]interface{}) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', 0)
	defer w.Flush()

	for key, value := range m {
		fmt.Fprintf(w, "%s:\t%v\n", key, formatValue(value))
	}

	return nil
}

func extractHeaders(item interface{}) ([]string, error) {
	m, ok := item.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("expected map[string]interface{}, got %T", item)
	}

	var headers []string
	// Define preferred order for common fields
	preferredOrder := []string{"id", "name", "description", "enabled", "created_at", "updated_at"}

	// Add preferred headers first if they exist
	for _, key := range preferredOrder {
		if _, exists := m[key]; exists {
			headers = append(headers, strings.ToUpper(key))
		}
	}

	// Add remaining headers
	for key := range m {
		if !contains(preferredOrder, key) {
			headers = append(headers, strings.ToUpper(key))
		}
	}

	return headers, nil
}

func extractValues(item interface{}, headers []string) ([]string, error) {
	m, ok := item.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("expected map[string]interface{}, got %T", item)
	}

	var values []string
	for _, header := range headers {
		key := strings.ToLower(header)
		value := m[key]
		values = append(values, formatValue(value))
	}

	return values, nil
}

func formatValue(v interface{}) string {
	if v == nil {
		return ""
	}

	switch val := v.(type) {
	case string:
		// Truncate long strings
		if len(val) > 50 {
			return val[:47] + "..."
		}
		return val
	case bool:
		if val {
			return "✓"
		}
		return "✗"
	case float64:
		return fmt.Sprintf("%.0f", val)
	case []interface{}:
		if len(val) == 0 {
			return "[]"
		}
		// Format arrays concisely
		items := make([]string, 0, len(val))
		for _, item := range val {
			items = append(items, fmt.Sprintf("%v", item))
		}
		result := "[" + strings.Join(items, ", ") + "]"
		if len(result) > 50 {
			return result[:47] + "..."
		}
		return result
	case map[string]interface{}:
		if len(val) == 0 {
			return "{}"
		}
		return fmt.Sprintf("{%d fields}", len(val))
	default:
		return fmt.Sprintf("%v", v)
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// PrintSuccess prints a success message
func PrintSuccess(message string) {
	fmt.Fprintf(os.Stdout, "✓ %s\n", message)
}

// PrintError prints an error message
func PrintError(message string) {
	fmt.Fprintf(os.Stderr, "✗ Error: %s\n", message)
}

// PrintWarning prints a warning message
func PrintWarning(message string) {
	fmt.Fprintf(os.Stderr, "⚠ Warning: %s\n", message)
}

// ParseJSONValue converts a string value to its appropriate type
func ParseJSONValue(value string) interface{} {
	// Try to parse as JSON first
	var result interface{}
	if err := json.Unmarshal([]byte(value), &result); err == nil {
		return result
	}

	// Return as string if not valid JSON
	return value
}

// MergeObjects merges multiple map objects
func MergeObjects(objects ...map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})
	for _, obj := range objects {
		for k, v := range obj {
			result[k] = v
		}
	}
	return result
}

// ConvertToMap converts a struct to map[string]interface{}
func ConvertToMap(v interface{}) (map[string]interface{}, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, err
	}

	return result, nil
}

// ExtractListFromResponse extracts a list from various response formats
func ExtractListFromResponse(data map[string]interface{}) []interface{} {
	// Try common list field names
	listFields := []string{"policies", "entitlements", "audit_logs", "items", "data", "results"}

	for _, field := range listFields {
		if list, ok := data[field].([]interface{}); ok {
			return list
		}
	}

	// If no list field found, check if data itself is the list
	v := reflect.ValueOf(data)
	if v.Kind() == reflect.Slice {
		return data[reflect.TypeOf(data).Name()].([]interface{})
	}

	return nil
}
