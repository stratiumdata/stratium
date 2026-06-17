package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
)

var (
	papURL     string
	authToken  string
	format     string
	outputFile string
	insecure   bool
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "stratium-audit",
		Short: "Stratium audit trail CLI — admin-only access to authorization decisions",
	}

	rootCmd.PersistentFlags().StringVar(&papURL, "pap-url", envOrDefault("STRATIUM_PAP_URL", "https://localhost:8090"), "PAP server URL")
	rootCmd.PersistentFlags().StringVar(&authToken, "token", os.Getenv("STRATIUM_AUTH_TOKEN"), "Authentication token")
	rootCmd.PersistentFlags().StringVar(&format, "format", "table", "Output format: table, json, csv")
	rootCmd.PersistentFlags().BoolVarP(&insecure, "insecure", "k", true, "Skip TLS certificate verification (for self-signed certs)")

	rootCmd.AddCommand(logsCmd())
	rootCmd.AddCommand(chainCmd())
	rootCmd.AddCommand(agentSummaryCmd())
	rootCmd.AddCommand(exportCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func logsCmd() *cobra.Command {
	var (
		limit     int
		since     string
		agentID   string
		decision  string
		tierMin   int
		provider  string
		transport string
	)

	cmd := &cobra.Command{
		Use:   "logs",
		Short: "List recent authorization decisions",
		RunE: func(cmd *cobra.Command, args []string) error {
			params := url.Values{}
			params.Set("limit", fmt.Sprintf("%d", limit))

			if since != "" {
				d, err := parseDuration(since)
				if err != nil {
					return fmt.Errorf("invalid --since value: %w", err)
				}
				params.Set("start_date", time.Now().Add(-d).Format(time.RFC3339))
			}
			if agentID != "" {
				params.Set("actor", agentID)
			}
			if decision != "" {
				params.Set("action", decision)
			}
			if provider != "" {
				params.Set("provider", provider)
			}
			if transport != "" {
				params.Set("transport", transport)
			}

			logs, err := fetchAuditLogs(params)
			if err != nil {
				return err
			}

			_ = tierMin // reserved for future filtering
			return printLogs(logs)
		},
	}

	cmd.Flags().IntVar(&limit, "limit", 20, "Max entries to return")
	cmd.Flags().StringVar(&since, "since", "", "Time window (e.g., 5m, 1h, 24h)")
	cmd.Flags().StringVar(&agentID, "agent-id", "", "Filter by agent ID")
	cmd.Flags().StringVar(&decision, "decision", "", "Filter by decision (ALLOW, DENY)")
	cmd.Flags().IntVar(&tierMin, "action-tier", -1, "Filter by minimum action tier")
	cmd.Flags().StringVar(&provider, "provider", "", "Filter by provider (anthropic, openai, custom)")
	cmd.Flags().StringVar(&transport, "transport", "", "Filter by transport layer (mcp, mcp-check, grpc)")

	return cmd
}

func chainCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "chain [delegation-id]",
		Short: "Show delegation chain activity",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			delegationID := args[0]
			params := url.Values{}
			params.Set("entity_id", delegationID)
			params.Set("limit", "50")

			logs, err := fetchAuditLogs(params)
			if err != nil {
				return err
			}

			fmt.Printf("Delegation chain: %s\n\n", delegationID)
			return printLogs(logs)
		},
	}
}

func agentSummaryCmd() *cobra.Command {
	var since string

	cmd := &cobra.Command{
		Use:   "agent-summary [agent-id]",
		Short: "Show agent activity summary",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			params := url.Values{}
			params.Set("actor", args[0])
			params.Set("limit", "100")

			if since != "" {
				d, err := parseDuration(since)
				if err != nil {
					return fmt.Errorf("invalid --since value: %w", err)
				}
				params.Set("start_date", time.Now().Add(-d).Format(time.RFC3339))
			}

			logs, err := fetchAuditLogs(params)
			if err != nil {
				return err
			}

			// Summarize
			var allows, denies int
			toolCounts := map[string]int{}
			for _, l := range logs {
				if result, ok := l["result"].(map[string]any); ok {
					if auth, ok := result["authorized"].(bool); ok {
						if auth {
							allows++
						} else {
							denies++
						}
					}
				}
				if tool, ok := l["tool"].(string); ok {
					toolCounts[tool]++
				}
			}

			fmt.Printf("Agent: %s\n", args[0])
			fmt.Printf("Total actions: %d (ALLOW: %d, DENY: %d)\n\n", allows+denies, allows, denies)

			if len(toolCounts) > 0 {
				fmt.Println("Tool usage:")
				for tool, count := range toolCounts {
					fmt.Printf("  %-30s %d\n", tool, count)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&since, "since", "24h", "Time window")
	return cmd
}

func exportCmd() *cobra.Command {
	var since string

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export audit logs for compliance",
		RunE: func(cmd *cobra.Command, args []string) error {
			params := url.Values{}
			params.Set("limit", "100")

			if since != "" {
				d, err := parseDuration(since)
				if err != nil {
					return fmt.Errorf("invalid --since value: %w", err)
				}
				params.Set("start_date", time.Now().Add(-d).Format(time.RFC3339))
			}

			logs, err := fetchAuditLogs(params)
			if err != nil {
				return err
			}

			data, err := json.MarshalIndent(logs, "", "  ")
			if err != nil {
				return err
			}

			if outputFile != "" {
				return os.WriteFile(outputFile, data, 0644)
			}
			fmt.Println(string(data))
			return nil
		},
	}

	cmd.Flags().StringVar(&since, "since", "7d", "Time window")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path")
	return cmd
}

func httpClient() *http.Client {
	if insecure {
		return &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		}
	}
	return http.DefaultClient
}

func fetchAuditLogs(params url.Values) ([]map[string]any, error) {
	reqURL := fmt.Sprintf("%s/api/v1/audit-logs?%s", papURL, params.Encode())

	req, err := http.NewRequest("GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	if authToken != "" {
		req.Header.Set("Authorization", "Bearer "+authToken)
	}

	resp, err := httpClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PAP at %s: %w", papURL, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("PAP returned %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Logs []map[string]any `json:"audit_logs"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return result.Logs, nil
}

func printLogs(logs []map[string]any) error {
	switch format {
	case "json":
		data, err := json.MarshalIndent(logs, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(data))
		return nil

	case "csv":
		fmt.Println("timestamp,agent,provider,transport,tool,tier,decision,reason")
		for _, l := range logs {
			fmt.Printf("%s,%s,%s,%s,%s,%v,%s,%s\n",
				getStr(l, "timestamp"), getStr(l, "actor"),
				getStr(l, "provider"), getStr(l, "transport"),
				getStr(l, "tool"), l["tier"],
				getStr(l, "decision"), getStr(l, "reason"))
		}
		return nil

	default: // table
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "TIMESTAMP\tAGENT\tPROVIDER\tLAYER\tTOOL\tTIER\tDECISION\tREASON")
		for _, l := range logs {
			ts := getStr(l, "timestamp")
			if len(ts) > 19 {
				ts = ts[:19]
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%v\t%s\t%s\n",
				ts, truncate(getStr(l, "actor"), 20),
				truncate(getStr(l, "provider"), 10),
				truncate(getStr(l, "transport"), 10),
				truncate(getStr(l, "tool"), 14), l["tier"],
				getStr(l, "decision"), truncate(getStr(l, "reason"), 40))
		}
		return w.Flush()
	}
}

func getStr(m map[string]any, key string) string {
	if v, ok := m[key]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-1] + "…"
}

func parseDuration(s string) (time.Duration, error) {
	// Support d (days) suffix in addition to Go's standard durations
	if strings.HasSuffix(s, "d") {
		s = strings.TrimSuffix(s, "d")
		var days int
		if _, err := fmt.Sscanf(s, "%d", &days); err != nil {
			return 0, err
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	return time.ParseDuration(s)
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
