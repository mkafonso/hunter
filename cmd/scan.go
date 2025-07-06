package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/mkafonso/hunter/checks/performance"
	"github.com/mkafonso/hunter/checks/security"
	"github.com/mkafonso/hunter/types"
	"github.com/mkafonso/hunter/utils"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan [url]",
	Short: "Scan a REST API endpoint",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		url := args[0]

		resp, latency, err := utils.FetchWithMetrics(url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error fetching URL: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		ctx := context.WithValue(resp.Request.Context(), "latency", latency)
		resp.Request = resp.Request.WithContext(ctx)

		var allFindings []types.Finding

		checks := []types.Check{
			security.SecurityHeadersCheck{},
			performance.LatencyCheck{Threshold: 500 * time.Millisecond},
		}

		for _, check := range checks {
			findings := check.Run(resp)
			allFindings = append(allFindings, findings...)
		}

		report := map[string]any{
			"score":  100 - len(allFindings)*5,
			"issues": allFindings,
		}

		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(report)
	},
}

func init() {
	rootCmd.AddCommand(scanCmd)
}
