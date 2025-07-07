package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/mkafonso/hunter/checks/performance"
	"github.com/mkafonso/hunter/checks/security"
	"github.com/mkafonso/hunter/checks/structure"
	"github.com/mkafonso/hunter/checks/vulnerabilities"
	"github.com/mkafonso/hunter/reporters"
	"github.com/mkafonso/hunter/scanner"
	"github.com/mkafonso/hunter/types"
	"github.com/spf13/cobra"
)

var reportFormat string

var scanCmd = &cobra.Command{
	Use:   "scan [url]",
	Short: "Scan a REST API endpoint",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		url := args[0]

		resp, latency, err := scanner.FetchWithMetrics(url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error fetching URL: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		ctx := context.WithValue(resp.Request.Context(), "latency", latency)
		resp.Request = resp.Request.WithContext(ctx)

		var allFindings []types.Finding

		checks := []types.Check{
			vulnerabilities.StacktraceCheck{},

			security.SecurityHeadersCheck{},
			security.CORSCheck{},
			security.HeadersExposureCheck{},
			security.PassiveRateLimitCheck{},
			security.ActiveRateLimitCheck{Requests: 10, Delay: 0, Timeout: 3 * time.Second},

			structure.StatusCodeCheck{},
			structure.VersioningCheck{},
			structure.MethodUsageCheck{},
			structure.InconsistentFieldCasingCheck{},

			performance.CompressionCheck{},
			performance.LatencyCheck{Threshold: 500 * time.Millisecond}, // 500ms
			performance.PayloadSizeCheck{MaxBytes: 500 * 1024},          // 500KB
		}

		for _, check := range checks {
			findings := check.Run(resp)
			allFindings = append(allFindings, findings...)
		}

		reporters.Report(reportFormat, allFindings)
	},
}

func init() {
	scanCmd.Flags().StringVarP(&reportFormat, "report", "r", "json", "Formato do relatório: json, markdown, html, slack")
	rootCmd.AddCommand(scanCmd)
}
