package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mkafonso/hunter/checks/performance"
	"github.com/mkafonso/hunter/checks/security"
	"github.com/mkafonso/hunter/checks/structure"
	"github.com/mkafonso/hunter/checks/vulnerabilities"
	"github.com/mkafonso/hunter/discovery"
	"github.com/mkafonso/hunter/reporters"
	"github.com/mkafonso/hunter/scanner"
	"github.com/mkafonso/hunter/types"
	"github.com/spf13/cobra"
)

var reportFormat string

var scanCmd = &cobra.Command{
	Use:   "scan [url]",
	Short: "Scan a REST API endpoint or OpenAPI doc",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		url := args[0]
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
			performance.LatencyCheck{Threshold: 500 * time.Millisecond},
			performance.PayloadSizeCheck{MaxBytes: 500 * 1024},
		}

		opts := scanner.ScanOptions{
			Checks:  checks,
			Timeout: 5 * time.Second,
		}

		if strings.HasSuffix(url, ".json") {
			api, err := discovery.DiscoverFromOpenAPI(url)
			if err != nil {
				fmt.Fprintf(os.Stderr, "⚠️  Failed to parse OpenAPI: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("🔍 %d endpoints encontrados\n", len(api.FullURLs))

			for _, ep := range api.FullURLs {
				fmt.Printf("📦 Scanning %s\n", ep)
				opts.URL = ep
				findings, err := scanner.RunScan(opts)
				if err != nil {
					fmt.Fprintf(os.Stderr, "❌ %v\n", err)
					continue
				}
				allFindings = append(allFindings, findings...)
			}
		} else {
			opts.URL = url
			findings, err := scanner.RunScan(opts)
			if err != nil {
				fmt.Fprintf(os.Stderr, "❌ %v\n", err)
				os.Exit(1)
			}
			allFindings = findings
		}

		reporters.Report(reportFormat, allFindings)
	},
}

func init() {
	scanCmd.Flags().StringVarP(&reportFormat, "report", "r", "json", "Formato do relatório: json, markdown, html, slack")
	rootCmd.AddCommand(scanCmd)
}
