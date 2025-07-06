package cmd

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/mkafonso/hunter/checks/security"
	"github.com/mkafonso/hunter/types"
	"github.com/spf13/cobra"
)

var scanCmd = &cobra.Command{
	Use:   "scan [url]",
	Short: "Scan a REST API endpoint",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		url := args[0]
		client := &http.Client{Timeout: 10 * time.Second}

		resp, err := client.Get(url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ Error fetching URL: %v\n", err)
			os.Exit(1)
		}
		defer resp.Body.Close()

		var allFindings []types.Finding

		checks := []types.Check{
			security.SecurityHeadersCheck{},
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
