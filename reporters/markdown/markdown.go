package markdownreport

import (
	"fmt"
	"os"

	"github.com/mkafonso/hunter/knowledge"
	"github.com/mkafonso/hunter/types"
)

func Generate(findings []types.Finding) {
	fmt.Fprintln(os.Stdout, "# Hunter Scan Report")
	fmt.Fprintln(os.Stdout)

	score := max(0, 100-len(findings)*5)

	fmt.Fprintf(os.Stdout, "**Score**: %d/100\n\n", score)

	if len(findings) == 0 {
		fmt.Fprintln(os.Stdout, "✅ No issues detected.")
		return
	}

	fmt.Fprintln(os.Stdout, "## Issues")

	for i, f := range findings {
		extras := knowledge.Enrich(f.Message)

		fmt.Fprintf(os.Stdout, "### %d. `%s`\n", i+1, f.Message)
		fmt.Fprintf(os.Stdout, "**Type**: %s  \n", f.Type)
		fmt.Fprintf(os.Stdout, "**Path**: `%s`\n\n", f.Path)

		if extras.Description != "" {
			fmt.Fprintf(os.Stdout, "**Description:** %s\n\n", extras.Description)
		}
		if extras.Recommendation != "" {
			fmt.Fprintf(os.Stdout, "**Recommendation:** %s\n\n", extras.Recommendation)
		}
		if len(extras.References) > 0 {
			fmt.Fprintln(os.Stdout, "**References:**")
			for _, ref := range extras.References {
				fmt.Fprintf(os.Stdout, "- [%s](%s)\n", ref, ref)
			}
			fmt.Fprintln(os.Stdout)
		}
	}
}
