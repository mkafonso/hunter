package markdownreport

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/mkafonso/hunter/knowledge"
	"github.com/mkafonso/hunter/types"
)

func Generate(findings []types.Finding) {
	score := max(0, 100-len(findings)*5)

	exportPath := "exports/report.md"
	if err := os.MkdirAll(filepath.Dir(exportPath), os.ModePerm); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Erro ao criar diretório exports/: %v\n", err)
		return
	}

	file, err := os.Create(exportPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Erro ao criar %s: %v\n", exportPath, err)
		return
	}
	defer file.Close()

	outputs := [](*os.File){os.Stdout, file}

	for _, out := range outputs {
		fmt.Fprintln(out, "# Hunter Scan Report")
		fmt.Fprintf(out, "**Score**: %d/100\n\n", score)

		if len(findings) == 0 {
			fmt.Fprintln(out, "✅ No issues detected.")
			continue
		}

		fmt.Fprintln(out, "## Issues")
		for i, f := range findings {
			extras := knowledge.Enrich(f.Message)

			fmt.Fprintf(out, "### %d. `%s`\n", i+1, f.Message)
			fmt.Fprintf(out, "**Type**: %s  \n", f.Type)
			fmt.Fprintf(out, "**Path**: `%s`\n\n", f.Path)

			if extras.Description != "" {
				fmt.Fprintf(out, "**Description:** %s\n\n", extras.Description)
			}
			if extras.Recommendation != "" {
				fmt.Fprintf(out, "**Recommendation:** %s\n\n", extras.Recommendation)
			}
			if len(extras.References) > 0 {
				fmt.Fprintln(out, "**References:**")
				for _, ref := range extras.References {
					fmt.Fprintf(out, "- [%s](%s)\n", ref, ref)
				}
				fmt.Fprintln(out)
			}
		}
	}
}
