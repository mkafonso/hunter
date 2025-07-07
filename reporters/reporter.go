package reporters

import (
	"fmt"
	"os"

	json "github.com/mkafonso/hunter/reporters/json"
	markdown "github.com/mkafonso/hunter/reporters/markdown"
	"github.com/mkafonso/hunter/types"
)

func Report(format string, findings []types.Finding) {
	switch format {
	case "json":
		json.Generate(findings)

	case "markdown":
		markdown.Generate(findings)

	default:
		fmt.Fprintf(os.Stderr, "Formato de relatório não suportado: %s\n", format)
		os.Exit(1)
	}
}
