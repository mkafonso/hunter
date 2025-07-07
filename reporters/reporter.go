package reporters

import (
	"fmt"
	"os"

	jsonreport "github.com/mkafonso/hunter/reporters/json"
	"github.com/mkafonso/hunter/types"
)

func Report(format string, findings []types.Finding) {
	switch format {
	case "json":
		jsonreport.Generate(findings)

	default:
		fmt.Fprintf(os.Stderr, "Formato de relatório não suportado: %s\n", format)
		os.Exit(1)
	}
}
