package jsonreport

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/mkafonso/hunter/knowledge"
	"github.com/mkafonso/hunter/types"
)

type DetailedFinding struct {
	Type           string   `json:"type"`
	Message        string   `json:"message"`
	Path           string   `json:"path"`
	Description    string   `json:"description,omitempty"`
	Recommendation string   `json:"recommendation,omitempty"`
	References     []string `json:"references,omitempty"`
}

type Report struct {
	Score  int               `json:"score"`
	Issues []DetailedFinding `json:"issues"`
}

func Generate(findings []types.Finding) {
	var enriched []DetailedFinding

	for _, f := range findings {
		extras := knowledge.Enrich(f.Message)
		enriched = append(enriched, DetailedFinding{
			Type:           f.Type,
			Message:        f.Message,
			Path:           f.Path,
			Description:    extras.Description,
			Recommendation: extras.Recommendation,
			References:     extras.References,
		})
	}

	report := Report{
		Score:  100 - len(enriched)*5,
		Issues: enriched,
	}

	// Print in the terminal
	_ = json.NewEncoder(os.Stdout).Encode(report)

	exportPath := "exports/report.json"
	if err := os.MkdirAll(filepath.Dir(exportPath), os.ModePerm); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Erro ao criar diretório exports/: %v\n", err)
		return
	}

	// Save file
	file, err := os.Create(exportPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ Erro ao criar %s: %v\n", exportPath, err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(report); err != nil {
		fmt.Fprintf(os.Stderr, "❌ Erro ao escrever JSON: %v\n", err)
	}
}
