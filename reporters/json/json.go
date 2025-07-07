package jsonreport

import (
	"encoding/json"
	"os"

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
		extras := enrich(f.Message)
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

	out := json.NewEncoder(os.Stdout)
	out.SetIndent("", "  ")
	out.Encode(report)
}
