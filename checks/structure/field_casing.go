package structure

import (
	"encoding/json"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/mkafonso/hunter/types"
)

type InconsistentFieldCasingCheck struct{}

func (f InconsistentFieldCasingCheck) Name() string {
	return "Field Naming Casing Consistency"
}

func (f InconsistentFieldCasingCheck) Run(resp *http.Response) []types.Finding {
	findings := []types.Finding{}

	if !strings.Contains(resp.Header.Get("Content-Type"), "application/json") {
		return findings
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return findings
	}
	resp.Body = io.NopCloser(strings.NewReader(string(body)))

	var data any
	if err := json.Unmarshal(body, &data); err != nil {
		return findings
	}

	casingCounts := map[string]int{}
	countFieldCasings(data, casingCounts)

	if len(casingCounts) > 1 {
		findings = append(findings, types.Finding{
			Type:    "structure",
			Message: "STRUCTURE_FIELD_CASING_INCONSISTENT",
			Path:    resp.Request.URL.Path,
		})
	}

	return findings
}

func countFieldCasings(data any, counts map[string]int) {
	switch v := data.(type) {
	case map[string]any:
		for key, val := range v {
			switch {
			case isCamelCase(key):
				counts["camelCase"]++
			case isSnakeCase(key):
				counts["snake_case"]++
			case isPascalCase(key):
				counts["PascalCase"]++
			default:
				counts["other"]++
			}
			countFieldCasings(val, counts)
		}
	case []any:
		for _, item := range v {
			countFieldCasings(item, counts)
		}
	}
}

func isCamelCase(s string) bool {
	return regexp.MustCompile(`^[a-z]+(?:[A-Z][a-z0-9]*)*$`).MatchString(s)
}

func isSnakeCase(s string) bool {
	return regexp.MustCompile(`^[a-z]+(_[a-z0-9]+)*$`).MatchString(s)
}

func isPascalCase(s string) bool {
	return regexp.MustCompile(`^[A-Z][a-zA-Z0-9]*$`).MatchString(s)
}
