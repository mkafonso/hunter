package structure

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/mkafonso/hunter/types"
)

type VersioningCheck struct{}

func (v VersioningCheck) Name() string {
	return "Versioning Presence"
}

func (v VersioningCheck) Run(resp *http.Response) []types.Finding {
	findings := []types.Finding{}

	urlPath := resp.Request.URL.Path
	query := resp.Request.URL.RawQuery

	// 1. Detect versioning in path (e.g., /v1/, /api/v2/)
	versioningPattern := regexp.MustCompile(`/(v|version)[0-9]+`)
	if !versioningPattern.MatchString(urlPath) {
		findings = append(findings, types.Finding{
			Type:    "structure",
			Message: "Missing versioning in API path",
			Path:    urlPath,
		})
	}

	// 2. Detect versioning via query param
	if strings.Contains(strings.ToLower(query), "version=") {
		findings = append(findings, types.Finding{
			Type:    "structure",
			Message: "Versioning via query param is discouraged (use path-based versioning)",
			Path:    urlPath,
		})
	}

	return findings
}
