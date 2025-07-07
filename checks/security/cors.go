package security

import (
	"net/http"
	"strings"

	"github.com/mkafonso/hunter/types"
)

type CORSCheck struct{}

func (c CORSCheck) Name() string {
	return "CORS Configuration"
}

func (c CORSCheck) Run(resp *http.Response) []types.Finding {
	findings := []types.Finding{}

	origin := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Origin"))
	credentials := strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Credentials"))
	methods := resp.Header.Get("Access-Control-Allow-Methods")
	headers := resp.Header.Get("Access-Control-Allow-Headers")

	// 1. Wildcard origin
	if origin == "*" {
		findings = append(findings, types.Finding{
			Type:    "security",
			Message: "CORS misconfiguration: Access-Control-Allow-Origin is set to '*' (allows any domain)",
			Path:    resp.Request.URL.Path,
		})
	}

	// 2. Wildcard origin with credentials (invalid per spec)
	if origin == "*" && strings.EqualFold(credentials, "true") {
		findings = append(findings, types.Finding{
			Type:    "security",
			Message: "CORS violation: 'Access-Control-Allow-Credentials: true' cannot be used with wildcard origin '*'",
			Path:    resp.Request.URL.Path,
		})
	}

	// 3. Overly permissive methods
	if strings.Contains(methods, "*") || strings.Contains(methods, "DELETE") {
		findings = append(findings, types.Finding{
			Type:    "security",
			Message: "CORS configuration allows dangerous methods (e.g., '*', DELETE)",
			Path:    resp.Request.URL.Path,
		})
	}

	// 4. Overly permissive headers
	if strings.Contains(headers, "*") {
		findings = append(findings, types.Finding{
			Type:    "security",
			Message: "CORS configuration allows all headers via wildcard",
			Path:    resp.Request.URL.Path,
		})
	}

	return findings
}
