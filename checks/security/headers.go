package security

import (
	"net/http"

	"github.com/mkafonso/hunter/types"
)

type SecurityHeadersCheck struct{}

var requiredHeaders = []string{
	"Strict-Transport-Security",
	"X-Content-Type-Options",
	"X-Frame-Options",
	"X-XSS-Protection",
	"Referrer-Policy",
}

func (s SecurityHeadersCheck) Name() string {
	return "Missing Security Headers"
}

func (s SecurityHeadersCheck) Run(resp *http.Response) []types.Finding {
	findings := []types.Finding{}

	for _, header := range requiredHeaders {
		if resp.Header.Get(header) == "" {
			findings = append(findings, types.Finding{
				Type:    "security",
				Message: "Missing header: " + header,
				Path:    resp.Request.URL.Path,
			})
		}
	}

	return findings
}
