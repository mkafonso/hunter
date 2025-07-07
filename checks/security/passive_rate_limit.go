package security

import (
	"net/http"
	"strconv"

	"github.com/mkafonso/hunter/types"
)

type PassiveRateLimitCheck struct{}

func (r PassiveRateLimitCheck) Name() string {
	return "Passive Rate Limiting Check"
}

func (r PassiveRateLimitCheck) Run(resp *http.Response) []types.Finding {
	findings := []types.Finding{}
	headers := resp.Header

	limit := headers.Get("X-RateLimit-Limit")
	remaining := headers.Get("X-RateLimit-Remaining")
	retry := headers.Get("Retry-After")

	// 1. No rate limiting headers
	if limit == "" && remaining == "" && retry == "" {
		findings = append(findings, types.Finding{
			Type:    "security",
			Message: "SECURITY_PASSIVE_RATE_LIMIT_HEADERS_NOT_FOUND",
			Path:    resp.Request.URL.Path,
		})
	}

	// 2. Headers present but limit = 0
	if limit == "0" {
		findings = append(findings, types.Finding{
			Type:    "security",
			Message: "SECURITY_PASSIVE_RATE_LIMIT_DISABLED",
			Path:    resp.Request.URL.Path,
		})
	}

	// 3. Limit < Remaining (inconsistency)
	if l, err1 := strconv.Atoi(limit); err1 == nil {
		if r, err2 := strconv.Atoi(remaining); err2 == nil && r > l {
			findings = append(findings, types.Finding{
				Type:    "security",
				Message: "SECURITY_PASSIVE_RATE_LIMIT_MISCONFIGURATION",
				Path:    resp.Request.URL.Path,
			})
		}
	}

	return findings
}
