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
			Message: "No rate-limiting headers found (e.g., X-RateLimit-Limit, Retry-After)",
			Path:    resp.Request.URL.Path,
		})
	}

	// 2. Headers present but limit = 0
	if limit == "0" {
		findings = append(findings, types.Finding{
			Type:    "security",
			Message: "X-RateLimit-Limit is set to 0 — rate limiting may be disabled",
			Path:    resp.Request.URL.Path,
		})
	}

	// 3. Limit < Remaining (inconsistency)
	if l, err1 := strconv.Atoi(limit); err1 == nil {
		if r, err2 := strconv.Atoi(remaining); err2 == nil && r > l {
			findings = append(findings, types.Finding{
				Type:    "security",
				Message: "X-RateLimit-Remaining is greater than X-RateLimit-Limit — possible misconfiguration",
				Path:    resp.Request.URL.Path,
			})
		}
	}

	// 4. 429 received = rate limit working (positive)
	if resp.StatusCode == 429 {
		findings = append(findings, types.Finding{
			Type:    "info",
			Message: "Received 429 Too Many Requests — rate limiting appears to be enforced",
			Path:    resp.Request.URL.Path,
		})
	}

	return findings
}
