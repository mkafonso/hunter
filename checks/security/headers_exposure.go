package security

import (
	"net/http"
	"strings"

	"github.com/mkafonso/hunter/types"
)

type HeadersExposureCheck struct{}

func (s HeadersExposureCheck) Name() string {
	return "Sensitive Headers Exposure"
}

func (s HeadersExposureCheck) Run(resp *http.Response) []types.Finding {
	findings := []types.Finding{}
	counter := 1

	headersExposure := []string{
		"Server",
		"X-Powered-By",
		"X-AspNet-Version",
		"X-Runtime",
		"X-Version",
		"X-Generator",
		"X-Backend-Server",
		"X-Drupal-Cache",
		"Via",
		"X-Forwarded-Server",
	}

	for _, header := range headersExposure {
		value := strings.TrimSpace(resp.Header.Get(header))
		if value != "" && !isGenericOrMasked(value) {
			findings = append(findings, types.Finding{
				Type:    "security",
				Message: "SECURITY_HEADER_EXPOSURE_DETECTED",
				Path:    resp.Request.URL.Path,
			})
			counter++
		}
	}

	return findings
}

func isGenericOrMasked(value string) bool {
	v := strings.ToLower(strings.TrimSpace(value))
	safeValues := []string{"", "unknown", "hidden", "masked", "none", "removed", "n/a"}
	for _, safe := range safeValues {
		if v == safe {
			return true
		}
	}
	return false
}
