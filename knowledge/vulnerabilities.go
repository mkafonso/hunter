package knowledge

import (
	"strings"

	"github.com/mkafonso/hunter/types"
)

func enrichVulnerabilities(finding string) *types.EnrichedInfo {
	switch {
	case strings.Contains(finding, "VULNERABILITY_STACKTRACE_DETECTED"):
		return &types.EnrichedInfo{
			Description:    "A stacktrace was found in the response body, indicating a server-side error leaking internal details.",
			Recommendation: "Disable stacktrace exposure in and return generic error messages instead.",
			References:     []string{""},
		}

	case strings.Contains(finding, "VULNERABILITY_STACKTRACE_LANGUAGE_SPECIFIC"):
		return &types.EnrichedInfo{
			Description:    "The response body contains stacktrace patterns specific to languages like Java, Python, Node.js, Ruby, or PHP.",
			Recommendation: "Sanitize all error messages and configure the application to hide implementation details in production.",
			References:     []string{""},
		}

	default:
		return nil
	}
}
