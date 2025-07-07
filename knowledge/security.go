package knowledge

import (
	"strings"

	"github.com/mkafonso/hunter/types"
)

func enrichSecurity(finding string) *types.EnrichedInfo {
	switch {
	case strings.Contains(finding, "SECURITY_ACTIVE_RATE_LIMIT_NOT_DETECTED"):
		return &types.EnrichedInfo{
			Description:    "No rate limiting was observed — the API responded normally to multiple rapid requests.",
			Recommendation: "Implement rate limiting to prevent abuse and reduce attack surface.",
			References:     []string{"https://developer.mozilla.org/en-US/docs/Glossary/Rate_limit"},
		}

	case strings.Contains(finding, "SECURITY_CORS_MISCONFIGURATION"):
		return &types.EnrichedInfo{
			Description:    "The 'Access-Control-Allow-Origin' header is set to '*', allowing any domain to access the resource.",
			Recommendation: "Restrict 'Access-Control-Allow-Origin' to trusted domains only.",
			References:     []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"},
		}

	case strings.Contains(finding, "SECURITY_CORS_CREDENTIALS_WITH_WILDCARD_ORIGIN"):
		return &types.EnrichedInfo{
			Description:    "'Access-Control-Allow-Credentials' is true while origin is '*', which is invalid per the CORS spec and creates security risks.",
			Recommendation: "Use specific origins instead of '*', or disable credentials if open access is required.",
			References:     []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials"},
		}

	case strings.Contains(finding, "SECURITY_CORS_ALLOW_ALL_HEADERS"):
		return &types.EnrichedInfo{
			Description:    "The 'Access-Control-Allow-Headers' header includes '*', potentially exposing sensitive data to cross-origin requests.",
			Recommendation: "Explicitly list only the necessary headers in 'Access-Control-Allow-Headers'.",
			References:     []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Headers"},
		}

	case strings.Contains(finding, "SECURITY_CORS_DANGEROUS_METHODS_ALLOWED"):
		return &types.EnrichedInfo{
			Description:    "CORS configuration allows dangerous HTTP methods like 'DELETE' or wildcard '*', which may enable cross-origin abuse.",
			Recommendation: "Restrict 'Access-Control-Allow-Methods' to safe methods such as 'GET' and 'POST'.",
			References:     []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Methods"},
		}

	case strings.Contains(finding, "SECURITY_HEADER_EXPOSURE_DETECTED"):
		return &types.EnrichedInfo{
			Description:    "Response includes headers that may reveal server technologies, versions, or internal infrastructure — useful for attackers.",
			Recommendation: "Remove or mask sensitive headers such as 'Server', 'X-Powered-By', and 'X-Backend-Server' in production environments.",
			References:     []string{"https://owasp.org/www-project-secure-headers/", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server"},
		}

	case strings.Contains(finding, "SECURITY_PASSIVE_RATE_LIMIT_HEADERS_NOT_FOUND"):
		return &types.EnrichedInfo{
			Description:    "No rate-limiting headers were found in the response, making it unclear whether abuse protection is in place.",
			Recommendation: "Add standard rate-limiting headers such as 'X-RateLimit-Limit' and 'Retry-After' to inform clients and improve security.",
			References:     []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Retry-After"},
		}

	case strings.Contains(finding, "SECURITY_PASSIVE_RATE_LIMIT_DISABLED"):
		return &types.EnrichedInfo{
			Description:    "Rate limiting appears to be disabled as 'X-RateLimit-Limit' is set to 0.",
			Recommendation: "Set a reasonable rate limit to prevent abuse and protect backend resources.",
			References:     []string{"https://cheatsheetseries.owasp.org/cheatsheets/Rate_Limiting_Cheat_Sheet.html"},
		}

	case strings.Contains(finding, "SECURITY_PASSIVE_RATE_LIMIT_MISCONFIGURATION"):
		return &types.EnrichedInfo{
			Description:    "'X-RateLimit-Remaining' is greater than 'X-RateLimit-Limit', indicating a possible configuration error.",
			Recommendation: "Ensure rate-limiting headers are calculated and returned consistently by the API gateway or backend.",
			References:     []string{"https://tools.ietf.org/id/draft-polli-ratelimit-headers-03.html"},
		}

	case strings.Contains(finding, "SECURITY_HEADER_MISSING"):
		return &types.EnrichedInfo{
			Description:    "A required security header is missing. These headers help protect against common vulnerabilities such as clickjacking, MIME-type sniffing, and XSS.",
			Recommendation: "Ensure headers like 'Strict-Transport-Security', 'X-Content-Type-Options', 'X-Frame-Options', 'X-XSS-Protection', and 'Referrer-Policy' are included in responses.",
			References:     []string{"https://owasp.org/www-project-secure-headers/", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers"},
		}

	default:
		return nil
	}
}
