package jsonreport

import "strings"

type EnrichedInfo struct {
	Description    string
	Recommendation string
	References     []string
}

func enrich(findingMessage string) EnrichedInfo {
	switch {
	/**
	 * PERFORMANCE
	 */
	case strings.Contains(findingMessage, "PERFORMANCE_COMPRESSION_LARGE_UNCOMPRESSED_RESPONSE"):
		return EnrichedInfo{
			Description:    "Large responses without compression increase bandwidth usage and page load time.",
			Recommendation: "Enable gzip, br, or deflate compression for responses larger than 1KB.",
			References:     []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Encoding"},
		}

	case strings.Contains(findingMessage, "PERFORMANCE_COMPRESSION_MISSING_CONTENT_ENCODING_HEADER"):
		return EnrichedInfo{
			Description:    "The 'Content-Encoding' header is missing — response is likely uncompressed.",
			Recommendation: "Add the 'Content-Encoding' header and enable compression on the server.",
			References:     []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Encoding"},
		}

	case strings.Contains(findingMessage, "PERFORMANCE_LATENCY_EXCEEDED_THRESHOLD"):
		return EnrichedInfo{
			Description:    "The response time exceeded the acceptable latency threshold, which can degrade user experience.",
			Recommendation: "Optimize backend performance, cache frequent responses, or analyze slow dependencies.",
			References:     []string{"https://developer.mozilla.org/en-US/docs/Web/Performance", "https://web.dev/time-to-first-byte/"},
		}

	case strings.Contains(findingMessage, "PERFORMANCE_PAYLOAD_SIZE_EXCEEDS_LIMIT"):
		return EnrichedInfo{
			Description:    "The response payload size is larger than expected, which can slow down clients or mobile devices.",
			Recommendation: "Reduce payload size by removing unnecessary fields, paginating large datasets, or optimizing binary data.",
			References:     []string{"https://web.dev/optimize-lcp/", "https://developers.google.com/web/fundamentals/performance/optimizing-content-efficiency/"},
		}

	/**
	 * PERFORMANCE
	 */
	case strings.Contains(findingMessage, "SECURITY_ACTIVE_RATE_LIMIT_NOT_DETECTED"):
		return EnrichedInfo{
			Description:    "No rate limiting was observed — the API responded normally to multiple rapid requests.",
			Recommendation: "Implement rate limiting to prevent abuse and reduce attack surface.",
			References:     []string{"https://developer.mozilla.org/en-US/docs/Glossary/Rate_limit"},
		}

	case strings.Contains(findingMessage, "SECURITY_CORS_MISCONFIGURATION"):
		return EnrichedInfo{
			Description:    "The 'Access-Control-Allow-Origin' header is set to '*', allowing any domain to access the resource.",
			Recommendation: "Restrict 'Access-Control-Allow-Origin' to trusted domains only.",
			References:     []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS"},
		}

	case strings.Contains(findingMessage, "SECURITY_CORS_CREDENTIALS_WITH_WILDCARD_ORIGIN"):
		return EnrichedInfo{
			Description:    "'Access-Control-Allow-Credentials' is true while origin is '*', which is invalid per the CORS spec and creates security risks.",
			Recommendation: "Use specific origins instead of '*', or disable credentials if open access is required.",
			References:     []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Credentials"},
		}

	case strings.Contains(findingMessage, "SECURITY_CORS_ALLOW_ALL_HEADERS"):
		return EnrichedInfo{
			Description:    "The 'Access-Control-Allow-Headers' header includes '*', potentially exposing sensitive data to cross-origin requests.",
			Recommendation: "Explicitly list only the necessary headers in 'Access-Control-Allow-Headers'.",
			References:     []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Headers"},
		}

	case strings.Contains(findingMessage, "SECURITY_CORS_DANGEROUS_METHODS_ALLOWED"):
		return EnrichedInfo{
			Description:    "CORS configuration allows dangerous HTTP methods like 'DELETE' or wildcard '*', which may enable cross-origin abuse.",
			Recommendation: "Restrict 'Access-Control-Allow-Methods' to safe methods such as 'GET' and 'POST'.",
			References:     []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Access-Control-Allow-Methods"},
		}

	case strings.Contains(findingMessage, "SECURITY_HEADER_EXPOSURE_DETECTED"):
		return EnrichedInfo{
			Description:    "Response includes headers that may reveal server technologies, versions, or internal infrastructure — useful for attackers.",
			Recommendation: "Remove or mask sensitive headers such as 'Server', 'X-Powered-By', and 'X-Backend-Server' in production environments.",
			References:     []string{"https://owasp.org/www-project-secure-headers/", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Server"},
		}

	case strings.Contains(findingMessage, "SECURITY_PASSIVE_RATE_LIMIT_HEADERS_NOT_FOUND"):
		return EnrichedInfo{
			Description:    "No rate-limiting headers were found in the response, making it unclear whether abuse protection is in place.",
			Recommendation: "Add standard rate-limiting headers such as 'X-RateLimit-Limit' and 'Retry-After' to inform clients and improve security.",
			References:     []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Retry-After"},
		}

	case strings.Contains(findingMessage, "SECURITY_PASSIVE_RATE_LIMIT_DISABLED"):
		return EnrichedInfo{
			Description:    "Rate limiting appears to be disabled as 'X-RateLimit-Limit' is set to 0.",
			Recommendation: "Set a reasonable rate limit to prevent abuse and protect backend resources.",
			References:     []string{"https://cheatsheetseries.owasp.org/cheatsheets/Rate_Limiting_Cheat_Sheet.html"},
		}

	case strings.Contains(findingMessage, "SECURITY_PASSIVE_RATE_LIMIT_MISCONFIGURATION"):
		return EnrichedInfo{
			Description:    "'X-RateLimit-Remaining' is greater than 'X-RateLimit-Limit', indicating a possible configuration error.",
			Recommendation: "Ensure rate-limiting headers are calculated and returned consistently by the API gateway or backend.",
			References:     []string{"https://tools.ietf.org/id/draft-polli-ratelimit-headers-03.html"},
		}

	case strings.Contains(findingMessage, "SECURITY_HEADER_MISSING"):
		return EnrichedInfo{
			Description:    "A required security header is missing. These headers help protect against common vulnerabilities such as clickjacking, MIME-type sniffing, and XSS.",
			Recommendation: "Ensure headers like 'Strict-Transport-Security', 'X-Content-Type-Options', 'X-Frame-Options', 'X-XSS-Protection', and 'Referrer-Policy' are included in responses.",
			References:     []string{"https://owasp.org/www-project-secure-headers/", "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers"},
		}

	default:
		return EnrichedInfo{}
	}
}
