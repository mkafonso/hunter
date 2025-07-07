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

	/**
	 * STRUCTURE
	 */
	case strings.Contains(findingMessage, "STRUCTURE_FIELD_CASING_INCONSISTENT"):
		return EnrichedInfo{
			Description:    "The JSON response uses multiple field naming conventions (e.g., camelCase, snake_case, PascalCase), which can confuse clients and reduce maintainability.",
			Recommendation: "Adopt a consistent naming convention for all fields in API responses (preferably camelCase or snake_case).",
			References:     []string{"https://dev.to/imichaelowolabi/what-case-should-your-api-request-response-be-ggo"},
		}

	case strings.Contains(findingMessage, "STRUCTURE_METHOD_USAGE_GET_UNSAFE_VERB"):
		return EnrichedInfo{
			Description:    "GET requests should be safe and not modify server state. Using action verbs like delete or update in GET URLs may cause side effects.",
			Recommendation: "Avoid using GET for operations that modify data. Use POST, PUT, PATCH, or DELETE accordingly.",
			References:     []string{"https://restfulapi.net/http-methods/#safe-and-idempotent-methods"},
		}

	case strings.Contains(findingMessage, "STRUCTURE_METHOD_USAGE_POST_FOR_SEARCH"):
		return EnrichedInfo{
			Description:    "POST method is used for searching, which semantically should be a GET request.",
			Recommendation: "Use GET for search operations to improve caching and adherence to REST conventions.",
			References:     []string{"https://restfulapi.net/resource-naming/"},
		}

	case strings.Contains(findingMessage, "STRUCTURE_METHOD_USAGE_PUT_WITHOUT_ID"):
		return EnrichedInfo{
			Description:    "PUT requests without resource ID usually indicate misuse as PUT is intended to update a specific resource.",
			Recommendation: "Use POST for creation or PATCH for partial updates without explicit ID in URL.",
			References:     []string{"https://restfulapi.net/resource-naming/"},
		}

	case strings.Contains(findingMessage, "STRUCTURE_METHOD_USAGE_DELETE_LARGE_BODY"):
		return EnrichedInfo{
			Description:    "DELETE requests returning large response bodies are unusual and may indicate unnecessary data transfer.",
			Recommendation: "Keep DELETE responses minimal, preferably no body or only essential confirmation.",
			References:     []string{"https://restfulapi.net/http-methods/#delete"},
		}

	case strings.Contains(findingMessage, "STRUCTURE_METHOD_USAGE_PATCH_WITHOUT_ID"):
		return EnrichedInfo{
			Description:    "PATCH requests generally require a resource ID to apply partial updates.",
			Recommendation: "Ensure PATCH requests include the resource identifier in the URL.",
			References:     []string{"https://restfulapi.net/http-methods/#patch"},
		}

	case strings.Contains(findingMessage, "STRUCTURE_METHOD_USAGE_GET_UNSAFE_SUFFIX"):
		return EnrichedInfo{
			Description:    "GET requests with URL suffixes like /delete or /update are unsafe and may modify state unexpectedly.",
			Recommendation: "Avoid encoding state-changing actions in GET request paths.",
			References:     []string{"https://restfulapi.net/http-methods/#safe-and-idempotent-methods"},
		}

	case strings.Contains(findingMessage, "STRUCTURE_VERSIONING_MISSING_IN_PATH"):
		return EnrichedInfo{
			Description:    "API routes without versioning in the path make it difficult to evolve the API without breaking existing clients.",
			Recommendation: "Include the API version in the URL path (e.g., /v1/resource) to support backward compatibility.",
			References:     []string{"https://restfulapi.net/versioning/"},
		}

	case strings.Contains(findingMessage, "STRUCTURE_VERSIONING_QUERY_PARAM_DISCOURAGED"):
		return EnrichedInfo{
			Description:    "Using query parameters for versioning is less preferred and can lead to caching issues and inconsistent API behavior.",
			Recommendation: "Prefer versioning via the URL path instead of query parameters.",
			References:     []string{"https://restfulapi.net/versioning/"},
		}

	case strings.Contains(findingMessage, "STRUCTURE_STATUS_CODE_2XX_ERROR_BODY"):
		return EnrichedInfo{
			Description:    "Response returned with 2xx status code but contains error-like fields in the JSON body.",
			Recommendation: "Ensure error responses use appropriate non-2xx status codes and proper error structures in the body.",
			References:     []string{"https://restfulapi.net/http-status-codes/"},
		}

	case strings.Contains(findingMessage, "STRUCTURE_STATUS_CODE_POST_204_WITH_BODY"):
		return EnrichedInfo{
			Description:    "POST requests returning 204 No Content should not include a response body.",
			Recommendation: "Avoid sending a response body with a 204 status code, following HTTP specifications.",
			References:     []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/204"},
		}

	case strings.Contains(findingMessage, "STRUCTURE_STATUS_CODE_GET_UNEXPECTED_201"):
		return EnrichedInfo{
			Description:    "GET requests should not return 201 Created status code.",
			Recommendation: "Use 201 status code only for successful resource creation requests (typically POST).",
			References:     []string{"https://restfulapi.net/http-methods/#post"},
		}

	case strings.Contains(findingMessage, "STRUCTURE_STATUS_CODE_GET_200_EMPTY_BODY"):
		return EnrichedInfo{
			Description:    "GET requests returned 200 OK but the response body is empty.",
			Recommendation: "Ensure GET requests with 200 status return a valid response body or use 204 No Content if empty.",
			References:     []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/204"},
		}

	case strings.Contains(findingMessage, "STRUCTURE_STATUS_CODE_204_WITH_BODY"):
		return EnrichedInfo{
			Description:    "204 No Content responses should not include a response body.",
			Recommendation: "Remove any body content from 204 responses as per HTTP spec.",
			References:     []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/204"},
		}

	case strings.Contains(findingMessage, "STRUCTURE_STATUS_CODE_GET_UNEXPECTED_204"):
		return EnrichedInfo{
			Description:    "GET requests returned 204 No Content, which is unexpected.",
			Recommendation: "Avoid returning 204 for GET requests; use 200 with empty body if appropriate.",
			References:     []string{"https://restfulapi.net/http-status-codes/"},
		}

	case strings.Contains(findingMessage, "STRUCTURE_STATUS_CODE_HEAD_UNEXPECTED"):
		return EnrichedInfo{
			Description:    "HEAD requests should only return 200 OK or 204 No Content status codes.",
			Recommendation: "Ensure HEAD responses use only 200 or 204 status codes.",
			References:     []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/HEAD"},
		}

	default:
		return EnrichedInfo{}
	}
}
