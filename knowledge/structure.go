package knowledge

import (
	"strings"

	"github.com/mkafonso/hunter/types"
)

func enrichStructure(finding string) *types.EnrichedInfo {
	switch {
	case strings.Contains(finding, "STRUCTURE_FIELD_CASING_INCONSISTENT"):
		return &types.EnrichedInfo{
			Description:    "The JSON response uses multiple field naming conventions (e.g., camelCase, snake_case, PascalCase), which can confuse clients and reduce maintainability.",
			Recommendation: "Adopt a consistent naming convention for all fields in API responses (preferably camelCase or snake_case).",
			References:     []string{"https://dev.to/imichaelowolabi/what-case-should-your-api-request-response-be-ggo"},
		}

	case strings.Contains(finding, "STRUCTURE_METHOD_USAGE_GET_UNSAFE_VERB"):
		return &types.EnrichedInfo{
			Description:    "GET requests should be safe and not modify server state. Using action verbs like delete or update in GET URLs may cause side effects.",
			Recommendation: "Avoid using GET for operations that modify data. Use POST, PUT, PATCH, or DELETE accordingly.",
			References:     []string{"https://restfulapi.net/http-methods/#safe-and-idempotent-methods"},
		}

	case strings.Contains(finding, "STRUCTURE_METHOD_USAGE_POST_FOR_SEARCH"):
		return &types.EnrichedInfo{
			Description:    "POST method is used for searching, which semantically should be a GET request.",
			Recommendation: "Use GET for search operations to improve caching and adherence to REST conventions.",
			References:     []string{"https://restfulapi.net/resource-naming/"},
		}

	case strings.Contains(finding, "STRUCTURE_METHOD_USAGE_PUT_WITHOUT_ID"):
		return &types.EnrichedInfo{
			Description:    "PUT requests without resource ID usually indicate misuse as PUT is intended to update a specific resource.",
			Recommendation: "Use POST for creation or PATCH for partial updates without explicit ID in URL.",
			References:     []string{"https://restfulapi.net/resource-naming/"},
		}

	case strings.Contains(finding, "STRUCTURE_METHOD_USAGE_DELETE_LARGE_BODY"):
		return &types.EnrichedInfo{
			Description:    "DELETE requests returning large response bodies are unusual and may indicate unnecessary data transfer.",
			Recommendation: "Keep DELETE responses minimal, preferably no body or only essential confirmation.",
			References:     []string{"https://restfulapi.net/http-methods/#delete"},
		}

	case strings.Contains(finding, "STRUCTURE_METHOD_USAGE_PATCH_WITHOUT_ID"):
		return &types.EnrichedInfo{
			Description:    "PATCH requests generally require a resource ID to apply partial updates.",
			Recommendation: "Ensure PATCH requests include the resource identifier in the URL.",
			References:     []string{"https://restfulapi.net/http-methods/#patch"},
		}

	case strings.Contains(finding, "STRUCTURE_METHOD_USAGE_GET_UNSAFE_SUFFIX"):
		return &types.EnrichedInfo{
			Description:    "GET requests with URL suffixes like /delete or /update are unsafe and may modify state unexpectedly.",
			Recommendation: "Avoid encoding state-changing actions in GET request paths.",
			References:     []string{"https://restfulapi.net/http-methods/#safe-and-idempotent-methods"},
		}

	case strings.Contains(finding, "STRUCTURE_VERSIONING_MISSING_IN_PATH"):
		return &types.EnrichedInfo{
			Description:    "API routes without versioning in the path make it difficult to evolve the API without breaking existing clients.",
			Recommendation: "Include the API version in the URL path (e.g., /v1/resource) to support backward compatibility.",
			References:     []string{"https://restfulapi.net/versioning/"},
		}

	case strings.Contains(finding, "STRUCTURE_VERSIONING_QUERY_PARAM_DISCOURAGED"):
		return &types.EnrichedInfo{
			Description:    "Using query parameters for versioning is less preferred and can lead to caching issues and inconsistent API behavior.",
			Recommendation: "Prefer versioning via the URL path instead of query parameters.",
			References:     []string{"https://restfulapi.net/versioning/"},
		}

	case strings.Contains(finding, "STRUCTURE_STATUS_CODE_2XX_ERROR_BODY"):
		return &types.EnrichedInfo{
			Description:    "Response returned with 2xx status code but contains error-like fields in the JSON body.",
			Recommendation: "Ensure error responses use appropriate non-2xx status codes and proper error structures in the body.",
			References:     []string{"https://restfulapi.net/http-status-codes/"},
		}

	case strings.Contains(finding, "STRUCTURE_STATUS_CODE_POST_204_WITH_BODY"):
		return &types.EnrichedInfo{
			Description:    "POST requests returning 204 No Content should not include a response body.",
			Recommendation: "Avoid sending a response body with a 204 status code, following HTTP specifications.",
			References:     []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/204"},
		}

	case strings.Contains(finding, "STRUCTURE_STATUS_CODE_GET_UNEXPECTED_201"):
		return &types.EnrichedInfo{
			Description:    "GET requests should not return 201 Created status code.",
			Recommendation: "Use 201 status code only for successful resource creation requests (typically POST).",
			References:     []string{"https://restfulapi.net/http-methods/#post"},
		}

	case strings.Contains(finding, "STRUCTURE_STATUS_CODE_GET_200_EMPTY_BODY"):
		return &types.EnrichedInfo{
			Description:    "GET requests returned 200 OK but the response body is empty.",
			Recommendation: "Ensure GET requests with 200 status return a valid response body or use 204 No Content if empty.",
			References:     []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/204"},
		}

	case strings.Contains(finding, "STRUCTURE_STATUS_CODE_204_WITH_BODY"):
		return &types.EnrichedInfo{
			Description:    "204 No Content responses should not include a response body.",
			Recommendation: "Remove any body content from 204 responses as per HTTP spec.",
			References:     []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/204"},
		}

	case strings.Contains(finding, "STRUCTURE_STATUS_CODE_GET_UNEXPECTED_204"):
		return &types.EnrichedInfo{
			Description:    "GET requests returned 204 No Content, which is unexpected.",
			Recommendation: "Avoid returning 204 for GET requests; use 200 with empty body if appropriate.",
			References:     []string{"https://restfulapi.net/http-status-codes/"},
		}

	case strings.Contains(finding, "STRUCTURE_STATUS_CODE_HEAD_UNEXPECTED"):
		return &types.EnrichedInfo{
			Description:    "HEAD requests should only return 200 OK or 204 No Content status codes.",
			Recommendation: "Ensure HEAD responses use only 200 or 204 status codes.",
			References:     []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/HEAD"},
		}

	default:
		return nil
	}
}
