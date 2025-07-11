package structure

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/mkafonso/hunter/types"
)

type MethodUsageCheck struct{}

func (m MethodUsageCheck) Name() string {
	return "Method Usage Validation"
}

func (m MethodUsageCheck) Run(resp *http.Response) []types.Finding {
	findings := []types.Finding{}

	method := resp.Request.Method
	path := strings.ToLower(resp.Request.URL.Path)

	// 1. GET used with action verbs (may modify state)
	if method == http.MethodGet && containsActionVerb(path) {
		findings = append(findings, types.Finding{
			Type:    "structure",
			Message: "STRUCTURE_METHOD_USAGE_GET_UNSAFE_VERB",
			Path:    path,
		})
	}

	// 2. POST used for searches
	if method == http.MethodPost && containsSearchIntent(path) {
		findings = append(findings, types.Finding{
			Type:    "structure",
			Message: "STRUCTURE_METHOD_USAGE_POST_FOR_SEARCH",
			Path:    path,
		})
	}

	// 3. PUT without ID in path
	if method == http.MethodPut && !hasResourceID(path) {
		findings = append(findings, types.Finding{
			Type:    "structure",
			Message: "STRUCTURE_METHOD_USAGE_PUT_WITHOUT_ID",
			Path:    path,
		})
	}

	// 4. DELETE with unexpected body
	if method == http.MethodDelete && resp.ContentLength > 100 {
		findings = append(findings, types.Finding{
			Type:    "structure",
			Message: "STRUCTURE_METHOD_USAGE_DELETE_LARGE_BODY",
			Path:    path,
		})
	}

	// 5. PATCH without ID (PATCH is usually partial and requires ID)
	if method == http.MethodPatch && !hasResourceID(path) {
		findings = append(findings, types.Finding{
			Type:    "structure",
			Message: "STRUCTURE_METHOD_USAGE_PATCH_WITHOUT_ID",
			Path:    path,
		})
	}

	// 6. GET with ID followed by /delete or /update
	if method == http.MethodGet && isUnsafeSuffix(path) {
		findings = append(findings, types.Finding{
			Type:    "structure",
			Message: "STRUCTURE_METHOD_USAGE_GET_UNSAFE_SUFFIX",
			Path:    path,
		})
	}

	return findings
}

// containsActionVerb detects unsafe verbs in GET path
func containsActionVerb(path string) bool {
	verbs := []string{"delete", "update", "create", "reset", "generate", "disable", "enable"}
	for _, verb := range verbs {
		if strings.Contains(path, verb) {
			return true
		}
	}
	return false
}

// containsSearchIntent detects search-like routes in POSTs
func containsSearchIntent(path string) bool {
	keywords := []string{"search", "find", "query", "lookup"}
	for _, word := range keywords {
		if strings.Contains(path, word) {
			return true
		}
	}
	return false
}

// hasResourceID checks for numeric ID or UUID near the end of the path
func hasResourceID(path string) bool {
	idPattern := regexp.MustCompile(`/.+/(?:[0-9]+|[a-f0-9\-]{36})/?(?:$|\?)`)
	return idPattern.MatchString(path)
}

// isUnsafeSuffix checks if path ends in an unsafe verb (e.g. /123/delete)
func isUnsafeSuffix(path string) bool {
	pattern := regexp.MustCompile(`/(?:[0-9]+|[a-f0-9\-]{36})/(delete|update|disable|enable)/?$`)
	return pattern.MatchString(path)
}
