package structure

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/mkafonso/hunter/types"
)

type StatusCodeCheck struct{}

func (s StatusCodeCheck) Name() string {
	return "Status Code Validation"
}

func (s StatusCodeCheck) Run(resp *http.Response) []types.Finding {
	findings := []types.Finding{}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return findings
		}
		resp.Body.Close()
		resp.Body = io.NopCloser(strings.NewReader(string(body)))

		// 1. 200 OK with error-like content
		if looksLikeError(body) {
			findings = append(findings, types.Finding{
				Type:    "structure",
				Message: "2xx status code with error-like response body",
				Path:    resp.Request.URL.Path,
			})
		}

		// 2. POST returning 204 with body
		if resp.Request.Method == "POST" && resp.StatusCode == 204 && len(body) > 0 {
			findings = append(findings, types.Finding{
				Type:    "structure",
				Message: "POST returned 204 No Content but response body is not empty",
				Path:    resp.Request.URL.Path,
			})
		}

		// 3. GET returning 201
		if resp.Request.Method == "GET" && resp.StatusCode == 201 {
			findings = append(findings, types.Finding{
				Type:    "structure",
				Message: "GET method returned 201 Created — unexpected",
				Path:    resp.Request.URL.Path,
			})
		}

		// 4. GET returning 2xx with empty body
		if resp.Request.Method == "GET" && resp.StatusCode == 200 && len(body) == 0 {
			findings = append(findings, types.Finding{
				Type:    "structure",
				Message: "GET returned 200 OK with empty body",
				Path:    resp.Request.URL.Path,
			})
		}

		// 5. 204 status should not return body, regardless of method
		if resp.StatusCode == 204 {
			body, _ := io.ReadAll(resp.Body)
			resp.Body = io.NopCloser(strings.NewReader(string(body))) // restore

			if len(body) > 0 {
				findings = append(findings, types.Finding{
					Type:    "structure",
					Message: "204 No Content response should not have a body",
					Path:    resp.Request.URL.Path,
				})
			}
		}

		// 6. GET should not return 204 No Content
		if resp.Request.Method == "GET" && resp.StatusCode == 204 {
			findings = append(findings, types.Finding{
				Type:    "structure",
				Message: "GET returned 204 No Content, expected 200 with content",
				Path:    resp.Request.URL.Path,
			})
		}

		// 7. HEAD should return 200 or 204
		if resp.Request.Method == "HEAD" && !(resp.StatusCode == 200 || resp.StatusCode == 204) {
			findings = append(findings, types.Finding{
				Type:    "structure",
				Message: "HEAD request returned unexpected status code",
				Path:    resp.Request.URL.Path,
			})
		}
	}

	return findings
}

func looksLikeError(body []byte) bool {
	var parsed map[string]any
	if err := json.Unmarshal(body, &parsed); err != nil {
		return false
	}

	for _, key := range []string{"error", "errors", "message", "exception", "stack"} {
		if _, ok := parsed[key]; ok {
			return true
		}
	}
	return false
}
