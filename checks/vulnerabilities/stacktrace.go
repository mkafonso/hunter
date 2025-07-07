package vulnerabilities

import (
	"bytes"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/mkafonso/hunter/types"
)

type StacktraceCheck struct{}

func (s StacktraceCheck) Name() string {
	return "Stacktrace Exposure"
}

func (s StacktraceCheck) Run(resp *http.Response) []types.Finding {
	findings := []types.Finding{}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return findings
	}
	resp.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	bodyStr := string(bodyBytes)

	counter := 1

	if looksLikeLanguageStacktrace(bodyStr) {
		findings = append(findings, types.Finding{
			Type:    "vulnerability",
			Message: format(counter, "Detected language-specific stacktrace"),
			Path:    resp.Request.URL.Path,
		})
		counter++
	}

	stackPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)\s+at\s+[\w\.$]+\.[\w$]+\([^\)]+\)`),       // Java/.NET
		regexp.MustCompile(`(?i)Traceback \(most recent call last\):`),     // Python
		regexp.MustCompile(`(?i)\s+at\s+(\/.*\.js:\d+:\d+)`),               // Node.js
		regexp.MustCompile(`(?i)from\s+\/.*\.rb:\d+:in\s+`),                // Ruby
		regexp.MustCompile(`(?i)#\d+\s+\/.*\.php\(\d+\):`),                 // PHP
		regexp.MustCompile(`(?i)(\/app\/|\/var\/www|C:\\|D:\\|\.cs|\.py)`), // Generic path leakage
	}

	for _, pattern := range stackPatterns {
		if pattern.Match(bodyBytes) {
			findings = append(findings, types.Finding{
				Type:    "vulnerability",
				Message: format(counter, "Detected stacktrace-like pattern in HTTP response body"),
				Path:    resp.Request.URL.Path,
			})
			counter++
			break // one match is enough
		}
	}

	return findings
}

func looksLikeLanguageStacktrace(body string) bool {
	markers := []string{
		"java.lang.", "javax.", "org.springframework", // Java
		"System.NullReferenceException",             // .NET
		"Traceback (most recent call last):",        // Python
		"at Function.Module._load", "node:internal", // Node.js
		"from /", "in `<main>`", // Ruby
		"#0 ", // PHP
	}
	for _, m := range markers {
		if strings.Contains(body, m) {
			return true
		}
	}
	return false
}

func format(n int, msg string) string {
	return "[" + strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(strings.ReplaceAll(msg, "\n", ""), "- "), "•")) + "] #" + strconv.Itoa(n) + " " + msg
}
