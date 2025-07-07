package performance

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/mkafonso/hunter/types"
)

type CompressionCheck struct{}

func (c CompressionCheck) Name() string {
	return "Response Compression"
}

func (c CompressionCheck) Run(resp *http.Response) []types.Finding {
	findings := []types.Finding{}

	encoding := strings.ToLower(resp.Header.Get("Content-Encoding"))

	if encoding == "gzip" || encoding == "br" || encoding == "deflate" {
		return findings
	}

	// Check size threshold if uncompressed
	cl := resp.Header.Get("Content-Length")
	if cl != "" {
		if size, err := strconv.Atoi(cl); err == nil && size > 1000 {
			findings = append(findings, types.Finding{
				Type:    "performance",
				Message: "PERFORMANCE_COMPRESSION_LARGE_UNCOMPRESSED_RESPONSE",
				Path:    resp.Request.URL.Path,
			})
			return findings
		}
	}

	if encoding == "" {
		findings = append(findings, types.Finding{
			Type:    "performance",
			Message: "PERFORMANCE_COMPRESSION_MISSING_CONTENT_ENCODING_HEADER",
			Path:    resp.Request.URL.Path,
		})
	}

	return findings
}
