package knowledge

import (
	"strings"

	"github.com/mkafonso/hunter/types"
)

func enrichPerformance(finding string) *types.EnrichedInfo {
	switch {
	case strings.Contains(finding, "PERFORMANCE_COMPRESSION_LARGE_UNCOMPRESSED_RESPONSE"):
		return &types.EnrichedInfo{
			Description:    "Large responses without compression increase bandwidth usage and page load time.",
			Recommendation: "Enable gzip, br, or deflate compression for responses larger than 1KB.",
			References:     []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Encoding"},
		}

	case strings.Contains(finding, "PERFORMANCE_COMPRESSION_MISSING_CONTENT_ENCODING_HEADER"):
		return &types.EnrichedInfo{
			Description:    "The 'Content-Encoding' header is missing — response is likely uncompressed.",
			Recommendation: "Add the 'Content-Encoding' header and enable compression on the server.",
			References:     []string{"https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Encoding"},
		}

	case strings.Contains(finding, "PERFORMANCE_LATENCY_EXCEEDED_THRESHOLD"):
		return &types.EnrichedInfo{
			Description:    "The response time exceeded the acceptable latency threshold, which can degrade user experience.",
			Recommendation: "Optimize backend performance, cache frequent responses, or analyze slow dependencies.",
			References:     []string{"https://developer.mozilla.org/en-US/docs/Web/Performance", "https://web.dev/time-to-first-byte/"},
		}

	case strings.Contains(finding, "PERFORMANCE_PAYLOAD_SIZE_EXCEEDS_LIMIT"):
		return &types.EnrichedInfo{
			Description:    "The response payload size is larger than expected, which can slow down clients or mobile devices.",
			Recommendation: "Reduce payload size by removing unnecessary fields, paginating large datasets, or optimizing binary data.",
			References:     []string{"https://web.dev/optimize-lcp/", "https://developers.google.com/web/fundamentals/performance/optimizing-content-efficiency/"},
		}

	default:
		return nil
	}
}
