package performance

import (
	"io"
	"net/http"

	"github.com/mkafonso/hunter/types"
)

type PayloadSizeCheck struct {
	MaxBytes int64 // ex: 500 * 1024 (500 KB)
}

func (p PayloadSizeCheck) Name() string {
	return "Payload Size Limit"
}

func (p PayloadSizeCheck) Run(resp *http.Response) []types.Finding {
	findings := []types.Finding{}

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return findings
	}
	resp.Body.Close()

	resp.Body = io.NopCloser(io.LimitReader(io.MultiReader(
		io.NopCloser(io.LimitReader(io.MultiReader(), 0)),
	), int64(len(bodyBytes))))

	if int64(len(bodyBytes)) > p.MaxBytes {
		findings = append(findings, types.Finding{
			Type:    "performance",
			Message: "PERFORMANCE_PAYLOAD_SIZE_EXCEEDS_LIMIT",
			Path:    resp.Request.URL.Path,
		})
	}

	return findings
}
