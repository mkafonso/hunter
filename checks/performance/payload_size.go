package performance

import (
	"fmt"
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
			Message: "Payload size exceeds limit: " + byteCountDecimal(int64(len(bodyBytes))),
			Path:    resp.Request.URL.Path,
		})
	}

	return findings
}

func byteCountDecimal(b int64) string {
	const unit = 1000
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := unit, 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "kMGTPE"[exp])
}
