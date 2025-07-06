package performance

import (
	"net/http"
	"time"

	"github.com/mkafonso/hunter/types"
)

type LatencyCheck struct {
	Threshold time.Duration
}

func (l LatencyCheck) Name() string {
	return "Latency Threshold"
}

func (l LatencyCheck) Run(resp *http.Response) []types.Finding {
	findings := []types.Finding{}

	duration, ok := resp.Request.Context().Value("latency").(time.Duration)
	if !ok {
		return findings
	}

	if duration > l.Threshold {
		findings = append(findings, types.Finding{
			Type:    "performance",
			Message: "Response time exceeded threshold: " + duration.String(),
			Path:    resp.Request.URL.Path,
		})
	}

	return findings
}
