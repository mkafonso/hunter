package scanner

import (
	"context"
	"fmt"
	"time"

	"github.com/mkafonso/hunter/types"
)

type ScanOptions struct {
	URL     string
	Checks  []types.Check
	Timeout time.Duration
}

func RunScan(opts ScanOptions) ([]types.Finding, error) {
	resp, latency, err := FetchWithMetrics(opts.URL)
	if err != nil {
		return nil, fmt.Errorf("fetch failed for %s: %w", opts.URL, err)
	}
	defer resp.Body.Close()

	ctx := context.WithValue(resp.Request.Context(), "latency", latency)
	resp.Request = resp.Request.WithContext(ctx)

	var all []types.Finding
	for _, check := range opts.Checks {
		all = append(all, check.Run(resp)...)
	}
	return all, nil
}
