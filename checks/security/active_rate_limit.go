package security

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/mkafonso/hunter/types"
)

type ActiveRateLimitCheck struct {
	Requests int           // ex., 10
	Delay    time.Duration // optional: delay between requests
	Timeout  time.Duration // optional: max timeout per request
}

func (a ActiveRateLimitCheck) Name() string {
	return "Active Rate Limiting Check"
}

func (a ActiveRateLimitCheck) Run(resp *http.Response) []types.Finding {
	findings := []types.Finding{}
	url := resp.Request.URL.String()

	if a.Requests <= 0 {
		a.Requests = 10
	}
	if a.Timeout <= 0 {
		a.Timeout = 3 * time.Second
	}

	var wg sync.WaitGroup
	var mu sync.Mutex

	statusCounts := map[int]int{}
	rateLimited := false

	client := &http.Client{Timeout: a.Timeout}

	for i := 0; i < a.Requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequestWithContext(context.Background(), "GET", url, nil)
			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			mu.Lock()
			statusCounts[resp.StatusCode]++
			if resp.StatusCode == 429 {
				rateLimited = true
			}
			mu.Unlock()
		}()
		if a.Delay > 0 {
			time.Sleep(a.Delay)
		}
	}

	wg.Wait()

	if rateLimited {
	} else {
		findings = append(findings, types.Finding{
			Type:    "security",
			Message: "SECURITY_ACTIVE_RATE_LIMIT_NOT_DETECTED",
			Path:    resp.Request.URL.Path,
		})
	}

	return findings
}
