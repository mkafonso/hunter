package utils

import (
	"net/http"
	"time"
)

func FetchWithMetrics(url string) (*http.Response, time.Duration, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	start := time.Now()

	resp, err := client.Get(url)
	duration := time.Since(start)

	return resp, duration, err
}
