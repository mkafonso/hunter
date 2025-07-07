package discovery

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

type APIDiscovery struct {
	BaseURL  string
	Paths    []string
	FullURLs []string
}

func DiscoverFromOpenAPI(docURL string) (*APIDiscovery, error) {
	resp, err := http.Get(docURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OpenAPI file: %w", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	var baseURL string
	var paths map[string]interface{}

	// Support OpenAPI v3 (servers[])
	if servers, ok := raw["servers"].([]interface{}); ok && len(servers) > 0 {
		if serverInfo, ok := servers[0].(map[string]interface{}); ok {
			if u, ok := serverInfo["url"].(string); ok {
				baseURL = u
			}
		}
	}

	// Support Swagger v2 (host + basePath)
	if swaggerVer, ok := raw["swagger"].(string); ok && swaggerVer == "2.0" {
		host, hasHost := raw["host"].(string)
		scheme := "https"
		if schemes, ok := raw["schemes"].([]interface{}); ok && len(schemes) > 0 {
			if s, ok := schemes[0].(string); ok {
				scheme = s
			}
		}
		if hasHost {
			baseURL = fmt.Sprintf("%s://%s", scheme, host)
			if bp, ok := raw["basePath"].(string); ok {
				baseURL += strings.TrimRight(bp, "/")
			}
		}
	}

	// Fallback if no baseURL
	if baseURL == "" {
		baseURL = extractBaseURL(docURL)
	}

	// Extract paths
	if p, ok := raw["paths"].(map[string]interface{}); ok {
		paths = p
	} else {
		return nil, fmt.Errorf("no paths found in OpenAPI document")
	}

	discoveredPaths := make([]string, 0)
	fullURLs := make([]string, 0)

	for path := range paths {
		cleanPath := path
		cleanPath = strings.ReplaceAll(path, "{", ":")
		discoveredPaths = append(discoveredPaths, cleanPath)
		full := strings.TrimRight(baseURL, "/") + cleanPath
		fullURLs = append(fullURLs, full)
	}

	return &APIDiscovery{
		BaseURL:  baseURL,
		Paths:    discoveredPaths,
		FullURLs: fullURLs,
	}, nil
}

func extractBaseURL(inputURL string) string {
	if !strings.HasPrefix(inputURL, "http") {
		inputURL = "https://" + inputURL
	}
	parsed, err := url.Parse(inputURL)
	if err != nil {
		return inputURL
	}
	return fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
}
