package types

import "net/http"

type Finding struct {
	Type    string `json:"type"`    // Ex: "security", "performance"
	Message string `json:"message"` // Ex: "Missing X-Content-Type-Options header"
	Path    string `json:"path"`    // Ex: "/login"
}

type Check interface {
	Name() string
	Run(resp *http.Response) []Finding
}
