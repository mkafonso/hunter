package types

import "net/http"

type Finding struct {
	Type           string   `json:"type"`
	Message        string   `json:"message"`
	Path           string   `json:"path"`
	Description    string   `json:"description,omitempty"`
	Recommendation string   `json:"recommendation,omitempty"`
	References     []string `json:"references,omitempty"`
}

type Check interface {
	Name() string
	Run(resp *http.Response) []Finding
}
