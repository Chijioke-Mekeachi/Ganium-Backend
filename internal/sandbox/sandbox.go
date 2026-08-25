package sandbox

import (
	"context"
	"time"
)

// SandboxResult holds the safe inspection output from an isolated run.
type SandboxResult struct {
	URL             string            `json:"url"`
	StatusCode      int               `json:"status_code"`
	Headers         map[string]string `json:"headers"`
	HTMLBody        string            `json:"html_body"`
	BodySizeBytes   int               `json:"body_size_bytes"`
	Title           string            `json:"title"`
	MetaDescription string            `json:"meta_description"`
	ScriptsFound    []string          `json:"scripts_found"`
	FormsFound      []string          `json:"forms_found"`
	LinksFound      []string          `json:"links_found"`
	ExecutionTime   time.Duration     `json:"execution_time"`
	SandboxEngine   string            `json:"sandbox_engine"` // "safe_http_isolated", "container_browser"
	SecurityFlags   []string          `json:"security_flags,omitempty"`
}

// SandboxRunner defines the contract for isolated target execution and inspection.
type SandboxRunner interface {
	InspectURL(ctx context.Context, targetURL string) (*SandboxResult, error)
}
