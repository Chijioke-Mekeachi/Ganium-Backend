package security

import (
	"net/http"
	"net/url"
	"strings"
)

// OriginValidator checks if HTTP / WebSocket origin headers are allowed.
type OriginValidator struct {
	allowAll       bool
	allowedOrigins map[string]struct{}
}

func NewOriginValidator(origins []string) *OriginValidator {
	v := &OriginValidator{
		allowedOrigins: make(map[string]struct{}),
	}

	for _, o := range origins {
		trimmed := strings.TrimSpace(o)
		if trimmed == "*" {
			v.allowAll = true
		} else if trimmed != "" {
			v.allowedOrigins[strings.ToLower(trimmed)] = struct{}{}
		}
	}

	return v
}

// IsAllowedOrigin validates the Origin header against the whitelist.
func (v *OriginValidator) IsAllowedOrigin(r *http.Request) bool {
	if v.allowAll {
		return true
	}

	origin := r.Header.Get("Origin")
	if origin == "" {
		// Non-browser or same-origin clients might not send Origin
		return true
	}

	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}

	normalized := strings.ToLower(parsed.Scheme + "://" + parsed.Host)
	_, ok := v.allowedOrigins[normalized]
	return ok
}
