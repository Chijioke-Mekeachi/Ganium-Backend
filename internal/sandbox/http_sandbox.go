package sandbox

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"ganium/internal/security"
)

var (
	titleRegex       = regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)
	metaDescRegex    = regexp.MustCompile(`(?i)<meta\s+name=["']description["']\s+content=["'](.*?)["']`)
	scriptSrcRegex   = regexp.MustCompile(`(?i)<script[^>]+src=["'](.*?)["']`)
	formActionRegex  = regexp.MustCompile(`(?i)<form[^>]+action=["'](.*?)["']`)
	hrefLinkRegex    = regexp.MustCompile(`(?i)<a[^>]+href=["'](.*?)["']`)
)

// HTTPSandbox implements safe, isolated HTTP fetching without executing client-side scripts.
type HTTPSandbox struct {
	client       *http.Client
	maxSizeBytes int64
	timeout      time.Duration
}

// NewHTTPSandbox initializes a sandboxed HTTP inspector.
func NewHTTPSandbox(timeout time.Duration, maxSizeBytes int64, maxRedirects int) *HTTPSandbox {
	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	if maxSizeBytes <= 0 {
		maxSizeBytes = 512 * 1024 // 512KB
	}
	return &HTTPSandbox{
		client:       security.SafeHTTPClient(timeout, maxRedirects),
		maxSizeBytes: maxSizeBytes,
		timeout:      timeout,
	}
}

// InspectURL safely fetches the target webpage in an isolated context.
func (s *HTTPSandbox) InspectURL(ctx context.Context, targetURL string) (*SandboxResult, error) {
	startTime := time.Now()

	reqCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create sandboxed request: %w", err)
	}

	// Use generic browser User-Agent without revealing scanner identity to prevent cloaking
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.5")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sandboxed request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read with hard upper bound to prevent memory exhaustion / ZIP-bomb-like attacks
	limitedReader := io.LimitReader(resp.Body, s.maxSizeBytes)
	bodyBytes, err := io.ReadAll(limitedReader)
	if err != nil {
		return nil, fmt.Errorf("failed reading sandboxed body: %w", err)
	}

	headers := make(map[string]string)
	for k, v := range resp.Header {
		if len(v) > 0 {
			headers[strings.ToLower(k)] = v[0]
		}
	}

	bodyStr := string(bodyBytes)

	// Extract Title
	title := ""
	if m := titleRegex.FindStringSubmatch(bodyStr); len(m) > 1 {
		title = strings.TrimSpace(m[1])
	}

	// Extract Meta Description
	metaDesc := ""
	if m := metaDescRegex.FindStringSubmatch(bodyStr); len(m) > 1 {
		metaDesc = strings.TrimSpace(m[1])
	}

	// Extract Scripts
	var scripts []string
	for _, match := range scriptSrcRegex.FindAllStringSubmatch(bodyStr, 50) {
		if len(match) > 1 {
			scripts = append(scripts, strings.TrimSpace(match[1]))
		}
	}

	// Extract Forms
	var forms []string
	for _, match := range formActionRegex.FindAllStringSubmatch(bodyStr, 20) {
		if len(match) > 1 {
			forms = append(forms, strings.TrimSpace(match[1]))
		}
	}

	// Extract Links
	var links []string
	for _, match := range hrefLinkRegex.FindAllStringSubmatch(bodyStr, 50) {
		if len(match) > 1 {
			link := strings.TrimSpace(match[1])
			if link != "" && !strings.HasPrefix(link, "#") && !strings.HasPrefix(link, "javascript:") {
				links = append(links, link)
			}
		}
	}

	return &SandboxResult{
		URL:             targetURL,
		StatusCode:      resp.StatusCode,
		Headers:         headers,
		HTMLBody:        bodyStr,
		BodySizeBytes:   len(bodyBytes),
		Title:           title,
		MetaDescription: metaDesc,
		ScriptsFound:    scripts,
		FormsFound:      forms,
		LinksFound:      links,
		ExecutionTime:   time.Since(startTime),
		SandboxEngine:   "safe_http_isolated",
	}, nil
}
