package sandbox

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"ganium/internal/security"
	"ganium/pkg/types"
)

var (
	titleRegex      = regexp.MustCompile(`(?i)<title[^>]*>(.*?)</title>`)
	metaDescRegex   = regexp.MustCompile(`(?i)<meta\s+name=["']description["']\s+content=["'](.*?)["']`)
	scriptSrcRegex  = regexp.MustCompile(`(?i)<script[^>]+src=["'](.*?)["']`)
	formActionRegex = regexp.MustCompile(`(?i)<form[^>]+action=["'](.*?)["']`)
	hrefLinkRegex   = regexp.MustCompile(`(?i)<a[^>]+href=["'](.*?)["']`)
)

// HTTPSandbox implements safe, isolated HTTP fetching without executing client-side scripts.
type HTTPSandbox struct {
	client       *http.Client
	maxSizeBytes int64
	timeout      time.Duration
	maxRedirects int
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
		maxRedirects: maxRedirects,
	}
}

// InspectURL safely fetches the target webpage in an isolated context.
func (s *HTTPSandbox) InspectURL(ctx context.Context, targetURL string) (*SandboxResult, error) {
	startTime := time.Now()
	// We'll perform controlled redirect-following manually so we can capture the chain.
	var (
		currentURL = targetURL
		chain      []types.RedirectHop
		finalResp  *http.Response
		finalBody  []byte
		finalErr   error
	)

	client := s.client
	// Ensure we don't let the client's default redirect policy follow automatically
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	for i := 0; i <= s.maxRedirects; i++ {
		reqCtx, cancel := context.WithTimeout(ctx, s.timeout)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, currentURL, nil)
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to create sandboxed request: %w", err)
		}
		// Standard browser-like headers
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")
		req.Header.Set("Sec-Fetch-Dest", "document")
		req.Header.Set("Sec-Fetch-Mode", "navigate")
		req.Header.Set("Sec-Fetch-Site", "none")

		resp, err := client.Do(req)
		cancel()
		if err != nil {
			finalErr = fmt.Errorf("sandboxed request failed: %w", err)
			break
		}

		// Read body (bounded) only for final non-redirect responses.
		if resp.StatusCode >= 300 && resp.StatusCode < 400 {
			// Capture location header and append hop
			loc := strings.TrimSpace(resp.Header.Get("Location"))
			resolved := loc
			if loc != "" {
				if u, perr := url.Parse(loc); perr == nil {
					if !u.IsAbs() {
						// Resolve relative location against currentURL
						if base, berr := url.Parse(currentURL); berr == nil {
							resolved = base.ResolveReference(u).String()
						}
					}
				}
			}

			chain = append(chain, types.RedirectHop{
				FromURL:    currentURL,
				ToURL:      resolved,
				StatusCode: resp.StatusCode,
			})

			// Prepare for next hop
			if resolved == "" {
				// No usable location, treat as final
				finalResp = resp
				break
			}
			currentURL = resolved
			// close response and continue
			resp.Body.Close()
			continue
		}

		// Non-redirect; capture body and break
		limitedReader := io.LimitReader(resp.Body, s.maxSizeBytes)
		bodyBytes, err := io.ReadAll(limitedReader)
		if err != nil {
			resp.Body.Close()
			finalErr = fmt.Errorf("failed reading sandboxed body: %w", err)
			break
		}
		finalResp = resp
		finalBody = bodyBytes
		break
	}

	if finalErr != nil {
		return nil, finalErr
	}

	if finalResp == nil {
		return nil, fmt.Errorf("no response obtained during sandbox fetch")
	}

	defer finalResp.Body.Close()

	headers := make(map[string]string)
	for k, v := range finalResp.Header {
		if len(v) > 0 {
			headers[strings.ToLower(k)] = v[0]
		}
	}

	bodyStr := string(finalBody)

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
	res := &SandboxResult{
		URL:             targetURL,
		StatusCode:      finalResp.StatusCode,
		Headers:         headers,
		HTMLBody:        bodyStr,
		BodySizeBytes:   len(finalBody),
		Title:           title,
		MetaDescription: metaDesc,
		ScriptsFound:    scripts,
		FormsFound:      forms,
		LinksFound:      links,
		ExecutionTime:   time.Since(startTime),
		SandboxEngine:   "safe_http_isolated",
		RedirectChain:   chain,
		FinalURL:        "",
	}

	if len(chain) > 0 {
		res.FinalURL = chain[len(chain)-1].ToURL
	} else {
		// If no redirects, final URL is the fetched URL
		res.FinalURL = finalResp.Request.URL.String()
	}

	return res, nil
}
