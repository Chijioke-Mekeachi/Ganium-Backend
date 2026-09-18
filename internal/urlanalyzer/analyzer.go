package urlanalyzer

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"ganium/internal/sandbox"
	"ganium/internal/security"
	"ganium/internal/threatintel"
	"ganium/pkg/types"
)

// URLAnalyzer defines the contract for analyzing URLs and websites.
type URLAnalyzer interface {
	Analyze(ctx context.Context, targetURL string) (*types.URLEvidence, error)
}

// Pipeline implements the URL investigation pipeline.
type Pipeline struct {
	dnsInspector *DNSInspector
	tlsInspector *TLSInspector
	sandbox      sandbox.SandboxRunner
	threatIntel  *threatintel.Aggregator
	timeout      time.Duration
}

// NewPipeline initializes a full URL investigation pipeline.
func NewPipeline(threatIntel *threatintel.Aggregator, runner sandbox.SandboxRunner, timeout time.Duration) *Pipeline {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if runner == nil {
		runner = sandbox.NewHTTPSandbox(6*time.Second, 512*1024, 4)
	}
	return &Pipeline{
		dnsInspector: NewDNSInspector(3 * time.Second),
		tlsInspector: NewTLSInspector(3 * time.Second),
		sandbox:      runner,
		threatIntel:  threatIntel,
		timeout:      timeout,
	}
}

// Analyze runs the complete deterministic evidence collection for a URL.
func (p *Pipeline) Analyze(ctx context.Context, rawURL string) (*types.URLEvidence, error) {
	startTime := time.Now()

	parsed, err := security.ValidateTargetURL(rawURL)
	if err != nil {
		// Attempt scheme prepending if missing
		if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
			parsed, err = security.ValidateTargetURL("https://" + rawURL)
		}
		if err != nil {
			return nil, fmt.Errorf("invalid URL target: %w", err)
		}
	}

	hostname := parsed.Hostname()
	normalizedURL := parsed.String()

	evidence := &types.URLEvidence{
		TargetType:    types.TargetTypeURL,
		Target:        rawURL,
		NormalizedURL: normalizedURL,
		CollectedAt:   time.Now().UTC(),
		URLStructure:  AnalyzeURLStructure(parsed),
	}

	// Concurrent evidence gathering
	var wg sync.WaitGroup
	var dnsErr, tlsErr error

	// 1. DNS Analysis
	wg.Add(1)
	go func() {
		defer wg.Done()
		dEv, err := p.dnsInspector.InspectDomain(ctx, hostname)
		if err != nil {
			dnsErr = err
		}
		evidence.Domain = dEv
	}()

	// 2. TLS Analysis (if HTTPS or standard port)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if parsed.Scheme == "https" || parsed.Port() == "443" || parsed.Port() == "" {
			tEv, err := p.tlsInspector.InspectTLS(ctx, hostname)
			if err != nil {
				tlsErr = err
			}
			evidence.TLS = tEv
		}
	}()

	// 3. Threat Intelligence
	wg.Add(1)
	go func() {
		defer wg.Done()
		if p.threatIntel != nil {
			evidence.ThreatIntelligence = p.threatIntel.CheckURL(ctx, normalizedURL)
			if evidence.ThreatIntelligence.Reputation == "unknown" {
				// Fallback to domain check
				evidence.ThreatIntelligence = p.threatIntel.CheckDomain(ctx, hostname)
			}
		}
	}()

	// 4. Safe Sandbox / Content Inspection
	wg.Add(1)
	go func() {
		defer wg.Done()
		if p.sandbox != nil {
			sandRes, err := p.sandbox.InspectURL(ctx, normalizedURL)
			if err == nil && sandRes != nil {
				evidence.Website = AnalyzeWebsiteContent(sandRes)

				// Build redirect evidence from sandbox redirect chain if available
				if len(sandRes.RedirectChain) > 0 {
					var final string
					for _, hop := range sandRes.RedirectChain {
						final = hop.ToURL
					}
					evidence.Redirects = types.RedirectEvidence{
						Count:            len(sandRes.RedirectChain),
						FinalDestination: final,
						CrossDomain:      isCrossDomain(normalizedURL, final),
						Chain:            sandRes.RedirectChain,
					}
				} else if sandRes.StatusCode >= 300 && sandRes.StatusCode < 400 {
					// Fallback single-location header handling
					dest := sandRes.Headers["location"]
					evidence.Redirects = types.RedirectEvidence{
						Count:            1,
						FinalDestination: dest,
						CrossDomain:      isCrossDomain(normalizedURL, dest),
						Chain: []types.RedirectHop{
							{FromURL: normalizedURL, ToURL: dest, StatusCode: sandRes.StatusCode},
						},
					}
				}

				// Passive endpoint observation (safe GET/HEAD checks) for discovered resources
				endpoints := passiveObserveEndpoints(ctx, sandRes, 6)
				if len(endpoints) > 0 {
					evidence.Website.ObservedEndpoints = endpoints
				}
			}
		}
	}()

	wg.Wait()

	_ = dnsErr
	_ = tlsErr

	evidence.ExecutionTimeMs = time.Since(startTime).Milliseconds()
	return evidence, nil
}

func isCrossDomain(from, to string) bool {
	uFrom, err1 := url.Parse(from)
	uTo, err2 := url.Parse(to)
	if err1 != nil || err2 != nil {
		return false
	}
	return uFrom.Hostname() != uTo.Hostname()
}

// passiveObserveEndpoints performs safe, limited HEAD/GET checks against discovered
// resource URLs (forms, scripts, links) without modifying server state.
func passiveObserveEndpoints(ctx context.Context, res *sandbox.SandboxResult, limit int) []types.EndpointObservation {
	if res == nil || limit <= 0 {
		return nil
	}

	seen := make(map[string]struct{})
	var out []types.EndpointObservation

	addCandidate := func(raw, source string) {
		if raw == "" || len(out) >= limit {
			return
		}
		// Ignore anchors and javascript: links
		if strings.HasPrefix(raw, "#") || strings.HasPrefix(strings.ToLower(raw), "javascript:") {
			return
		}
		resolved := raw
		if u, err := url.Parse(raw); err == nil {
			if !u.IsAbs() {
				if base, berr := url.Parse(res.FinalURL); berr == nil {
					resolved = base.ResolveReference(u).String()
				}
			}
		}
		if _, ok := seen[resolved]; ok {
			return
		}
		seen[resolved] = struct{}{}

		// Validate target URL and only proceed for http(s)
		if _, err := security.ValidateTargetURL(resolved); err != nil {
			return
		}

		// Perform a safe HEAD request with short timeout
		client := security.SafeHTTPClient(4*time.Second, 2)
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }

		reqCtx, cancel := context.WithTimeout(ctx, 4*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(reqCtx, http.MethodHead, resolved, nil)
		if err != nil {
			return
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; GaniumScanner/1.0)")

		resp, err := client.Do(req)
		if err != nil {
			// If HEAD fails, attempt a lightweight GET as fallback for servers that block HEAD
			req, err = http.NewRequestWithContext(reqCtx, http.MethodGet, resolved, nil)
			if err != nil {
				return
			}
			resp, err = client.Do(req)
			if err != nil {
				return
			}
		}
		defer resp.Body.Close()

		ct := resp.Header.Get("Content-Type")
		domain := ""
		if u, err := url.Parse(resolved); err == nil {
			domain = u.Hostname()
		}

		out = append(out, types.EndpointObservation{
			Endpoint:       resolved,
			MethodObserved: "HEAD/GET",
			Status:         resp.StatusCode,
			ContentType:    ct,
			Domain:         domain,
			Source:         source,
		})
	}

	// prioritize forms and scripts, then links
	for _, f := range res.FormsFound {
		addCandidate(f, "form_action")
		if len(out) >= limit {
			return out
		}
	}
	for _, s := range res.ScriptsFound {
		addCandidate(s, "script_reference")
		if len(out) >= limit {
			return out
		}
	}
	for _, l := range res.LinksFound {
		addCandidate(l, "link")
		if len(out) >= limit {
			return out
		}
	}

	return out
}
