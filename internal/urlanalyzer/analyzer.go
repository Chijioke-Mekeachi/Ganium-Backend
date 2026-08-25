package urlanalyzer

import (
	"context"
	"fmt"
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
				// Check redirects if status was 3xx or chain reported
				if sandRes.StatusCode >= 300 && sandRes.StatusCode < 400 {
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
