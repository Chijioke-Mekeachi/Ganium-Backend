package threatintel

import (
	"context"
	"time"

	"ganium/pkg/types"
)

// TargetKind defines what category of entity is being queried for threat intel.
type TargetKind string

const (
	TargetKindDomain TargetKind = "domain"
	TargetKindIP     TargetKind = "ip"
	TargetKindURL    TargetKind = "url"
	TargetKindWallet TargetKind = "wallet"
)

// ThreatReport represents a normalized finding from a single threat intel source.
type ThreatReport struct {
	Source     string   `json:"source"`
	Target     string   `json:"target"`
	IsPhishing bool     `json:"is_phishing"`
	IsMalware  bool     `json:"is_malware"`
	IsScam     bool     `json:"is_scam"`
	Reputation string   `json:"reputation"` // "clean", "suspicious", "malicious", "unknown"
	Labels     []string `json:"labels,omitempty"`
	Confidence float64  `json:"confidence"`
	Details    string   `json:"details,omitempty"`
}

// ThreatIntelProvider is the pluggable interface for threat intelligence feeds.
type ThreatIntelProvider interface {
	Name() string
	CheckDomain(ctx context.Context, domain string) (*ThreatReport, error)
	CheckIP(ctx context.Context, ip string) (*ThreatReport, error)
	CheckURL(ctx context.Context, url string) (*ThreatReport, error)
	CheckWallet(ctx context.Context, network, address string) (*ThreatReport, error)
}

// Aggregator collects and merges findings across all configured providers.
type Aggregator struct {
	providers []ThreatIntelProvider
	cache     Cache
	timeout   time.Duration
}

// NewAggregator initializes a threat intelligence aggregator.
func NewAggregator(cache Cache, providers ...ThreatIntelProvider) *Aggregator {
	if cache == nil {
		cache = NewInMemoryCache(30 * time.Minute)
	}
	return &Aggregator{
		providers: providers,
		cache:     cache,
		timeout:   5 * time.Second,
	}
}

// CheckURL queries all providers for URL-specific threat intelligence.
func (a *Aggregator) CheckURL(ctx context.Context, targetURL string) types.ThreatIntelligenceEvidence {
	var evidence types.ThreatIntelligenceEvidence
	evidence.Reputation = "unknown"

	if cached, ok := a.cache.Get("url:" + targetURL); ok {
		return cached
	}

	for _, provider := range a.providers {
		provCtx, cancel := context.WithTimeout(ctx, a.timeout)
		report, err := provider.CheckURL(provCtx, targetURL)
		cancel()

		if err != nil || report == nil {
			continue
		}

		a.mergeReport(&evidence, report)
	}

	a.cache.Set("url:"+targetURL, evidence)
	return evidence
}

// CheckDomain queries all providers for domain reputation.
func (a *Aggregator) CheckDomain(ctx context.Context, domain string) types.ThreatIntelligenceEvidence {
	var evidence types.ThreatIntelligenceEvidence
	evidence.Reputation = "unknown"

	if cached, ok := a.cache.Get("domain:" + domain); ok {
		return cached
	}

	for _, provider := range a.providers {
		provCtx, cancel := context.WithTimeout(ctx, a.timeout)
		report, err := provider.CheckDomain(provCtx, domain)
		cancel()

		if err != nil || report == nil {
			continue
		}

		a.mergeReport(&evidence, report)
	}

	a.cache.Set("domain:"+domain, evidence)
	return evidence
}

// CheckWallet queries all providers for blockchain address threat intelligence.
func (a *Aggregator) CheckWallet(ctx context.Context, network, address string) types.ThreatIntelligenceEvidence {
	var evidence types.ThreatIntelligenceEvidence
	evidence.Reputation = "unknown"

	key := "wallet:" + network + ":" + address
	if cached, ok := a.cache.Get(key); ok {
		return cached
	}

	for _, provider := range a.providers {
		provCtx, cancel := context.WithTimeout(ctx, a.timeout)
		report, err := provider.CheckWallet(provCtx, network, address)
		cancel()

		if err != nil || report == nil {
			continue
		}

		a.mergeReport(&evidence, report)
	}

	a.cache.Set(key, evidence)
	return evidence
}

func (a *Aggregator) mergeReport(evidence *types.ThreatIntelligenceEvidence, report *ThreatReport) {
	evidence.TotalEngines++
	evidence.ThreatFeeds = append(evidence.ThreatFeeds, report.Source)

	if report.IsPhishing {
		evidence.Phishing = true
		evidence.MaliciousReports++
	}
	if report.IsMalware {
		evidence.Malware = true
		evidence.MaliciousReports++
	}
	if report.IsScam {
		evidence.MaliciousReports++
		evidence.KnownScamIndicators = append(evidence.KnownScamIndicators, report.Details)
	}

	for _, l := range report.Labels {
		evidence.SecurityLabels = append(evidence.SecurityLabels, l)
	}

	if report.Reputation == "malicious" || evidence.MaliciousReports > 0 {
		evidence.Reputation = "malicious"
	} else if report.Reputation == "suspicious" && evidence.Reputation != "malicious" {
		evidence.Reputation = "suspicious"
	} else if report.Reputation == "clean" && evidence.Reputation == "unknown" {
		evidence.Reputation = "clean"
	}
}
