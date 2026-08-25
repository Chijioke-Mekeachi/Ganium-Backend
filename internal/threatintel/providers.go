package threatintel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"ganium/internal/security"
)

// VirusTotalProvider integrates with VirusTotal v3 API.
type VirusTotalProvider struct {
	apiKey string
	client *http.Client
}

func NewVirusTotalProvider(apiKey string) *VirusTotalProvider {
	return &VirusTotalProvider{
		apiKey: apiKey,
		client: security.SafeHTTPClient(6*time.Second, 2),
	}
}

func (v *VirusTotalProvider) Name() string {
	return "virustotal"
}

func (v *VirusTotalProvider) CheckDomain(ctx context.Context, domain string) (*ThreatReport, error) {
	if v.apiKey == "" {
		return nil, nil // gracefully skip if no key configured
	}

	reqURL := fmt.Sprintf("https://www.virustotal.com/api/v3/domains/%s", domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("x-apikey", v.apiKey)

	resp, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return &ThreatReport{Source: v.Name(), Target: domain, Reputation: "clean", Confidence: 0.5}, nil
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("VT API error: HTTP %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	var vtResp struct {
		Data struct {
			Attributes struct {
				LastAnalysisStats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Harmless   int `json:"harmless"`
					Undetected int `json:"undetected"`
				} `json:"last_analysis_stats"`
			} `json:"attributes"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &vtResp); err != nil {
		return nil, err
	}

	stats := vtResp.Data.Attributes.LastAnalysisStats
	isMal := stats.Malicious > 0
	isSusp := stats.Suspicious > 0
	rep := "clean"
	if isMal {
		rep = "malicious"
	} else if isSusp {
		rep = "suspicious"
	}

	return &ThreatReport{
		Source:     v.Name(),
		Target:     domain,
		IsPhishing: stats.Malicious > 0,
		IsMalware:  stats.Malicious > 1,
		Reputation: rep,
		Confidence: 0.90,
		Details:    fmt.Sprintf("VT Detections: %d malicious, %d suspicious out of %d engines", stats.Malicious, stats.Suspicious, stats.Malicious+stats.Suspicious+stats.Harmless+stats.Undetected),
	}, nil
}

func (v *VirusTotalProvider) CheckIP(ctx context.Context, ip string) (*ThreatReport, error) {
	return nil, nil
}

func (v *VirusTotalProvider) CheckURL(ctx context.Context, rawURL string) (*ThreatReport, error) {
	return nil, nil
}

func (v *VirusTotalProvider) CheckWallet(ctx context.Context, network, address string) (*ThreatReport, error) {
	return nil, nil
}

// MockProvider is used for unit and integration testing.
type MockProvider struct {
	Report *ThreatReport
}

func (m *MockProvider) Name() string { return "mock_threat_intel" }
func (m *MockProvider) CheckDomain(ctx context.Context, domain string) (*ThreatReport, error) {
	if m.Report != nil {
		return m.Report, nil
	}
	return &ThreatReport{Source: m.Name(), Target: domain, Reputation: "clean", Confidence: 0.9}, nil
}
func (m *MockProvider) CheckIP(ctx context.Context, ip string) (*ThreatReport, error) {
	return m.Report, nil
}
func (m *MockProvider) CheckURL(ctx context.Context, url string) (*ThreatReport, error) {
	if m.Report != nil {
		return m.Report, nil
	}
	if strings.Contains(url, "malicious-phish.com") {
		return &ThreatReport{
			Source:     m.Name(),
			Target:     url,
			IsPhishing: true,
			IsScam:     true,
			Reputation: "malicious",
			Labels:     []string{"mock_phish_flag"},
			Confidence: 0.98,
			Details:    "Mock detected phishing test target",
		}, nil
	}
	return &ThreatReport{Source: m.Name(), Target: url, Reputation: "clean", Confidence: 0.9}, nil
}
func (m *MockProvider) CheckWallet(ctx context.Context, network, address string) (*ThreatReport, error) {
	if m.Report != nil {
		return m.Report, nil
	}
	if strings.HasPrefix(strings.ToLower(address), "0xdead") {
		return &ThreatReport{
			Source:     m.Name(),
			Target:     address,
			IsScam:     true,
			Reputation: "malicious",
			Confidence: 0.95,
			Details:    "Mock detected drainer test address",
		}, nil
	}
	return &ThreatReport{Source: m.Name(), Target: address, Reputation: "clean", Confidence: 0.8}, nil
}
