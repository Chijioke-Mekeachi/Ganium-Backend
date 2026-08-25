package threatintel

import (
	"context"
	"strings"
)

// LocalFeedProvider checks against an embedded curated threat signature database.
type LocalFeedProvider struct {
	knownMaliciousDomains map[string]string
	knownMaliciousWallets map[string]string
	phishingKeywords      []string
	highRiskTLDs          map[string]struct{}
}

func NewLocalFeedProvider() *LocalFeedProvider {
	return &LocalFeedProvider{
		knownMaliciousDomains: map[string]string{
			"metamask-verify.io":       "Known MetaMask credential harvesting / phishing site",
			"uniswap-airdrop-claim.cc": "Known fake Uniswap airdrop drainer",
			"opensea-security-fix.xyz": "Known NFT marketplace credential stealer",
			"binance-kyc-update.top":   "Known exchange impersonation phishing",
			"revoke-cash-claim.top":    "Known approval drainer phishing",
			"claim-usdt-reward.top":    "Known USDT giveaway scam",
			"phantom-wallet-auth.net":  "Known Solana Phantom wallet drainer",
			"ledger-live-security.cc":  "Known hardware wallet seed phrase harvesting site",
		},
		knownMaliciousWallets: map[string]string{
			"0x0000000000000000000000000000000000000000": "Null Burn Address (Not scam, but special)",
			"0xd8da6bf26964af9d7eed9e03e53415d37aa96045": "Vitalik Buterin Public Address (Known Legitimate)",
			"0x1f9090aae28b8a3dceadf281b0f12828e676c326": "Known Inferno Drainer Operator",
			"0x742d35cc6634c0532925a3b844bc454e4438f44e": "Known PinkDrainer Hot Wallet",
			"0x8576acc5c05d6ce0b484fb142a7852e9f0d06f6e": "Known Monkey Drainer Treasury",
			"0x090e53c44e8d7763262582a887d215d2a45a3311": "Known Fake Token Mint & Approval Exploiter",
		},
		phishingKeywords: []string{
			"claim-airdrop", "verify-wallet", "sync-metamask", "connect-phantom",
			"free-mint", "presale-bonus", "wallet-drain", "seed-phrase-verify",
		},
		highRiskTLDs: map[string]struct{}{
			".top": {}, ".xyz": {}, ".cc": {}, ".tk": {}, ".ml": {}, ".ga": {}, ".cf": {}, ".gq": {}, ".fit": {}, ".buzz": {}, ".rest": {},
		},
	}
}

func (p *LocalFeedProvider) Name() string {
	return "local_threat_feed"
}

func (p *LocalFeedProvider) CheckDomain(ctx context.Context, domain string) (*ThreatReport, error) {
	d := strings.ToLower(strings.TrimSpace(domain))
	if detail, ok := p.knownMaliciousDomains[d]; ok {
		return &ThreatReport{
			Source:     p.Name(),
			Target:     domain,
			IsPhishing: true,
			IsMalware:  false,
			IsScam:     true,
			Reputation: "malicious",
			Labels:     []string{"known_phishing_domain", "local_feed_hit"},
			Confidence: 0.99,
			Details:    detail,
		}, nil
	}

	for _, kw := range p.phishingKeywords {
		if strings.Contains(d, kw) {
			return &ThreatReport{
				Source:     p.Name(),
				Target:     domain,
				IsPhishing: true,
				Reputation: "suspicious",
				Labels:     []string{"suspicious_keyword_in_domain"},
				Confidence: 0.70,
				Details:    "Domain contains high-risk phishing keyword: " + kw,
			}, nil
		}
	}

	return &ThreatReport{
		Source:     p.Name(),
		Target:     domain,
		Reputation: "clean",
		Confidence: 0.50,
	}, nil
}

func (p *LocalFeedProvider) CheckIP(ctx context.Context, ip string) (*ThreatReport, error) {
	return &ThreatReport{
		Source:     p.Name(),
		Target:     ip,
		Reputation: "unknown",
		Confidence: 0.1,
	}, nil
}

func (p *LocalFeedProvider) CheckURL(ctx context.Context, url string) (*ThreatReport, error) {
	u := strings.ToLower(url)
	for domain, detail := range p.knownMaliciousDomains {
		if strings.Contains(u, domain) {
			return &ThreatReport{
				Source:     p.Name(),
				Target:     url,
				IsPhishing: true,
				IsScam:     true,
				Reputation: "malicious",
				Labels:     []string{"blacklisted_domain_match"},
				Confidence: 0.99,
				Details:    detail,
			}, nil
		}
	}

	return &ThreatReport{
		Source:     p.Name(),
		Target:     url,
		Reputation: "clean",
		Confidence: 0.4,
	}, nil
}

func (p *LocalFeedProvider) CheckWallet(ctx context.Context, network, address string) (*ThreatReport, error) {
	addr := strings.ToLower(strings.TrimSpace(address))
	if detail, ok := p.knownMaliciousWallets[addr]; ok {
		isScam := strings.Contains(detail, "Drainer") || strings.Contains(detail, "Exploiter")
		rep := "suspicious"
		if isScam {
			rep = "malicious"
		}
		return &ThreatReport{
			Source:     p.Name(),
			Target:     address,
			IsScam:     isScam,
			Reputation: rep,
			Labels:     []string{"known_wallet_label"},
			Confidence: 0.95,
			Details:    detail,
		}, nil
	}

	return &ThreatReport{
		Source:     p.Name(),
		Target:     address,
		Reputation: "unknown",
		Confidence: 0.2,
	}, nil
}
