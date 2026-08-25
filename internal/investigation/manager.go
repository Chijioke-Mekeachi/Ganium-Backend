package investigation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"ganium/internal/ai"
	"ganium/internal/config"
	"ganium/internal/messageanalyzer"
	"ganium/internal/sandbox"
	"ganium/internal/security"
	"ganium/internal/threatintel"
	"ganium/internal/urlanalyzer"
	"ganium/internal/walletanalyzer"
	"ganium/pkg/types"
)

// Request describes a single investigation request.
type Request struct {
	InvestigationID string
	CaseID          string
	TargetType      types.TargetType
	Target          string
	Network         string
	Source          string
}

// Result bundles the collected evidence and the final AI assessment.
type Result struct {
	Evidence   types.UnifiedInvestigationEvidence
	Assessment *types.FinalAssessment
}

// Manager coordinates deterministic evidence collection and final AI analysis.
type Manager struct {
	urlAnalyzer     urlanalyzer.URLAnalyzer
	walletAnalyzer  walletanalyzer.WalletAnalyzer
	messageAnalyzer messageanalyzer.MessageAnalyzer
	threatIntel     *threatintel.Aggregator
	analyst         ai.Analyst
	timeout         time.Duration
}

// NewManagerFromConfig constructs the full investigation stack from runtime config.
func NewManagerFromConfig(cfg *config.Config) *Manager {
	if cfg == nil {
		cfg = config.LoadFromEnv()
	}

	cache := threatintel.NewInMemoryCache(30 * time.Minute)
	providers := []threatintel.ThreatIntelProvider{
		threatintel.NewLocalFeedProvider(),
	}
	if strings.TrimSpace(cfg.VirusTotalAPIKey) != "" {
		providers = append(providers, threatintel.NewVirusTotalProvider(cfg.VirusTotalAPIKey))
	}

	aggregator := threatintel.NewAggregator(cache, providers...)
	sandboxRunner := sandbox.NewHTTPSandbox(cfg.HTTPTimeout, cfg.MaxBodySizeBytes, cfg.MaxRedirects)

	return &Manager{
		urlAnalyzer:     urlanalyzer.NewPipeline(aggregator, sandboxRunner, cfg.HTTPTimeout),
		walletAnalyzer:  walletanalyzer.NewAnalyzer(aggregator, cfg.SolanaRPCURL, cfg.EthereumRPCURL),
		messageAnalyzer: messageanalyzer.NewAnalyzer(),
		threatIntel:     aggregator,
		analyst:         ai.NewGeminiAnalyst(cfg.GeminiAPIKey, cfg.GeminiModel),
		timeout:         cfg.HTTPTimeout,
	}
}

// Investigate collects evidence, normalizes it, and produces the final AI verdict.
func (m *Manager) Investigate(ctx context.Context, req Request) (*Result, error) {
	if m == nil {
		return nil, fmt.Errorf("investigation manager is not configured")
	}

	target := strings.TrimSpace(req.Target)
	if target == "" {
		return nil, fmt.Errorf("target cannot be empty")
	}

	investigationID := strings.TrimSpace(req.InvestigationID)
	if investigationID == "" {
		investigationID = newInvestigationID()
	}

	resolvedType := normalizeTargetType(req.TargetType, target)
	start := time.Now()

	bundle := types.UnifiedInvestigationEvidence{
		InvestigationID: investigationID,
		CaseID:          strings.TrimSpace(req.CaseID),
		TargetType:      resolvedType,
		Target:          target,
		CollectedAt:     time.Now().UTC(),
		AuditMetadata: map[string]any{
			"requested_target_type": string(req.TargetType),
			"resolved_target_type":  string(resolvedType),
			"source":                strings.TrimSpace(req.Source),
		},
	}

	switch resolvedType {
	case types.TargetTypeURL, types.TargetTypeWebsite, types.TargetTypeDomain:
		urlEvidence, err := m.collectURLEvidence(ctx, target)
		if err != nil {
			return nil, err
		}
		bundle.URLEvidence = urlEvidence
		bundle.ThreatIntel = urlEvidence.ThreatIntelligence
		if urlEvidence != nil {
			bundle.Relationships = append(bundle.Relationships, redirectRelationships(target, urlEvidence)...)
		}
	case types.TargetTypeWallet:
		walletEvidence, err := m.collectWalletEvidence(ctx, req.Network, target)
		if err != nil {
			return nil, err
		}
		bundle.WalletEvidence = walletEvidence
		bundle.ThreatIntel = walletEvidence.ThreatIntelligence
	case types.TargetTypeMessage, types.TargetTypeCase:
		messageEvidence, err := m.collectMessageEvidence(ctx, target, req.Source)
		if err != nil {
			return nil, err
		}
		bundle.MessageEvidence = messageEvidence
		bundle.Relationships = append(bundle.Relationships, messageRelationships(target, messageEvidence)...)
	}

	if bundle.ThreatIntel.Reputation == "" {
		bundle.ThreatIntel.Reputation = "unknown"
	}
	if bundle.AuditMetadata == nil {
		bundle.AuditMetadata = make(map[string]any)
	}
	bundle.AuditMetadata["collection_duration_ms"] = time.Since(start).Milliseconds()
	bundle.AuditMetadata["deterministic_sources"] = []string{
		"url_analyzer",
		"wallet_analyzer",
		"message_analyzer",
		"threat_intel",
	}

	assessment, err := m.analyst.Assess(ctx, bundle)
	if err != nil || assessment == nil {
		reason := "AI assessment unavailable"
		if err != nil {
			reason = reason + ": " + err.Error()
		}
		fallback := types.DefaultUnknownAssessment(investigationID, reason)
		fallback.Entities = snapshotEntities(bundle)
		fallback.ModelName = "unavailable"
		assessment = &fallback
	}

	return &Result{
		Evidence:   bundle,
		Assessment: assessment,
	}, nil
}

func (m *Manager) collectURLEvidence(ctx context.Context, target string) (*types.URLEvidence, error) {
	normalized, err := ensureURL(target)
	if err != nil {
		return nil, err
	}
	evidence, err := m.urlAnalyzer.Analyze(ctx, normalized)
	if err != nil {
		return nil, err
	}
	return evidence, nil
}

func (m *Manager) collectWalletEvidence(ctx context.Context, network, target string) (*types.WalletEvidence, error) {
	evidence, err := m.walletAnalyzer.Analyze(ctx, network, target)
	if err != nil {
		return nil, err
	}
	return evidence, nil
}

func (m *Manager) collectMessageEvidence(ctx context.Context, target, source string) (*types.MessageEvidence, error) {
	if strings.TrimSpace(source) == "" {
		source = "arbitrary"
	}
	evidence, err := m.messageAnalyzer.Analyze(ctx, target, source)
	if err != nil {
		return nil, err
	}
	return evidence, nil
}

func normalizeTargetType(declared types.TargetType, target string) types.TargetType {
	declared = types.TargetType(strings.ToLower(strings.TrimSpace(string(declared))))
	switch declared {
	case types.TargetTypeURL, types.TargetTypeWebsite, types.TargetTypeWallet, types.TargetTypeMessage, types.TargetTypeCase, types.TargetTypeDomain:
		return declared
	}

	trimmed := strings.TrimSpace(target)
	if looksLikeWallet(trimmed) {
		return types.TargetTypeWallet
	}
	if u, err := url.Parse(trimmed); err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Hostname() != "" {
		return types.TargetTypeURL
	}
	if strings.Contains(trimmed, ".") && !strings.Contains(trimmed, " ") {
		return types.TargetTypeDomain
	}
	return types.TargetTypeMessage
}

func ensureURL(target string) (string, error) {
	trimmed := strings.TrimSpace(target)
	if trimmed == "" {
		return "", fmt.Errorf("target cannot be empty")
	}
	if _, err := security.ValidateTargetURL(trimmed); err == nil {
		return trimmed, nil
	}
	if !strings.HasPrefix(trimmed, "http://") && !strings.HasPrefix(trimmed, "https://") {
		candidate := "https://" + trimmed
		if _, err := security.ValidateTargetURL(candidate); err == nil {
			return candidate, nil
		}
		return "", fmt.Errorf("invalid URL target: %s", target)
	}
	return "", fmt.Errorf("invalid URL target: %s", target)
}

func newInvestigationID() string {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "GAN-UNKNOWN"
	}
	return "GAN-" + strings.ToUpper(hex.EncodeToString(raw[:]))[:6]
}

func looksLikeWallet(target string) bool {
	trimmed := strings.TrimSpace(target)
	return evmWalletPattern.MatchString(trimmed) || btcWalletPattern.MatchString(trimmed) || solWalletPattern.MatchString(trimmed)
}

func snapshotEntities(bundle types.UnifiedInvestigationEvidence) types.ExtractedEntities {
	var entities types.ExtractedEntities
	if bundle.URLEvidence != nil {
		entities.URLs = append(entities.URLs, bundle.URLEvidence.NormalizedURL)
		entities.Domains = append(entities.Domains, bundle.URLEvidence.Domain.Name)
	}
	if bundle.WalletEvidence != nil {
		entities.WalletAddresses = append(entities.WalletAddresses, bundle.WalletEvidence.Address)
	}
	if bundle.MessageEvidence != nil {
		entities = mergeEntities(entities, bundle.MessageEvidence.ExtractedEntities)
	}
	entities.URLs = uniqueStrings(entities.URLs)
	entities.WalletAddresses = uniqueStrings(entities.WalletAddresses)
	entities.Domains = uniqueStrings(entities.Domains)
	entities.Usernames = uniqueStrings(entities.Usernames)
	entities.EmailAddresses = uniqueStrings(entities.EmailAddresses)
	entities.PhoneNumbers = uniqueStrings(entities.PhoneNumbers)
	entities.TransactionHashes = uniqueStrings(entities.TransactionHashes)
	entities.ContractAddresses = uniqueStrings(entities.ContractAddresses)
	return entities
}

func mergeEntities(dst, src types.ExtractedEntities) types.ExtractedEntities {
	dst.URLs = append(dst.URLs, src.URLs...)
	dst.WalletAddresses = append(dst.WalletAddresses, src.WalletAddresses...)
	dst.Domains = append(dst.Domains, src.Domains...)
	dst.Usernames = append(dst.Usernames, src.Usernames...)
	dst.EmailAddresses = append(dst.EmailAddresses, src.EmailAddresses...)
	dst.PhoneNumbers = append(dst.PhoneNumbers, src.PhoneNumbers...)
	dst.TransactionHashes = append(dst.TransactionHashes, src.TransactionHashes...)
	dst.ContractAddresses = append(dst.ContractAddresses, src.ContractAddresses...)
	return dst
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func redirectRelationships(target string, evidence *types.URLEvidence) []types.TargetRelationship {
	if evidence == nil {
		return nil
	}

	var relationships []types.TargetRelationship
	if evidence.Redirects.FinalDestination != "" && evidence.Redirects.FinalDestination != target {
		relationships = append(relationships, types.TargetRelationship{
			SourceTarget: target,
			SourceType:   string(types.TargetTypeURL),
			RelationType: "redirects_to",
			TargetTarget: evidence.Redirects.FinalDestination,
			TargetType:   string(types.TargetTypeURL),
			Details:      "Final destination discovered during safe redirect analysis",
		})
	}
	for _, hop := range evidence.Redirects.Chain {
		if hop.ToURL == "" || hop.ToURL == hop.FromURL {
			continue
		}
		relationships = append(relationships, types.TargetRelationship{
			SourceTarget: hop.FromURL,
			SourceType:   string(types.TargetTypeURL),
			RelationType: "redirects_to",
			TargetTarget: hop.ToURL,
			TargetType:   string(types.TargetTypeURL),
			Details:      fmt.Sprintf("HTTP %d", hop.StatusCode),
		})
	}
	return relationships
}

func messageRelationships(target string, evidence *types.MessageEvidence) []types.TargetRelationship {
	if evidence == nil {
		return nil
	}

	var relationships []types.TargetRelationship
	for _, value := range evidence.ExtractedEntities.URLs {
		relationships = append(relationships, types.TargetRelationship{
			SourceTarget: target,
			SourceType:   string(types.TargetTypeMessage),
			RelationType: "extracted_from",
			TargetTarget: value,
			TargetType:   string(types.TargetTypeURL),
		})
	}
	for _, value := range evidence.ExtractedEntities.WalletAddresses {
		relationships = append(relationships, types.TargetRelationship{
			SourceTarget: target,
			SourceType:   string(types.TargetTypeMessage),
			RelationType: "extracted_from",
			TargetTarget: value,
			TargetType:   string(types.TargetTypeWallet),
		})
	}
	for _, value := range evidence.ExtractedEntities.Domains {
		relationships = append(relationships, types.TargetRelationship{
			SourceTarget: target,
			SourceType:   string(types.TargetTypeMessage),
			RelationType: "mentions",
			TargetTarget: value,
			TargetType:   string(types.TargetTypeDomain),
		})
	}
	return relationships
}

var (
	evmWalletPattern = regexp.MustCompile(`^(0x[a-fA-F0-9]{40}|[a-zA-Z0-9_.-]+\.eth)$`)
	btcWalletPattern = regexp.MustCompile(`^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$`)
	solWalletPattern = regexp.MustCompile(`^[1-9A-HJ-NP-Za-km-z]{32,44}$`)
)
