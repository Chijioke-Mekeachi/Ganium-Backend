package messageanalyzer

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"time"

	"ganium/pkg/types"
)

// MessageAnalyzer defines the contract for message analysis.
type MessageAnalyzer interface {
	Analyze(ctx context.Context, message string, source string) (*types.MessageEvidence, error)
}

// Analyzer inspects messages for social engineering, crypto scams, urgency, and extracts entities.
type Analyzer struct{}

func NewAnalyzer() *Analyzer {
	return &Analyzer{}
}

var (
	urgencyPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(immediate(ly)?|urgent(ly)?|act now|within 24 hours|expires soon|final warning|account suspended|security breach|risk of loss)\b`),
		regexp.MustCompile(`(?i)\b(limited time|only a few spots|before it is too late|last chance)\b`),
	}

	impersonationPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(metamask support|binance team|opensea support|coinbase helpdesk|trust wallet support|telegram admin|discord mod|customer care agent)\b`),
		regexp.MustCompile(`(?i)\b(official support|security desk|compliance officer|airdrop manager)\b`),
	}

	cryptoRewardPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(won\s+\d+(\.\d+)?\s*(usdt|usdc|eth|btc|sol|bnb)|claim\s+(free\s+)?(reward|airdrop|tokens|prize)|guaranteed\s+(100x|1000%|profit|return))\b`),
		regexp.MustCompile(`(?i)\b(exclusive giveaway|presale allocation|free mint|bonus tokens)\b`),
	}

	credentialPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(seed phrase|recovery phrase|12 words|24 words|private key|mnemonic|enter your secret phrase|backup phrase)\b`),
		regexp.MustCompile(`(?i)\b(verify your identity by entering password|synchronize wallet|import wallet)\b`),
	}

	drainerPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(connect wallet to claim|sign message to verify|approve transaction to receive|claim gas refund)\b`),
	}

	fearPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)\b(your assets will be frozen|account terminated|legal action|compromised wallet|unauthorized transaction)\b`),
	}
)

// Analyze performs NLP heuristics and entity extraction on the message text.
func (a *Analyzer) Analyze(ctx context.Context, message string, source string) (*types.MessageEvidence, error) {
	startTime := time.Now()
	trimmed := strings.TrimSpace(message)

	hasher := sha256.New()
	hasher.Write([]byte(trimmed))
	msgHash := hex.EncodeToString(hasher.Sum(nil))[:16]

	if source == "" {
		source = "arbitrary"
	}

	signals := types.MessageAnalysisSignals{}
	var detectedKw []string
	var impersonatedBrands []string

	// 1. Urgency Detection
	for _, p := range urgencyPatterns {
		if p.MatchString(trimmed) {
			signals.Urgency = true
			detectedKw = append(detectedKw, p.FindString(trimmed))
		}
	}

	// 2. Impersonation Detection
	for _, p := range impersonationPatterns {
		if p.MatchString(trimmed) {
			signals.Impersonation = true
			detectedKw = append(detectedKw, p.FindString(trimmed))
		}
	}

	// Known brands check
	brands := []string{"MetaMask", "Binance", "Coinbase", "Trust Wallet", "Phantom", "Ledger", "OpenSea", "Uniswap", "Telegram", "Discord"}
	for _, b := range brands {
		if strings.Contains(strings.ToLower(trimmed), strings.ToLower(b)) {
			impersonatedBrands = append(impersonatedBrands, b)
		}
	}

	// 3. Crypto Reward / Giveaway
	for _, p := range cryptoRewardPatterns {
		if p.MatchString(trimmed) {
			signals.CryptoReward = true
			signals.FakeGiveaway = true
			detectedKw = append(detectedKw, p.FindString(trimmed))
		}
	}

	// 4. Credential & Seed Phrase Harvesting
	for _, p := range credentialPatterns {
		if p.MatchString(trimmed) {
			signals.CredentialRequest = true
			signals.SeedPhraseRequest = true
			detectedKw = append(detectedKw, p.FindString(trimmed))
		}
	}

	// 5. Drainer Techniques
	for _, p := range drainerPatterns {
		if p.MatchString(trimmed) {
			signals.DrainerTechnique = true
			detectedKw = append(detectedKw, p.FindString(trimmed))
		}
	}

	// 6. Fear Tactics
	for _, p := range fearPatterns {
		if p.MatchString(trimmed) {
			signals.FearTactics = true
			detectedKw = append(detectedKw, p.FindString(trimmed))
		}
	}

	// 7. Entity Extraction
	entities := ExtractEntities(trimmed)
	if len(entities.URLs) > 0 {
		signals.MaliciousLinks = true
	}

	signals.DetectedKeywords = unique(detectedKw)
	signals.ImpersonatedBrands = unique(impersonatedBrands)

	evidence := &types.MessageEvidence{
		TargetType:        types.TargetTypeMessage,
		MessageSource:     source,
		MessageLength:     len(trimmed),
		MessageHash:       msgHash,
		MessageAnalysis:   signals,
		ExtractedEntities: entities,
		CollectedAt:       time.Now().UTC(),
		ExecutionTimeMs:   time.Since(startTime).Milliseconds(),
	}

	return evidence, nil
}
