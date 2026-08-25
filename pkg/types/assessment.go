package types

import "time"

// Verdict represents the security judgment level.
type Verdict string

const (
	VerdictSafe       Verdict = "SAFE"
	VerdictLowRisk    Verdict = "LOW_RISK"
	VerdictSuspicious Verdict = "SUSPICIOUS"
	VerdictHighRisk   Verdict = "HIGH_RISK"
	VerdictCritical   Verdict = "CRITICAL"
	VerdictUnknown    Verdict = "UNKNOWN"
)

// RiskLevel categorizes the severity level.
type RiskLevel string

const (
	RiskLevelSafe       RiskLevel = "SAFE"
	RiskLevelLow        RiskLevel = "LOW_RISK"
	RiskLevelSuspicious RiskLevel = "SUSPICIOUS"
	RiskLevelHigh       RiskLevel = "HIGH_RISK"
	RiskLevelCritical   RiskLevel = "CRITICAL"
	RiskLevelUnknown    RiskLevel = "UNKNOWN"
)

// FinalAssessment is the final decision object produced exclusively by the AI Security Analyst.
type FinalAssessment struct {
	InvestigationID    string            `json:"investigation_id"`
	CaseID             string            `json:"case_id,omitempty"`
	RiskScore          int               `json:"risk_score"` // 0 to 100
	RiskLevel          RiskLevel         `json:"risk_level"`
	Verdict            Verdict           `json:"verdict"`
	Confidence         float64           `json:"confidence"` // 0.0 to 1.0
	Summary            string            `json:"summary"`
	Reasons            []string          `json:"reasons"`
	StrongestEvidence  []string          `json:"strongest_evidence"`
	Uncertainty        []string          `json:"uncertainty"`
	RecommendedActions []string          `json:"recommended_actions"`
	FalsePositiveNotes []string          `json:"false_positive_notes,omitempty"`
	Entities           ExtractedEntities `json:"entities"`
	ModelName          string            `json:"model_name,omitempty"`
	TokensUsed         int               `json:"tokens_used,omitempty"`
	EvaluatedAt        time.Time         `json:"evaluated_at"`
	RawRepaired        bool              `json:"raw_repaired,omitempty"`
}

// IsValidVerdict checks if a string is a valid verdict enum.
func IsValidVerdict(v string) bool {
	switch Verdict(v) {
	case VerdictSafe, VerdictLowRisk, VerdictSuspicious, VerdictHighRisk, VerdictCritical, VerdictUnknown:
		return true
	default:
		return false
	}
}

// NormalizeVerdict ensures that any arbitrary verdict string maps safely to a standard verdict.
func NormalizeVerdict(v string) Verdict {
	switch v {
	case "SAFE", "safe":
		return VerdictSafe
	case "LOW_RISK", "low_risk", "LOW", "low":
		return VerdictLowRisk
	case "SUSPICIOUS", "suspicious", "SUSPECT", "suspect":
		return VerdictSuspicious
	case "HIGH_RISK", "high_risk", "HIGH", "high":
		return VerdictHighRisk
	case "CRITICAL", "critical", "SCAM", "scam", "MALICIOUS", "malicious":
		return VerdictCritical
	default:
		return VerdictUnknown
	}
}

// DefaultUnknownAssessment returns a safe controlled fallback assessment when evidence is insufficient or parsing fails.
func DefaultUnknownAssessment(investigationID, reason string) FinalAssessment {
	return FinalAssessment{
		InvestigationID:    investigationID,
		RiskScore:          50,
		RiskLevel:          RiskLevelUnknown,
		Verdict:            VerdictUnknown,
		Confidence:         0.0,
		Summary:            "Assessment inconclusive. " + reason,
		Reasons:            []string{reason},
		StrongestEvidence:  []string{"Insufficient or conflicting evidence provided."},
		Uncertainty:        []string{"Deterministic signals and AI reasoning could not verify safety or malicious intent."},
		RecommendedActions: []string{"Do not interact with the target until further verification.", "Verify the domain or address through official channels."},
		EvaluatedAt:        time.Now().UTC(),
	}
}
