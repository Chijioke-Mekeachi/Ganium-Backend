package types

import "time"

// TargetReference represents a target within an investigation case.
type TargetReference struct {
	ID          string     `json:"id" bson:"id"`
	Type        TargetType `json:"type" bson:"type"`
	Value       string     `json:"value" bson:"value"`
	Network     string     `json:"network,omitempty" bson:"network,omitempty"`
	AddedAt     time.Time  `json:"added_at" bson:"added_at"`
	Source      string     `json:"source,omitempty" bson:"source,omitempty"` // "user_input", "extracted_from_message", "extracted_from_url"
	ParentTarget string    `json:"parent_target,omitempty" bson:"parent_target,omitempty"`
}

// SenderRole identifies who sent a message in an investigation session.
type SenderRole string

const (
	SenderRoleUser   SenderRole = "user"
	SenderRoleAI     SenderRole = "ganium_ai"
	SenderRoleSystem SenderRole = "system"
)

// CaseMessage represents a chat turn within a multi-target investigation case.
type CaseMessage struct {
	ID                 string           `json:"id" bson:"id"`
	CaseID             string           `json:"case_id" bson:"case_id"`
	Sender             SenderRole       `json:"sender" bson:"sender"`
	Content            string           `json:"content" bson:"content"`
	EvidenceSnapshot   *UnifiedInvestigationEvidence `json:"evidence_snapshot,omitempty" bson:"evidence_snapshot,omitempty"`
	AssessmentSnapshot *FinalAssessment `json:"assessment_snapshot,omitempty" bson:"assessment_snapshot,omitempty"`
	Timestamp          time.Time        `json:"timestamp" bson:"timestamp"`
}

// CaseStatus represents the lifecycle state of a case.
type CaseStatus string

const (
	CaseStatusActive    CaseStatus = "active"
	CaseStatusPending   CaseStatus = "pending"
	CaseStatusCompleted CaseStatus = "completed"
	CaseStatusArchived  CaseStatus = "archived"
)

// Case represents a full investigation case containing multiple targets, evidence, AI decisions, and conversation history.
type Case struct {
	ID                string                       `json:"id" bson:"_id"` // e.g. "GAN-8F29A1"
	UserID            string                       `json:"user_id" bson:"user_id"`
	Title             string                       `json:"title" bson:"title"`
	Status            CaseStatus                   `json:"status" bson:"status"`
	PrimaryTarget     TargetReference              `json:"primary_target" bson:"primary_target"`
	Targets           []TargetReference            `json:"targets" bson:"targets"`
	Relationships     []TargetRelationship         `json:"relationships" bson:"relationships"`
	LatestEvidence    UnifiedInvestigationEvidence `json:"latest_evidence" bson:"latest_evidence"`
	LatestAssessment  *FinalAssessment             `json:"latest_assessment,omitempty" bson:"latest_assessment,omitempty"`
	AssessmentHistory []FinalAssessment            `json:"assessment_history,omitempty" bson:"assessment_history,omitempty"`
	Messages          []CaseMessage                `json:"messages,omitempty" bson:"messages,omitempty"`
	Tags              []string                     `json:"tags,omitempty" bson:"tags,omitempty"`
	CreatedAt         time.Time                    `json:"created_at" bson:"created_at"`
	UpdatedAt         time.Time                    `json:"updated_at" bson:"updated_at"`
}
