package types

import "time"

// WSEventType represents a type of WebSocket message event.
type WSEventType string

const (
	EventInvestigationStarted WSEventType = "investigation.started"
	EventAnalysisStarted      WSEventType = "analysis.started"
	EventAnalysisProgress     WSEventType = "analysis.progress"
	EventEvidenceFound        WSEventType = "evidence.found"
	EventAIAnalyzing          WSEventType = "ai.analyzing"
	EventAssessmentCompleted  WSEventType = "assessment.completed"
	EventMessageReceived      WSEventType = "message.received"
	EventError                WSEventType = "error"
	EventPing                 WSEventType = "ping"
	EventPong                 WSEventType = "pong"
	EventUserPrompt           WSEventType = "user.prompt"
)

// WSEvent represents a real-time event dispatched to clients.
type WSEvent struct {
	Event           WSEventType `json:"event"`
	InvestigationID string      `json:"investigation_id,omitempty"`
	CaseID          string      `json:"case_id,omitempty"`
	Stage           string      `json:"stage,omitempty"`
	Progress        int         `json:"progress,omitempty"` // 0 - 100
	Target          string      `json:"target,omitempty"`
	TargetType      TargetType  `json:"target_type,omitempty"`
	Evidence        any         `json:"evidence,omitempty"`
	Assessment      *FinalAssessment `json:"assessment,omitempty"`
	Message         *CaseMessage     `json:"message,omitempty"`
	Error           string      `json:"error,omitempty"`
	Timestamp       time.Time   `json:"timestamp"`
}

// NewWSEvent is a helper to construct a timestamped WebSocket event.
func NewWSEvent(eventType WSEventType, investigationID string) WSEvent {
	return WSEvent{
		Event:           eventType,
		InvestigationID: investigationID,
		Timestamp:       time.Now().UTC(),
	}
}
