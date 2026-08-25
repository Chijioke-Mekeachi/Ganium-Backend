package types

// FinalAssessmentJSONSchema defines the JSON Schema that the AI model must strictly adhere to.
const FinalAssessmentJSONSchema = `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "GaniumFinalAssessment",
  "type": "object",
  "required": [
    "risk_score",
    "risk_level",
    "verdict",
    "confidence",
    "summary",
    "reasons",
    "strongest_evidence",
    "uncertainty",
    "recommended_actions"
  ],
  "properties": {
    "investigation_id": { "type": "string" },
    "case_id": { "type": "string" },
    "risk_score": {
      "type": "integer",
      "minimum": 0,
      "maximum": 100
    },
    "risk_level": {
      "type": "string",
      "enum": ["SAFE", "LOW_RISK", "SUSPICIOUS", "HIGH_RISK", "CRITICAL", "UNKNOWN"]
    },
    "verdict": {
      "type": "string",
      "enum": ["SAFE", "LOW_RISK", "SUSPICIOUS", "HIGH_RISK", "CRITICAL", "UNKNOWN"]
    },
    "confidence": {
      "type": "number",
      "minimum": 0.0,
      "maximum": 1.0
    },
    "summary": { "type": "string" },
    "reasons": {
      "type": "array",
      "items": { "type": "string" }
    },
    "strongest_evidence": {
      "type": "array",
      "items": { "type": "string" }
    },
    "uncertainty": {
      "type": "array",
      "items": { "type": "string" }
    },
    "recommended_actions": {
      "type": "array",
      "items": { "type": "string" }
    },
    "false_positive_notes": {
      "type": "array",
      "items": { "type": "string" }
    },
    "entities": {
      "type": "object",
      "properties": {
        "urls": { "type": "array", "items": { "type": "string" } },
        "wallet_addresses": { "type": "array", "items": { "type": "string" } },
        "domains": { "type": "array", "items": { "type": "string" } }
      }
    }
  },
  "additionalProperties": true
}`

// EvidenceJSONSchema defines the JSON Schema format for evidence bundles passed to the AI Analyst.
const EvidenceJSONSchema = `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "title": "GaniumInvestigationEvidence",
  "type": "object",
  "required": [
    "investigation_id",
    "target_type",
    "target",
    "threat_intelligence"
  ],
  "properties": {
    "investigation_id": { "type": "string" },
    "case_id": { "type": "string" },
    "target_type": {
      "type": "string",
      "enum": ["url", "website", "wallet", "message", "case", "domain"]
    },
    "target": { "type": "string" },
    "collected_at": { "type": "string", "format": "date-time" },
    "url_evidence": { "type": "object" },
    "wallet_evidence": { "type": "object" },
    "message_evidence": { "type": "object" },
    "threat_intelligence": { "type": "object" },
    "relationships": { "type": "array" }
  }
}`
