package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type RecordScanRequest struct {
	Content         string `json:"content" bson:"content"`
	ContentType     string `json:"content_type" bson:"content_type"`
	RiskScore       string `json:"risk_score" bson:"risk_score"`
	Classification  string `json:"classification" bson:"classification"`
	Explanation     string `json:"explanation" bson:"explanation"`
	Recommendations string `json:"recommendations" bson:"recommendations"`
	ScanType	   string `json:"scan_type" bson:"scan_type"`
}

// ScanRecord represents a record of a scan performed on some content.

type ScanRecord struct {
	ID              primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	UserID          string             `json:"user_id" bson:"user_id"`
	Content         string             `json:"content" bson:"content"`
	ContentType     string             `json:"content_type" bson:"content_type"`
	RiskScore       string             `json:"risk_score" bson:"risk_score"`
	Classification  string             `json:"classification" bson:"classification"`
	Explanation     string             `json:"explanation" bson:"explanation"`
	Recommendations string             `json:"recommendations" bson:"recommendations"`
	TokensUsed      int                `json:"tokens_used" bson:"tokens_used"`
	CreatedAt       time.Time          `json:"created_at" bson:"created_at"`
}
