package models

import (
	"strings"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

const (
	SupportStatusOpen     = "open"
	SupportStatusPending  = "pending"
	SupportStatusResolved = "resolved"
	SupportStatusClosed   = "closed"

	SupportSenderUser    = "user"
	SupportSenderSupport = "support"
)

var validSupportStatuses = map[string]struct{}{
	SupportStatusOpen:     {},
	SupportStatusPending:  {},
	SupportStatusResolved: {},
	SupportStatusClosed:   {},
}

func IsValidSupportStatus(status string) bool {
	_, ok := validSupportStatuses[strings.ToLower(strings.TrimSpace(status))]
	return ok
}

func NormalizeSupportStatus(status string) string {
	return strings.ToLower(strings.TrimSpace(status))
}

type SupportConversation struct {
	ID            bson.ObjectID  `json:"id" bson:"_id,omitempty"`
	UserID        bson.ObjectID  `json:"userId" bson:"user_id"`
	Subject       string         `json:"subject" bson:"subject"`
	Status        string         `json:"status" bson:"status"`
	AssignedTo    *bson.ObjectID `json:"assignedTo,omitempty" bson:"assigned_to,omitempty"`
	CreatedAt     time.Time      `json:"createdAt" bson:"created_at"`
	UpdatedAt     time.Time      `json:"updatedAt" bson:"updated_at"`
	LastMessageAt time.Time      `json:"lastMessageAt" bson:"last_message_at"`
}

type SupportMessage struct {
	ID             bson.ObjectID `json:"id" bson:"_id,omitempty"`
	ConversationID bson.ObjectID `json:"conversationId" bson:"conversation_id"`
	SenderID       bson.ObjectID `json:"senderId" bson:"sender_id"`
	SenderType     string        `json:"senderType" bson:"sender_type"`
	Message        string        `json:"message" bson:"message"`
	CreatedAt      time.Time     `json:"createdAt" bson:"created_at"`
	UpdatedAt      time.Time     `json:"updatedAt" bson:"updated_at"`
}

type CreateSupportConversationRequest struct {
	Subject string `json:"subject" example:"Payment problem"`
	Message string `json:"message" example:"My payment was completed but my tokens were not added."`
}

type SupportMessageRequest struct {
	Message string `json:"message" example:"I have attached the payment reference."`
}

type SupportConversationUpdateRequest struct {
	Status     string `json:"status,omitempty" example:"pending"`
	AssignedTo string `json:"assignedTo,omitempty" example:"64d8e0d1a29b3d4a9f3401aa"`
}

type SupportConversationListResponse struct {
	Conversations []SupportConversation `json:"conversations"`
	Page          int                   `json:"page"`
	Limit         int                   `json:"limit"`
	Total         int64                 `json:"total"`
}
