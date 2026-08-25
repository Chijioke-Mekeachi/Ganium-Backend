package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Notification represents a single notification belonging to a user.
type Notification struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID    string             `bson:"user_id" json:"user_id"`
	Title     string             `bson:"title" json:"title"`
	Message   string             `bson:"message" json:"message"`
	Type      string             `bson:"type,omitempty" json:"type,omitempty"`
	Read      bool               `bson:"read" json:"read"`
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
	UpdatedAt time.Time          `bson:"updated_at" json:"updated_at"`
}

// NotificationUpdateRequest carries editable fields for a notification.
type NotificationUpdateRequest struct {
	Title   string `json:"title,omitempty" example:"Scan complete"`
	Message string `json:"message,omitempty" example:"Your advanced scan finished with a suspicious verdict."`
}