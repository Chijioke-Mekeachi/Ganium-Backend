package notify

import (
	"context"
	"fmt"
	"strings"
	"time"

	"ganium/src/db"
	"ganium/src/models"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

// Create inserts a notification for the given user. Safe to call
// from any package (controllers, auth, etc.) with no import cycle.
func Create(email, title, message, notifType string) error {
	email = strings.TrimSpace(email)
	if email == "" {
		return fmt.Errorf("email is required")
	}

	collection := db.MongoClient.
		Database(db.DatabaseName).
		Collection("notifications")

	now := time.Now().UTC()

	notification := models.Notification{
		ID:        primitive.NewObjectID(),
		UserID:    email,
		Title:     title,
		Message:   message,
		Type:      notifType,
		Read:      false,
		CreatedAt: now,
		UpdatedAt: now,
	}

	_, err := collection.InsertOne(context.Background(), notification)
	return err
}