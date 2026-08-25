package controllers

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"ganium/src/db"
	"ganium/src/models"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"ganium/src/notify"
)

// ============================================================
// GET NOTIFICATIONS
// ============================================================
func CreateNotification(email, title, message, notifType string) error {
	return notify.Create(email, title, message, notifType)
}


func GetNotifications(email string) ([]models.Notification, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return nil, fmt.Errorf("email is required")
	}

	collection := db.MongoClient.
		Database(db.DatabaseName).
		Collection("notifications")

	findOptions := options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}})

	cursor, err := collection.Find(
		context.Background(),
		bson.M{"user_id": email},
		findOptions,
	)
	if err != nil {
		return nil, err
	}
	defer cursor.Close(context.Background())

	notifications := []models.Notification{}
	if err := cursor.All(context.Background(), &notifications); err != nil {
		return nil, err
	}

	return notifications, nil
}

// ============================================================
// DELETE NOTIFICATION
// ============================================================

func DeleteNotification(email, id string) error {
	email = strings.TrimSpace(email)
	id = strings.TrimSpace(id)

	if email == "" {
		return fmt.Errorf("email is required")
	}

	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return fmt.Errorf("invalid notification id")
	}

	collection := db.MongoClient.
		Database(db.DatabaseName).
		Collection("notifications")

	result, err := collection.DeleteOne(
		context.Background(),
		bson.M{"_id": objectID, "user_id": email},
	)
	if err != nil {
		return err
	}

	if result.DeletedCount == 0 {
		return fmt.Errorf("notification not found")
	}

	return nil
}

// ============================================================
// UPDATE NOTIFICATION
// ============================================================

func UpdateNotification(
	email, id string,
	payload models.NotificationUpdateRequest,
) (*models.Notification, error) {
	email = strings.TrimSpace(email)
	id = strings.TrimSpace(id)

	if email == "" {
		return nil, fmt.Errorf("email is required")
	}

	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, fmt.Errorf("invalid notification id")
	}

	updates := bson.M{}

	if title := strings.TrimSpace(payload.Title); title != "" {
		updates["title"] = title
	}

	if message := strings.TrimSpace(payload.Message); message != "" {
		updates["message"] = message
	}

	if len(updates) == 0 {
		return getNotificationByID(email, objectID)
	}

	updates["updated_at"] = time.Now().UTC()

	collection := db.MongoClient.
		Database(db.DatabaseName).
		Collection("notifications")

	result, err := collection.UpdateOne(
		context.Background(),
		bson.M{"_id": objectID, "user_id": email},
		bson.M{"$set": updates},
	)
	if err != nil {
		return nil, err
	}

	if result.MatchedCount == 0 {
		return nil, fmt.Errorf("notification not found")
	}

	return getNotificationByID(email, objectID)
}

// ============================================================
// MARK NOTIFICATION AS READ
// ============================================================

func MarkNotificationAsRead(email, id string) (*models.Notification, error) {
	email = strings.TrimSpace(email)
	id = strings.TrimSpace(id)

	if email == "" {
		return nil, fmt.Errorf("email is required")
	}

	objectID, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return nil, fmt.Errorf("invalid notification id")
	}

	collection := db.MongoClient.
		Database(db.DatabaseName).
		Collection("notifications")

	result, err := collection.UpdateOne(
		context.Background(),
		bson.M{"_id": objectID, "user_id": email},
		bson.M{"$set": bson.M{
			"read":       true,
			"updated_at": time.Now().UTC(),
		}},
	)
	if err != nil {
		return nil, err
	}

	if result.MatchedCount == 0 {
		return nil, fmt.Errorf("notification not found")
	}

	return getNotificationByID(email, objectID)
}

// ============================================================
// FETCH NOTIFICATION BY ID
// ============================================================

func getNotificationByID(
	email string,
	id primitive.ObjectID,
) (*models.Notification, error) {
	collection := db.MongoClient.
		Database(db.DatabaseName).
		Collection("notifications")

	var notification models.Notification

	err := collection.FindOne(
		context.Background(),
		bson.M{"_id": id, "user_id": email},
	).Decode(&notification)

	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, fmt.Errorf("notification not found")
		}
		return nil, err
	}

	return &notification, nil
}

// ============================================================
// CREATE NOTIFICATION (internal helper, used by other controllers)
// ============================================================
