package controllers

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"ganium/src/db"
	"ganium/src/models"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

const maxSupportMessageLength = 5000

var (
	ErrSupportUnauthorized          = errors.New("unauthorized")
	ErrSupportForbidden             = errors.New("forbidden")
	ErrSupportConversationNotFound  = errors.New("conversation not found")
	ErrSupportMessageNotFound       = errors.New("message not found")
	ErrInvalidSupportConversationID = errors.New("invalid conversation id")
	ErrInvalidSupportStatus         = errors.New("invalid status")
)

func EnsureSupportIndexes() error {
	if db.MongoClient == nil {
		return errors.New("database is not initialized")
	}
	ctx := context.Background()

	convCollection := db.MongoClient.Database(db.DatabaseName).Collection("support_conversations")
	_, err := convCollection.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "user_id", Value: 1}}},
		{Keys: bson.D{{Key: "status", Value: 1}}},
		{Keys: bson.D{{Key: "assigned_to", Value: 1}}},
		{Keys: bson.D{{Key: "created_at", Value: -1}}},
		{Keys: bson.D{{Key: "last_message_at", Value: -1}}},
	})
	if err != nil {
		return err
	}

	msgCollection := db.MongoClient.Database(db.DatabaseName).Collection("support_messages")
	_, err = msgCollection.Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "conversation_id", Value: 1}}},
		{Keys: bson.D{{Key: "sender_id", Value: 1}}},
		{Keys: bson.D{{Key: "created_at", Value: -1}}},
	})
	return err
}

func CreateSupportConversation(email string, payload models.CreateSupportConversationRequest) (*models.SupportConversation, *models.SupportMessage, error) {
	if strings.TrimSpace(email) == "" {
		return nil, nil, ErrSupportUnauthorized
	}
	user, err := findUserByEmail(email)
	if err != nil {
		return nil, nil, err
	}

	subject := strings.TrimSpace(payload.Subject)
	if subject == "" {
		return nil, nil, errors.New("subject is required")
	}
	if len(subject) > 200 {
		return nil, nil, errors.New("subject must be 200 characters or fewer")
	}

	messageText, err := normalizeSupportMessage(payload.Message)
	if err != nil {
		return nil, nil, err
	}

	now := time.Now().UTC()
	conversation := &models.SupportConversation{
		UserID:        user.ID,
		Subject:       subject,
		Status:        models.SupportStatusOpen,
		CreatedAt:     now,
		UpdatedAt:     now,
		LastMessageAt: now,
	}

	result, err := supportConversationsCollection().InsertOne(context.Background(), conversation)
	if err != nil {
		return nil, nil, err
	}
	conversation.ID = result.InsertedID.(bson.ObjectID)

	message := &models.SupportMessage{
		ConversationID: conversation.ID,
		SenderID:       user.ID,
		SenderType:     senderTypeForRole(user.Role),
		Message:        messageText,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	messageResult, err := supportMessagesCollection().InsertOne(context.Background(), message)
	if err != nil {
		return nil, nil, err
	}
	message.ID = messageResult.InsertedID.(bson.ObjectID)

	_, _ = supportConversationsCollection().UpdateOne(context.Background(), bson.M{"_id": conversation.ID}, bson.M{"$set": bson.M{"last_message_at": now, "updated_at": now}})
	return conversation, message, nil
}

func GetUserSupportConversations(email string, page, limit int) ([]models.SupportConversation, int64, error) {
	user, err := findUserByEmail(email)
	if err != nil {
		return nil, 0, err
	}
	return listSupportConversations(bson.M{"user_id": user.ID}, page, limit)
}

func GetSupportConversationForUser(email, conversationID string) (*models.SupportConversation, error) {
	user, err := findUserByEmail(email)
	if err != nil {
		return nil, err
	}
	conversation, err := findSupportConversationByID(conversationID)
	if err != nil {
		return nil, err
	}
	if conversation.UserID != user.ID {
		return nil, ErrSupportForbidden
	}
	return conversation, nil
}

func GetSupportConversationMessagesForUser(email, conversationID string) ([]models.SupportMessage, error) {
	if _, err := GetSupportConversationForUser(email, conversationID); err != nil {
		return nil, err
	}
	return listSupportMessagesByConversationID(conversationID)
}

func SendSupportMessage(email, conversationID string, payload models.SupportMessageRequest) (*models.SupportMessage, error) {
	user, err := findUserByEmail(email)
	if err != nil {
		return nil, err
	}
	conversation, err := findSupportConversationByID(conversationID)
	if err != nil {
		return nil, err
	}
	if conversation.UserID != user.ID {
		return nil, ErrSupportForbidden
	}

	messageText, err := normalizeSupportMessage(payload.Message)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	message := &models.SupportMessage{
		ConversationID: conversation.ID,
		SenderID:       user.ID,
		SenderType:     senderTypeForRole(user.Role),
		Message:        messageText,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	result, err := supportMessagesCollection().InsertOne(context.Background(), message)
	if err != nil {
		return nil, err
	}
	message.ID = result.InsertedID.(bson.ObjectID)
	_, _ = supportConversationsCollection().UpdateOne(context.Background(), bson.M{"_id": conversation.ID}, bson.M{"$set": bson.M{"updated_at": now, "last_message_at": now}})
	return message, nil
}

func CloseSupportConversation(email, conversationID string) (*models.SupportConversation, error) {
	user, err := findUserByEmail(email)
	if err != nil {
		return nil, err
	}
	conversation, err := findSupportConversationByID(conversationID)
	if err != nil {
		return nil, err
	}
	if conversation.UserID != user.ID {
		return nil, ErrSupportForbidden
	}
	if conversation.Status == models.SupportStatusClosed {
		return conversation, nil
	}
	now := time.Now().UTC()
	conversation.Status = models.SupportStatusClosed
	conversation.UpdatedAt = now
	_, err = supportConversationsCollection().UpdateOne(context.Background(), bson.M{"_id": conversation.ID}, bson.M{"$set": bson.M{"status": conversation.Status, "updated_at": now}})
	if err != nil {
		return nil, err
	}
	return conversation, nil
}

func AdminListSupportConversations(currentUserEmail string, page, limit int, status, customer, assignedTo, search, date string) ([]models.SupportConversation, int64, error) {
	currentUser, err := findUserByEmail(currentUserEmail)
	if err != nil {
		return nil, 0, err
	}

	query := bson.M{}
	if status != "" {
		normalized, err := normalizeSupportStatus(status)
		if err != nil {
			return nil, 0, err
		}
		query["status"] = normalized
	}
	if customer != "" {
		customerID, err := userIDByEmailOrHex(customer)
		if err != nil {
			return nil, 0, err
		}
		query["user_id"] = customerID
	}
	if assignedTo != "" {
		assignedID, err := parseObjectID(assignedTo)
		if err != nil {
			return nil, 0, err
		}
		query["assigned_to"] = assignedID
	}
	if search != "" {
		query["$or"] = []bson.M{{"subject": bson.M{"$regex": search, "$options": "i"}}}
	}
	if date != "" {
		start, end, err := parseConversationDateRange(date)
		if err != nil {
			return nil, 0, err
		}
		query["created_at"] = bson.M{"$gte": start, "$lt": end}
	}

	if strings.EqualFold(currentUser.Role, "support") || strings.EqualFold(currentUser.Role, "support_agent") {
		if assignedTo == "" {
			query["assigned_to"] = currentUser.ID
		}
	}

	return listSupportConversations(query, page, limit)
}

func GetAdminSupportConversation(email, conversationID string) (*models.SupportConversation, []models.SupportMessage, error) {
	currentUser, err := findUserByEmail(email)
	if err != nil {
		return nil, nil, err
	}
	conversation, err := findSupportConversationByID(conversationID)
	if err != nil {
		return nil, nil, err
	}
	if !isAdminSupportedRole(currentUser.Role) {
		return nil, nil, ErrSupportForbidden
	}
	if strings.EqualFold(currentUser.Role, "support") || strings.EqualFold(currentUser.Role, "support_agent") {
		if conversation.AssignedTo == nil || *conversation.AssignedTo != currentUser.ID {
			return nil, nil, ErrSupportForbidden
		}
	}
	messages, err := listSupportMessagesByConversationID(conversationID)
	if err != nil {
		return nil, nil, err
	}
	return conversation, messages, nil
}

func SendAdminSupportReply(email, conversationID string, payload models.SupportMessageRequest) (*models.SupportMessage, error) {
	currentUser, err := findUserByEmail(email)
	if err != nil {
		return nil, err
	}
	if !isAdminSupportedRole(currentUser.Role) {
		return nil, ErrSupportForbidden
	}
	conversation, err := findSupportConversationByID(conversationID)
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(currentUser.Role, "support") || strings.EqualFold(currentUser.Role, "support_agent") {
		if conversation.AssignedTo == nil || *conversation.AssignedTo != currentUser.ID {
			return nil, ErrSupportForbidden
		}
	}

	messageText, err := normalizeSupportMessage(payload.Message)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	message := &models.SupportMessage{
		ConversationID: conversation.ID,
		SenderID:       currentUser.ID,
		SenderType:     senderTypeForRole(currentUser.Role),
		Message:        messageText,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	result, err := supportMessagesCollection().InsertOne(context.Background(), message)
	if err != nil {
		return nil, err
	}
	message.ID = result.InsertedID.(bson.ObjectID)

	if conversation.Status == models.SupportStatusOpen {
		conversation.Status = models.SupportStatusPending
	}
	conversation.UpdatedAt = now
	conversation.LastMessageAt = now
	_, _ = supportConversationsCollection().UpdateOne(context.Background(), bson.M{"_id": conversation.ID}, bson.M{"$set": bson.M{"status": conversation.Status, "updated_at": now, "last_message_at": now}})
	return message, nil
}

func UpdateSupportConversationByAdmin(email, conversationID string, payload models.SupportConversationUpdateRequest) (*models.SupportConversation, error) {
	currentUser, err := findUserByEmail(email)
	if err != nil {
		return nil, err
	}
	if !isAdminSupportedRole(currentUser.Role) {
		return nil, ErrSupportForbidden
	}
	conversation, err := findSupportConversationByID(conversationID)
	if err != nil {
		return nil, err
	}
	if strings.EqualFold(currentUser.Role, "support") || strings.EqualFold(currentUser.Role, "support_agent") {
		if conversation.AssignedTo == nil || *conversation.AssignedTo != currentUser.ID {
			return nil, ErrSupportForbidden
		}
	}

	updates := bson.M{"updated_at": time.Now().UTC()}
	if strings.TrimSpace(payload.Status) != "" {
		normalized, err := normalizeSupportStatus(payload.Status)
		if err != nil {
			return nil, err
		}
		updates["status"] = normalized
		conversation.Status = normalized
	}
	if strings.TrimSpace(payload.AssignedTo) != "" {
		assignedID, err := parseObjectID(payload.AssignedTo)
		if err != nil {
			return nil, errors.New("assignedTo must be a valid user id")
		}
		updates["assigned_to"] = assignedID
		conversation.AssignedTo = &assignedID
	}
	if len(updates) <= 1 {
		return conversation, nil
	}

	_, err = supportConversationsCollection().UpdateOne(context.Background(), bson.M{"_id": conversation.ID}, bson.M{"$set": updates})
	if err != nil {
		return nil, err
	}
	conversation.UpdatedAt = updates["updated_at"].(time.Time)
	return conversation, nil
}

func findUserByEmail(email string) (*models.User, error) {
	if db.MongoClient == nil {
		return nil, errors.New("database is not initialized")
	}
	collection := db.MongoClient.Database(db.DatabaseName).Collection("users")
	var user models.User
	if err := collection.FindOne(context.Background(), bson.M{"email": strings.TrimSpace(email)}).Decode(&user); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, errors.New("user not found")
		}
		return nil, err
	}
	return &user, nil
}

func findSupportConversationByID(conversationID string) (*models.SupportConversation, error) {
	id, err := parseObjectID(conversationID)
	if err != nil {
		return nil, ErrInvalidSupportConversationID
	}
	var conversation models.SupportConversation
	if err := supportConversationsCollection().FindOne(context.Background(), bson.M{"_id": id}).Decode(&conversation); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, ErrSupportConversationNotFound
		}
		return nil, err
	}
	return &conversation, nil
}

func listSupportConversations(query bson.M, page, limit int) ([]models.SupportConversation, int64, error) {
	if page <= 0 {
		page = 1
	}
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	collection := supportConversationsCollection()
	total, err := collection.CountDocuments(context.Background(), query)
	if err != nil {
		return nil, 0, err
	}

	findOpts := options.Find().SetSkip(int64((page - 1) * limit)).SetLimit(int64(limit)).SetSort(bson.D{{Key: "updated_at", Value: -1}})
	cursor, err := collection.Find(context.Background(), query, findOpts)
	if err != nil {
		return nil, 0, err
	}
	defer cursor.Close(context.Background())

	var conversations []models.SupportConversation
	if err := cursor.All(context.Background(), &conversations); err != nil {
		return nil, 0, err
	}
	return conversations, total, nil
}

func listSupportMessagesByConversationID(conversationID string) ([]models.SupportMessage, error) {
	id, err := parseObjectID(conversationID)
	if err != nil {
		return nil, ErrInvalidSupportConversationID
	}
	cursor, err := supportMessagesCollection().Find(context.Background(), bson.M{"conversation_id": id}, options.Find().SetSort(bson.D{{Key: "created_at", Value: 1}}))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(context.Background())

	var messages []models.SupportMessage
	if err := cursor.All(context.Background(), &messages); err != nil {
		return nil, err
	}
	return messages, nil
}

func normalizeSupportStatus(status string) (string, error) {
	normalized := models.NormalizeSupportStatus(status)
	if !models.IsValidSupportStatus(normalized) {
		return "", ErrInvalidSupportStatus
	}
	return normalized, nil
}

func parseObjectID(value string) (bson.ObjectID, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return bson.NilObjectID, ErrInvalidSupportConversationID
	}
	id, err := bson.ObjectIDFromHex(trimmed)
	if err != nil {
		return bson.NilObjectID, ErrInvalidSupportConversationID
	}
	return id, nil
}

func normalizeSupportMessage(payload string) (string, error) {
	trimmed := strings.TrimSpace(payload)
	if trimmed == "" {
		return "", errors.New("message is required")
	}
	if len(trimmed) > maxSupportMessageLength {
		return "", fmt.Errorf("message must be %d characters or fewer", maxSupportMessageLength)
	}
	return trimmed, nil
}

func senderTypeForRole(role string) string {
	s := strings.ToLower(strings.TrimSpace(role))
	if s == "admin" || s == "super_admin" || s == "support" || s == "support_agent" {
		return models.SupportSenderSupport
	}
	return models.SupportSenderUser
}

func isAdminSupportedRole(role string) bool {
	s := strings.ToLower(strings.TrimSpace(role))
	return s == "admin" || s == "super_admin" || s == "support" || s == "support_agent"
}

func userIDByEmailOrHex(value string) (bson.ObjectID, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return bson.NilObjectID, errors.New("customer is required")
	}
	if id, err := bson.ObjectIDFromHex(trimmed); err == nil {
		return id, nil
	}
	user, err := findUserByEmail(trimmed)
	if err != nil {
		return bson.NilObjectID, err
	}
	return user.ID, nil
}

func parseConversationDateRange(date string) (time.Time, time.Time, error) {
	trimmed := strings.TrimSpace(date)
	if trimmed == "" {
		return time.Time{}, time.Time{}, errors.New("date is required")
	}
	parsed, err := time.Parse(time.RFC3339, trimmed)
	if err != nil {
		return time.Time{}, time.Time{}, errors.New("invalid date format")
	}
	start := parsed.UTC()
	end := start.Add(24 * time.Hour)
	return start, end, nil
}

func supportConversationsCollection() *mongo.Collection {
	return db.MongoClient.Database(db.DatabaseName).Collection("support_conversations")
}

func supportMessagesCollection() *mongo.Collection {
	return db.MongoClient.Database(db.DatabaseName).Collection("support_messages")
}

func FormatSupportError(err error) string {
	if err == nil {
		return ""
	}
	switch {
	case errors.Is(err, ErrSupportUnauthorized):
		return "unauthorized"
	case errors.Is(err, ErrSupportForbidden):
		return "forbidden"
	case errors.Is(err, ErrSupportConversationNotFound):
		return "conversation not found"
	case errors.Is(err, ErrInvalidSupportConversationID):
		return "invalid conversation id"
	case errors.Is(err, ErrInvalidSupportStatus):
		return "invalid status"
	case strings.Contains(err.Error(), "message is required"):
		return "message is required"
	case strings.Contains(err.Error(), "must be"):
		return err.Error()
	case strings.Contains(err.Error(), "required"):
		return err.Error()
	case strings.Contains(err.Error(), "database"):
		return "database error"
	default:
		return "internal server error"
	}
}

func SupportQueryParamInt(value string, defaultValue int) int {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return defaultValue
	}
	parsed, err := strconv.Atoi(trimmed)
	if err != nil || parsed <= 0 {
		return defaultValue
	}
	return parsed
}
