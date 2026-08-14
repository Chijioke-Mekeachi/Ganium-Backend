package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"ganium/src/db"
	"ganium/src/utils"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type oldUser struct {
	ID                 string  `json:"id"`
	Email              *string `json:"email"`
	Password           *string `json:"encrypted_password"`
	FullName           *string `json:"full_name"`
	AvatarURL          *string `json:"avatar_url"`
	SubscriptionPlanID *string `json:"subscription_plan_id"`
	TokensRemaining    int     `json:"tokens_remaining"`
	TokensUsedTotal    int     `json:"tokens_used_total"`
	SubscriptionStatus *string `json:"subscription_status"`
	CurrentPeriodEnd   *string `json:"current_period_end"`
	LastScanAt         *string `json:"last_scan_at"`
	CreatedAt          *string `json:"created_at"`
	UpdatedAt          *string `json:"updated_at"`
	IsVerified         *bool   `json:"is_verified"`
}

type oldAuth struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Password  string `json:"encrypted_password"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type oldScan struct {
	ID              string `json:"id"`
	UserID          string `json:"user_id"`
	Content         string `json:"content"`
	ContentType     string `json:"content_type"`
	RiskScore       string `json:"risk_score"`
	Classification  string `json:"classification"`
	Explanation     string `json:"explanation"`
	Recommendations string `json:"recommendations"`
	TokensUsed      int    `json:"tokens_used"`
	CreatedAt       string `json:"created_at"`
}

func main() {
	if err := utils.LoadDotEnv(".env"); err != nil {
		fmt.Println("warning: .env not loaded:", err)
	}
	if err := db.ConnectMongoDB(); err != nil {
		panic(err)
	}

	ctx := context.Background()
	usersCol := db.MongoClient.Database(db.DatabaseName).Collection("users")
	scansCol := db.MongoClient.Database(db.DatabaseName).Collection("scan_records")

	importProfiles(ctx, usersCol, readOldUsers("src/sql/profiles_rows.json"))
	importAuth(ctx, usersCol, readOldAuth("src/sql/auth.json"))
	importScans(ctx, scansCol, readOldScans("src/sql/scans_history_rows.json"))
	importScans(ctx, scansCol, readOldScans("src/sql/qr_scans_rows.json"))
	fmt.Println("migration finished")
}

func readOldUsers(path string) []oldUser {
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var rows []oldUser
	if err := json.Unmarshal(data, &rows); err != nil {
		panic(err)
	}
	return rows
}

func readOldAuth(path string) []oldAuth {
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var rows []oldAuth
	if err := json.Unmarshal(data, &rows); err != nil {
		panic(err)
	}
	return rows
}

func readOldScans(path string) []oldScan {
	data, err := os.ReadFile(path)
	if err != nil {
		panic(err)
	}
	var rows []oldScan
	if err := json.Unmarshal(data, &rows); err != nil {
		panic(err)
	}
	return rows
}

func importProfiles(ctx context.Context, col *mongo.Collection, rows []oldUser) {
	for _, row := range rows {
		if row.Email == nil || *row.Email == "" {
			continue
		}
		doc := bson.M{
			"email":               *row.Email,
			"tokens_remaining":     row.TokensRemaining,
			"tokens_used_total":    row.TokensUsedTotal,
			"subscription_status":  derefString(row.SubscriptionStatus, "inactive"),
			"subscription_plan_id": row.SubscriptionPlanID,
			"created_at":           parseTimePtr(row.CreatedAt),
			"updated_at":           parseTimePtr(row.UpdatedAt),
			"last_scan_at":         parseTimePtr(row.LastScanAt),
		}
		if row.FullName != nil {
			doc["full_name"] = *row.FullName
		}
		if row.AvatarURL != nil {
			doc["avatar_url"] = *row.AvatarURL
		}
		if row.CurrentPeriodEnd != nil {
			doc["current_period_end"] = parseTimePtr(row.CurrentPeriodEnd)
		}
		if row.IsVerified != nil {
			doc["isVerified"] = *row.IsVerified
		}
		_, _ = col.UpdateOne(ctx, bson.M{"email": *row.Email}, bson.M{"$set": doc}, options.UpdateOne().SetUpsert(true))
	}
}

func importAuth(ctx context.Context, col *mongo.Collection, rows []oldAuth) {
	for _, row := range rows {
		if row.Email == "" {
			continue
		}
		doc := bson.M{
			"email":      row.Email,
			"password":   row.Password,
			"isVerified": true,
			"created_at": parseTimeString(row.CreatedAt),
			"updated_at": parseTimeString(row.UpdatedAt),
		}
		_, _ = col.UpdateOne(ctx, bson.M{"email": row.Email}, bson.M{"$set": doc}, options.UpdateOne().SetUpsert(true))
	}
}

func importScans(ctx context.Context, col *mongo.Collection, rows []oldScan) {
	for _, row := range rows {
		if row.Content == "" {
			continue
		}
		doc := bson.M{
			"user_id":         row.UserID,
			"content":         row.Content,
			"content_type":     row.ContentType,
			"risk_score":      row.RiskScore,
			"classification":   row.Classification,
			"explanation":     row.Explanation,
			"recommendations": row.Recommendations,
			"tokens_used":     row.TokensUsed,
			"created_at":      parseTimeString(row.CreatedAt),
		}
		if row.ID != "" {
			if oid, err := primitive.ObjectIDFromHex(row.ID); err == nil {
				doc["_id"] = oid
			}
		}
		filter := bson.M{"user_id": row.UserID, "content": row.Content, "created_at": doc["created_at"]}
		_, _ = col.UpdateOne(ctx, filter, bson.M{"$setOnInsert": doc}, options.UpdateOne().SetUpsert(true))
	}
}

func parseTimeString(value string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, value)
	if err != nil {
		t, err = time.Parse("2006-01-02 15:04:05.999999999-07", value)
		if err != nil {
			return time.Time{}
		}
	}
	return t.UTC()
}

func parseTimePtr(value *string) *time.Time {
	if value == nil || *value == "" {
		return nil
	}
	t := parseTimeString(*value)
	if t.IsZero() {
		return nil
	}
	return &t
}

func derefString(value *string, fallback string) string {
	if value == nil || *value == "" {
		return fallback
	}
	return *value
}
