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
)

func GetCurrentUserProfile(email string) (*models.UserProfileResponse, error) {
	doc, err := fetchUserDocument(email)
	if err != nil {
		return nil, err
	}

	return buildUserProfileResponse(doc), nil
}

func UpdateCurrentUserProfile(
	email string,
	payload models.UserProfileUpdateRequest,
) (*models.UserProfileResponse, error) {
	updates := bson.M{}

	if fullName := strings.TrimSpace(payload.FullName); fullName != "" {
		updates["full_name"] = fullName
	}

	if avatarURL := strings.TrimSpace(payload.AvatarURL); avatarURL != "" {
		updates["avatar_url"] = avatarURL
	}

	if len(updates) == 0 {
		return GetCurrentUserProfile(email)
	}

	now := time.Now().UTC()
	updates["updated_at"] = now

	collection := db.MongoClient.
		Database(db.DatabaseName).
		Collection("users")

	result, err := collection.UpdateOne(
		context.Background(),
		bson.M{
			"email": strings.TrimSpace(email),
		},
		bson.M{
			"$set": updates,
		},
	)

	if err != nil {
		return nil, err
	}

	if result.MatchedCount == 0 {
		return nil, fmt.Errorf("user not found")
	}

	// Redis cache invalidation removed

	return GetCurrentUserProfile(email)
}

func DeleteCurrentUser(email string) error {
	ctx := context.Background()
	database := db.MongoClient.Database(db.DatabaseName)

	email = strings.TrimSpace(email)

	if email == "" {
		return fmt.Errorf("email is required")
	}

	if _, err := database.
		Collection("scan_records").
		DeleteMany(
			ctx,
			bson.M{
				"user_id": email,
			},
		); err != nil {
		return err
	}

	if _, err := database.
		Collection("payment_history").
		DeleteMany(
			ctx,
			bson.M{
				"email": email,
			},
		); err != nil {
		return err
	}

	if _, err := database.
		Collection("crypto_payments").
		DeleteMany(
			ctx,
			bson.M{
				"email": email,
			},
		); err != nil {
		return err
	}

	result, err := database.
		Collection("users").
		DeleteOne(
			ctx,
			bson.M{
				"email": email,
			},
		)

	if err != nil {
		return err
	}

	if result.DeletedCount == 0 {
		return fmt.Errorf("user not found")
	}

	_ = LogAdminEvent(
		"user_deleted",
		"User deleted",
		fmt.Sprintf("User account %s was deleted.", email),
		email,
	)

	// Redis cache invalidation removed

	return nil
}

// ============================================================
// WALLET SUMMARY
// ============================================================

func GetWalletSummary(
	email string,
) (*models.WalletSummary, error) {
	profile, err := GetCurrentUserProfile(email)
	if err != nil {
		return nil, err
	}

	walletBalance := profile.WalletBalance

	if walletBalance == 0 && profile.TokensRemaining > 0 {
		walletBalance = float64(profile.TokensRemaining) / 10.0
	}

	now := time.Now().UTC()

	summary := &models.WalletSummary{
		Email:           profile.Email,
		TokensRemaining: profile.TokensRemaining,
		TokensUsedTotal: profile.TokensUsedTotal,
		WalletBalance:   walletBalance,
		TokenRatePerUSD: 10,
		TokenValueUSD:   0.10,
		UpdatedAt:       &now,
	}

	if profile.UpdatedAt != nil {
		summary.UpdatedAt = profile.UpdatedAt
	}

	return summary, nil
}

// ============================================================
// BALANCE SUMMARY
// ============================================================

func GetBalanceSummary(
	email string,
) (*models.BalanceSummary, error) {
	wallet, err := GetWalletSummary(email)
	if err != nil {
		return nil, err
	}

	return &models.BalanceSummary{
		Wallet: *wallet,
		Plans:  GetPaymentPlans(),
	}, nil
}

// ============================================================
// FETCH USER
// ============================================================

func fetchUserDocument(
	email string,
) (bson.M, error) {
	email = strings.TrimSpace(email)

	if email == "" {
		return nil, fmt.Errorf("email is required")
	}
	collection := db.MongoClient.
		Database(db.DatabaseName).
		Collection("users")

	var doc bson.M

	err := collection.
		FindOne(
			context.Background(),
			bson.M{
				"email": email,
			},
		).
		Decode(&doc)

	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, fmt.Errorf("user not found")
		}

		return nil, err
	}

	return doc, nil
}

// ============================================================
// BUILD USER PROFILE RESPONSE
// ============================================================

func buildUserProfileResponse(
	doc bson.M,
) *models.UserProfileResponse {
	response := &models.UserProfileResponse{}

	response.Email = stringField(doc["email"])
	response.FullName = stringField(doc["full_name"])
	response.AvatarURL = stringField(doc["avatar_url"])

	response.SubscriptionPlanID =
		stringPointerField(doc["subscription_plan_id"])

	response.TokensRemaining =
		intField(doc["tokens_remaining"])

	response.TokensUsedTotal =
		intField(doc["tokens_used_total"])

	response.SubscriptionStatus =
		stringField(doc["subscription_status"])

	response.CurrentPeriodEnd =
		timeField(doc["current_period_end"])

	response.LastScanAt =
		timeField(doc["last_scan_at"])

	response.WalletBalance =
		floatField(doc["wallet_balance"])

	response.IsVerified =
		boolField(doc["isVerified"])

	response.CreatedAt =
		timeField(doc["created_at"])

	response.UpdatedAt =
		timeField(doc["updated_at"])

	return response
}

// ============================================================
// STRING FIELD
// ============================================================

func stringField(value any) string {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)

	case []byte:
		return strings.TrimSpace(string(v))

	default:
		return ""
	}
}

// ============================================================
// STRING POINTER FIELD
// ============================================================

func stringPointerField(
	value any,
) *string {
	if s := stringField(value); s != "" {
		return &s
	}

	return nil
}

// ============================================================
// BOOL FIELD
// ============================================================

func boolField(value any) bool {
	switch v := value.(type) {
	case bool:
		return v

	case int32:
		return v != 0

	case int64:
		return v != 0

	case int:
		return v != 0

	case float64:
		return v != 0

	case float32:
		return v != 0

	default:
		return false
	}
}

// ============================================================
// INT FIELD
// ============================================================

func intField(value any) int {
	switch v := value.(type) {
	case int:
		return v

	case int32:
		return int(v)

	case int64:
		return int(v)

	case float64:
		return int(v)

	case float32:
		return int(v)

	case primitive.Decimal128:
		bigInt, exponent, err := v.BigInt()
		if err != nil || bigInt == nil {
			return 0
		}

		if exponent > 0 {
			for i := 0; i < exponent; i++ {
				bigInt.Mul(
					bigInt,
					bigInt.SetInt64(10),
				)
			}
		}

		return int(bigInt.Int64())

	default:
		return 0
	}
}

// ============================================================
// FLOAT FIELD
// ============================================================

func floatField(value any) float64 {
	switch v := value.(type) {
	case float64:
		return v

	case float32:
		return float64(v)

	case int:
		return float64(v)

	case int32:
		return float64(v)

	case int64:
		return float64(v)

	case primitive.Decimal128:
		bigInt, exponent, err := v.BigInt()

		if err != nil || bigInt == nil {
			return 0
		}

		value := float64(bigInt.Int64())

		switch {
		case exponent > 0:
			for i := 0; i < exponent; i++ {
				value *= 10
			}

		case exponent < 0:
			for i := 0; i > exponent; i-- {
				value /= 10
			}
		}

		return value

	default:
		return 0
	}
}

// ============================================================
// TIME FIELD
// ============================================================

func timeField(
	value any,
) *time.Time {
	switch v := value.(type) {
	case time.Time:
		t := v.UTC()
		return &t

	case *time.Time:
		if v == nil {
			return nil
		}

		t := v.UTC()
		return &t

	case primitive.DateTime:
		t := v.Time().UTC()
		return &t

	case int64:
		if v == 0 {
			return nil
		}

		t := time.UnixMilli(v).UTC()
		return &t

	case int:
		if v == 0 {
			return nil
		}

		t := time.Unix(
			int64(v),
			0,
		).UTC()

		return &t

	case float64:
		if v == 0 {
			return nil
		}

		t := time.UnixMilli(
			int64(v),
		).UTC()

		return &t

	case string:
		t, err := parseTimeString(v)

		if err != nil {
			return nil
		}

		return &t

	default:
		return nil
	}
}

// ============================================================
// PARSE TIME STRING
// ============================================================

func parseTimeString(
	value string,
) (time.Time, error) {
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02 15:04:05.999999999-07",
		"2006-01-02 15:04:05-07",
		"2006-01-02 15:04:05.999999999",
		"2006-01-02 15:04:05",
	}

	trimmed := strings.TrimSpace(value)

	for _, layout := range layouts {
		if t, err := time.Parse(
			layout,
			trimmed,
		); err == nil {
			return t.UTC(), nil
		}
	}

	return time.Time{},
		fmt.Errorf(
			"unsupported time value: %s",
			value,
		)
}
