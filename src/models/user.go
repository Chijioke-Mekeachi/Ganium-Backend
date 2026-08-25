package models

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"ganium/internal/config"
	"ganium/src/db"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type User struct {
	ID                 bson.ObjectID `json:"id" bson:"_id,omitempty"`
	Email              string        `json:"email" bson:"email"`
	Password           string        `json:"password" bson:"password"`
	FullName           string        `json:"full_name,omitempty" bson:"full_name,omitempty"`
	AvatarURL          string        `json:"avatar_url,omitempty" bson:"avatar_url,omitempty"`
	SubscriptionPlanID *string       `json:"subscription_plan_id,omitempty" bson:"subscription_plan_id,omitempty"`

	TokensRemaining    int    `json:"tokens_remaining" bson:"tokens_remaining"`
	TokensUsedTotal    int    `json:"tokens_used_total" bson:"tokens_used_total"`
	SubscriptionStatus string `json:"subscription_status" bson:"subscription_status"`

	CurrentPeriodEnd *time.Time `json:"current_period_end,omitempty" bson:"current_period_end,omitempty"`
	LastScanAt       *time.Time `json:"last_scan_at,omitempty" bson:"last_scan_at,omitempty"`

	WalletBalance float64 `json:"wallet_balance" bson:"wallet_balance"`

	// ============================================================
	// SOLANA WALLET
	// ============================================================

	SolanaWalletAddress     string     `json:"solana_wallet_address,omitempty" bson:"solana_wallet_address,omitempty"`
	SolanaNetwork           string     `json:"solana_network,omitempty" bson:"solana_network,omitempty"`
	SolanaWalletConnected   bool       `json:"solana_wallet_connected" bson:"solana_wallet_connected"`
	SolanaWalletConnectedAt *time.Time `json:"solana_wallet_connected_at,omitempty" bson:"solana_wallet_connected_at,omitempty"`

	CreatedAt time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt time.Time `json:"updated_at" bson:"updated_at"`

	IsVerified bool `json:"isVerified" bson:"isVerified"`

	OTPHash          string `json:"otpHash,omitempty" bson:"otpHash,omitempty"`
	OTPExpiry        int64  `json:"otpExpiry,omitempty" bson:"otpExpiry,omitempty"`
	ResetTokenHash   string `json:"resetTokenHash,omitempty" bson:"resetTokenHash,omitempty"`
	ResetTokenExpiry int64  `json:"resetTokenExpiry,omitempty" bson:"resetTokenExpiry,omitempty"`
}

type UserProfile struct {
	ID                 string  `json:"id"`
	Email              string  `json:"email"`
	FullName           string  `json:"full_name,omitempty"`
	AvatarURL          string  `json:"avatar_url,omitempty"`
	SubscriptionPlanID *string `json:"subscription_plan_id,omitempty"`
	TokensRemaining    int     `json:"tokens_remaining"`
	TokensUsedTotal    int     `json:"tokens_used_total"`
	SubscriptionStatus string  `json:"subscription_status"`

	CurrentPeriodEnd *time.Time `json:"current_period_end,omitempty"`
	LastScanAt       *time.Time `json:"last_scan_at,omitempty"`

	WalletBalance float64 `json:"wallet_balance"`

	// Solana
	SolanaWalletAddress     string     `json:"solana_wallet_address,omitempty"`
	SolanaNetwork           string     `json:"solana_network,omitempty"`
	SolanaWalletConnected   bool       `json:"solana_wallet_connected"`
	SolanaWalletConnectedAt *time.Time `json:"solana_wallet_connected_at,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type UserProfileUpdateRequest struct {
	FullName  string `json:"full_name,omitempty" example:"Jane Doe"`
	AvatarURL string `json:"avatar_url,omitempty" example:"https://cdn.example.com/avatar.png"`
}

type UserProfileResponse struct {
	Email              string  `json:"email"`
	FullName           string  `json:"full_name,omitempty"`
	AvatarURL          string  `json:"avatar_url,omitempty"`
	SubscriptionPlanID *string `json:"subscription_plan_id,omitempty"`
	TokensRemaining    int     `json:"tokens_remaining"`
	TokensUsedTotal    int     `json:"tokens_used_total"`
	SubscriptionStatus string  `json:"subscription_status"`

	CurrentPeriodEnd *time.Time `json:"current_period_end,omitempty"`
	LastScanAt       *time.Time `json:"last_scan_at,omitempty"`

	WalletBalance float64 `json:"wallet_balance"`

	IsVerified bool `json:"isVerified"`

	// Solana
	SolanaWalletAddress     string     `json:"solana_wallet_address,omitempty"`
	SolanaNetwork           string     `json:"solana_network,omitempty"`
	SolanaWalletConnected   bool       `json:"solana_wallet_connected"`
	SolanaWalletConnectedAt *time.Time `json:"solana_wallet_connected_at,omitempty"`

	CreatedAt *time.Time `json:"created_at,omitempty"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

type WalletSummary struct {
	Email           string `json:"email"`
	TokensRemaining int    `json:"tokens_remaining"`
	TokensUsedTotal int    `json:"tokens_used_total"`

	WalletBalance float64 `json:"wallet_balance"`

	TokenRatePerUSD int     `json:"token_rate_per_usd" example:"10"`
	TokenValueUSD   float64 `json:"token_value_usd" example:"0.10"`

	// Solana
	SolanaWalletAddress     string     `json:"solana_wallet_address,omitempty"`
	SolanaNetwork           string     `json:"solana_network,omitempty"`
	SolanaWalletConnected   bool       `json:"solana_wallet_connected"`
	SolanaWalletConnectedAt *time.Time `json:"solana_wallet_connected_at,omitempty"`

	UpdatedAt *time.Time `json:"updated_at,omitempty"`
}

type BalanceSummary struct {
	Wallet WalletSummary `json:"wallet"`
	Plans  []PaymentPlan `json:"plans"`
}

func GetUserByID(ctx context.Context, id string) (bson.M, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("email is required")
	}

	key := userCacheKey(id)
	if db.RedisClient != nil {
		cached, cacheErr := db.RedisClient.Get(ctx, key).Bytes()
		if cacheErr == nil {
			var doc bson.M
			if err := json.Unmarshal(cached, &doc); err == nil {
				return doc, nil
			}
		}
	}

	var doc bson.M
	err := db.MongoClient.
		Database(db.DatabaseName).
		Collection("users").
		FindOne(
			ctx,
			bson.M{"email": id},
			options.FindOne().SetProjection(bson.M{
				"password":         0,
				"otpHash":          0,
				"otpExpiry":        0,
				"resetTokenHash":   0,
				"resetTokenExpiry": 0,
			}),
		).
		Decode(&doc)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}

	if db.RedisClient != nil {
		if encoded, marshalErr := json.Marshal(doc); marshalErr == nil {
			cfg := config.LoadFromEnv()
			_ = db.RedisClient.Set(ctx, key, encoded, jitterTTL(cfg.UserCacheTTL)).Err()
		}
	}

	return doc, nil
}

func InvalidateUserCache(ctx context.Context, id string) error {
	if db.RedisClient == nil {
		return nil
	}
	return db.RedisClient.Del(ctx, userCacheKey(id)).Err()
}

func userCacheKey(id string) string {
	return "user:" + strings.TrimSpace(id)
}
