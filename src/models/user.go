package models

import (
	"time"

	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID                 primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	Email              string             `json:"email" bson:"email"`
	Password           string             `json:"password" bson:"password"`
	FullName           string             `json:"full_name,omitempty" bson:"full_name,omitempty"`
	AvatarURL          string             `json:"avatar_url,omitempty" bson:"avatar_url,omitempty"`
	SubscriptionPlanID *string            `json:"subscription_plan_id,omitempty" bson:"subscription_plan_id,omitempty"`
	TokensRemaining    int                `json:"tokens_remaining" bson:"tokens_remaining"`
	TokensUsedTotal    int                `json:"tokens_used_total" bson:"tokens_used_total"`
	SubscriptionStatus string             `json:"subscription_status" bson:"subscription_status"`
	CurrentPeriodEnd   *time.Time         `json:"current_period_end,omitempty" bson:"current_period_end,omitempty"`
	LastScanAt         *time.Time         `json:"last_scan_at,omitempty" bson:"last_scan_at,omitempty"`
	WalletBalance      float64            `json:"wallet_balance" bson:"wallet_balance"`
	CreatedAt          time.Time          `json:"created_at" bson:"created_at"`
	UpdatedAt          time.Time          `json:"updated_at" bson:"updated_at"`
	IsVerified         bool               `json:"isVerified" bson:"isVerified"`
	OTPHash            string             `json:"otpHash,omitempty" bson:"otpHash,omitempty"`
	OTPExpiry          int64              `json:"otpExpiry,omitempty" bson:"otpExpiry,omitempty"`
	ResetTokenHash     string             `json:"resetTokenHash,omitempty" bson:"resetTokenHash,omitempty"`
	ResetTokenExpiry   int64              `json:"resetTokenExpiry,omitempty" bson:"resetTokenExpiry,omitempty"`
}

type UserProfile struct {
	ID                 string     `json:"id"`
	Email              string     `json:"email"`
	FullName           string     `json:"full_name,omitempty"`
	AvatarURL          string     `json:"avatar_url,omitempty"`
	SubscriptionPlanID *string    `json:"subscription_plan_id,omitempty"`
	TokensRemaining    int        `json:"tokens_remaining"`
	TokensUsedTotal    int        `json:"tokens_used_total"`
	SubscriptionStatus string     `json:"subscription_status"`
	CurrentPeriodEnd   *time.Time `json:"current_period_end,omitempty"`
	LastScanAt         *time.Time `json:"last_scan_at,omitempty"`
	WalletBalance      float64    `json:"wallet_balance"`
	CreatedAt          time.Time  `json:"created_at"`
	UpdatedAt          time.Time  `json:"updated_at"`
}
