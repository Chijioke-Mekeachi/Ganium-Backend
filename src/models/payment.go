package models

import "time"

// ============================================================
// PAYSTACK
// ============================================================

type PaystackInitializeRequest struct {
	Plan      string `json:"plan,omitempty" example:"pro"`
	Reference string `json:"reference,omitempty" example:"GANIUM-123456"`
	Callback  string `json:"callback_url,omitempty" example:"https://app.ganium.ai/payment/callback"`
	Mode      string `json:"mode,omitempty" example:"hosted"`
}

type PaystackInitializeResponse struct {
	Status           bool    `json:"status"`
	Message          string  `json:"message"`
	AuthorizationURL string  `json:"authorization_url,omitempty"`
	AccessCode       string  `json:"access_code,omitempty"`
	Reference        string  `json:"reference,omitempty"`
	CheckoutMode     string  `json:"checkout_mode,omitempty"`
	InlinePublicKey  string  `json:"inline_public_key,omitempty"`
	Amount           float64 `json:"amount,omitempty"`
	Currency         string  `json:"currency,omitempty"`
	TokensGranted    int     `json:"tokens_granted,omitempty"`
	Plan             string  `json:"plan,omitempty"`
}

type PaymentPlan struct {
	Code         string  `json:"code"`
	Name         string  `json:"name"`
	Amount       float64 `json:"amount"`
	Currency     string  `json:"currency"`
	Tokens       int     `json:"tokens"`
	Description  string  `json:"description"`
	CheckoutMode string  `json:"checkout_mode"`
}

type PaymentHistory struct {
	Reference        string     `json:"reference" bson:"reference"`
	Email            string     `json:"email" bson:"email"`
	Plan             string     `json:"plan" bson:"plan"`
	Amount           float64    `json:"amount" bson:"amount"`
	Currency         string     `json:"currency" bson:"currency"`
	TokensGranted    int        `json:"tokens_granted" bson:"tokens_granted"`
	Status           string     `json:"status" bson:"status"`
	Channel          string     `json:"channel,omitempty" bson:"channel,omitempty"`
	AuthorizationURL string     `json:"authorization_url,omitempty" bson:"authorization_url,omitempty"`
	AccessCode       string     `json:"access_code,omitempty" bson:"access_code,omitempty"`
	CreatedAt        time.Time  `json:"created_at" bson:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at" bson:"updated_at"`
	PaidAt           *time.Time `json:"paid_at,omitempty" bson:"paid_at,omitempty"`
	RawEvent         string     `json:"raw_event,omitempty" bson:"raw_event,omitempty"`

	// Prevents a Paystack transaction from being credited
	// more than once.
	Credited bool `json:"credited" bson:"credited"`
}

// ============================================================
// SOLANA / SJLY PAYMENT
// ============================================================

type CryptoPayment struct {
	// Internal Ganium payment ID.
	PaymentID string `json:"payment_id" bson:"payment_id"`

	// Authenticated Ganium user email.
	Email string `json:"email" bson:"email"`

	// Ganium payment plan.
	Plan string `json:"plan" bson:"plan"`

	// USD value of the selected plan.
	USDPrice float64 `json:"usd_price" bson:"usd_price"`

	// Amount of SJLY to be paid.
	//
	// Stored as a string because SPL token amounts
	// are integer base units.
	TokenAmount string `json:"token_amount" bson:"token_amount"`

	// Token symbol.
	TokenSymbol string `json:"token_symbol" bson:"token_symbol"`

	// SPL token mint address.
	TokenMint string `json:"token_mint" bson:"token_mint"`

	// Solana network.
	Network string `json:"network" bson:"network"`

	// GaniumAI receiving wallet.
	RecipientWallet string `json:"recipient_wallet" bson:"recipient_wallet"`

	// User's Solana wallet.
	UserWallet string `json:"user_wallet,omitempty" bson:"user_wallet,omitempty"`

	// Solana transaction signature.
	TransactionSignature string `json:"transaction_signature,omitempty" bson:"transaction_signature,omitempty"`

	// Payment status:
	//
	// pending
	// verifying
	// success
	// failed
	Status string `json:"status" bson:"status"`

	// Number of GaniumAI tokens to grant.
	TokensGranted int `json:"tokens_granted" bson:"tokens_granted"`

	// Prevents duplicate token crediting.
	Credited bool `json:"credited" bson:"credited"`

	CreatedAt time.Time `json:"created_at" bson:"created_at"`

	UpdatedAt time.Time `json:"updated_at" bson:"updated_at"`

	VerifiedAt *time.Time `json:"verified_at,omitempty" bson:"verified_at,omitempty"`
}

// ============================================================
// CREATE CRYPTO PAYMENT RESPONSE
// ============================================================

type CreateCryptoPaymentResponse struct {
	PaymentID string `json:"payment_id"`

	Plan string `json:"plan"`

	USDPrice float64 `json:"usd_price"`

	TokenSymbol string `json:"token_symbol"`

	TokenAmount string `json:"token_amount"`

	TokenMint string `json:"token_mint"`

	Network string `json:"network"`

	RecipientWallet string `json:"recipient_wallet"`

	TokensGranted int `json:"tokens_granted"`

	Status string `json:"status"`

	CreatedAt time.Time `json:"created_at"`
}