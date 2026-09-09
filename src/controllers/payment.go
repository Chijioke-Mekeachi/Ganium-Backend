package controllers

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"ganium/src/db"
	"ganium/src/models"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// ============================================================
// PAYMENT PLANS
// ============================================================

var paymentPlans = map[string]models.PaymentPlan{
	"basic": {
		Code:         "basic",
		Name:         "Basic",
		Amount:       1.00,
		Currency:     "USD",
		Tokens:       10,
		Description:  "$1 for 10 tokens",
		CheckoutMode: "hosted",
	},
	"starter": {
		Code:         "starter",
		Name:         "Starter",
		Amount:       10.00,
		Currency:     "USD",
		Tokens:       100,
		Description:  "$10 for 100 tokens",
		CheckoutMode: "hosted",
	},
	"pro": {
		Code:         "pro",
		Name:         "Pro",
		Amount:       100.00,
		Currency:     "USD",
		Tokens:       1000,
		Description:  "$100 for 1000 tokens",
		CheckoutMode: "hosted",
	},
}

const defaultExchangeRateAPI = "https://open.er-api.com/v6/latest/USD"
const exchangeRateCacheTTL = 15 * time.Minute

var (
	exchangeRateMu      sync.RWMutex
	cachedUSDToNGN      float64
	exchangeRateUpdated time.Time
)

type exchangeRateResponse struct {
	Result string             `json:"result"`
	Rates  map[string]float64 `json:"rates"`
}

// ============================================================
// EXCHANGE RATE
// ============================================================

func ExchangeRateAPIURL() string {
	apiURL := strings.TrimSpace(os.Getenv("EXCHANGE_RATE_API_URL"))

	if apiURL == "" {
		return defaultExchangeRateAPI
	}

	return apiURL
}

func GetUSDToNGNRate() (float64, error) {
	exchangeRateMu.RLock()

	if cachedUSDToNGN > 0 &&
		time.Since(exchangeRateUpdated) < exchangeRateCacheTTL {

		rate := cachedUSDToNGN
		exchangeRateMu.RUnlock()

		return rate, nil
	}

	exchangeRateMu.RUnlock()

	req, err := http.NewRequest(
		http.MethodGet,
		ExchangeRateAPIURL(),
		nil,
	)

	if err != nil {
		return 0, fmt.Errorf(
			"failed to create exchange-rate request: %w",
			err,
		)
	}

	req.Header.Set("Accept", "application/json")

	res, err := (&http.Client{
		Timeout: 10 * time.Second,
	}).Do(req)

	if err != nil {
		return 0, fmt.Errorf(
			"failed to reach exchange-rate API: %w",
			err,
		)
	}

	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return 0, fmt.Errorf(
			"exchange-rate API returned status %d",
			res.StatusCode,
		)
	}

	var data exchangeRateResponse

	if err := json.NewDecoder(res.Body).Decode(&data); err != nil {
		return 0, fmt.Errorf(
			"failed to parse exchange-rate response: %w",
			err,
		)
	}

	rate, ok := data.Rates["NGN"]

	if !ok || rate <= 0 {
		return 0, fmt.Errorf("NGN rate not found")
	}

	exchangeRateMu.Lock()

	cachedUSDToNGN = rate
	exchangeRateUpdated = time.Now()

	exchangeRateMu.Unlock()

	return rate, nil
}

func USDToNGN(usd float64) (float64, error) {
	rate, err := GetUSDToNGNRate()

	if err != nil {
		return 0, err
	}

	return math.Round(usd*rate*100) / 100, nil
}

// ============================================================
// PAYSTACK RESPONSE MODELS
// ============================================================

type paystackInitResponse struct {
	Status  bool   `json:"status"`
	Message string `json:"message"`

	Data struct {
		AuthorizationURL string `json:"authorization_url"`
		AccessCode       string `json:"access_code"`
		Reference        string `json:"reference"`
	} `json:"data"`
}

type paystackVerifyResponse struct {
	Status  bool   `json:"status"`
	Message string `json:"message"`

	Data struct {
		Status    string `json:"status"`
		Reference string `json:"reference"`
		Currency  string `json:"currency"`
		Channel   string `json:"channel"`
		PaidAt    string `json:"paid_at"`

		Customer struct {
			Email string `json:"email"`
		} `json:"customer"`

		Metadata map[string]any `json:"metadata"`
	} `json:"data"`
}

// ============================================================
// ENVIRONMENT HELPERS
// ============================================================

func PaystackSecret() string {
	return os.Getenv("PAYSTACK_SECRET_KEY")
}

func AppDeepLinkURL() string {
	return strings.TrimSpace(
		os.Getenv("APP_DEEP_LINK_URL"),
	)
}

// func SolanaRPCURL() string {
// 	rpc := strings.TrimSpace(
// 		os.Getenv("SOLANA_RPC_URL"),
// 	)

// 	if rpc == "" {
// 		return "https://api.mainnet-beta.solana.com"
// 	}

// 	return rpc
// }

// func SJLYMintAddress() string {
// 	return strings.TrimSpace(
// 		os.Getenv("SJLY_MINT_ADDRESS"),
// 	)
// }

func GaniumSolanaWallet() string {
	return strings.TrimSpace(
		os.Getenv("GANIUM_SOLANA_WALLET"),
	)
}

// ============================================================
// APP PAYMENT REDIRECT
// ============================================================

func BuildAppPaymentRedirect(
	reference,
	status string,
) string {

	base := AppDeepLinkURL()

	if base == "" {
		base = "ganium://payment/result"
	}

	u, err := url.Parse(base)

	if err != nil {
		return base
	}

	q := u.Query()

	if reference != "" {
		q.Set("reference", reference)
	}

	if status != "" {
		q.Set("status", status)
	}

	u.RawQuery = q.Encode()

	return u.String()
}

// ============================================================
// PAYMENT PLAN HELPERS
// ============================================================

func GetPaymentPlans() []models.PaymentPlan {
	plans := make(
		[]models.PaymentPlan,
		0,
		len(paymentPlans),
	)

	for _, plan := range paymentPlans {
		plans = append(plans, plan)
	}

	return plans
}

func ResolvePaymentPlan(
	code string,
) (models.PaymentPlan, bool) {

	plan, ok := paymentPlans[strings.ToLower(
		strings.TrimSpace(code),
	)]

	return plan, ok
}

func NormalizePaymentPlanInput(
	values ...string,
) string {

	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}

	return ""
}

// ============================================================
// PAYSTACK INITIALIZE
// ============================================================

func InitializePaymentForPlan(
	email,
	planCode,
	reference,
	callbackURL,
	mode string,
) (*models.PaystackInitializeResponse, string, error) {

	email = strings.TrimSpace(email)
	planCode = strings.TrimSpace(planCode)

	plan, ok := ResolvePaymentPlan(planCode)

	if !ok {
		return nil,
			"invalid plan selected",
			fmt.Errorf("unknown plan %q", planCode)
	}

	ngnAmount, err := USDToNGN(plan.Amount)

	if err != nil {
		return nil,
			"failed to convert USD price to NGN",
			err
	}

	if PaystackSecret() == "" {
		return nil,
			"paystack secret key not configured",
			fmt.Errorf("missing PAYSTACK_SECRET_KEY")
	}

	if email == "" {
		return nil,
			"authenticated email is required",
			fmt.Errorf("missing email")
	}

	if mode == "" {
		mode = "hosted"
	}

	mode = strings.ToLower(
		strings.TrimSpace(mode),
	)

	if mode != "hosted" &&
		mode != "inline" {

		mode = "hosted"
	}

	if callbackURL == "" {
		callbackURL = strings.TrimSpace(
			os.Getenv("PAYSTACK_CALLBACK_URL"),
		)
	}

	payload := map[string]any{
		"email":     email,
		"amount":    int64(math.Round(ngnAmount * 100)),
		"currency":  "NGN",
		"reference": reference,

		"metadata": map[string]any{
			"plan":           plan.Code,
			"tokens_granted": plan.Tokens,
			"checkout_mode":  mode,
			"email":          email,
		},
	}

	if payload["reference"] == "" {
		payload["reference"] = fmt.Sprintf(
			"ganium_%d",
			time.Now().UnixNano(),
		)
	}

	if callbackURL != "" {
		payload["callback_url"] = callbackURL
	}

	bodyBytes, err := json.Marshal(payload)

	if err != nil {
		return nil,
			"failed to encode paystack request",
			err
	}

	req, err := http.NewRequest(
		http.MethodPost,
		"https://api.paystack.co/transaction/initialize",
		bytes.NewReader(bodyBytes),
	)

	if err != nil {
		return nil,
			"failed to create paystack request",
			err
	}

	req.Header.Set(
		"Authorization",
		"Bearer "+PaystackSecret(),
	)

	req.Header.Set(
		"Content-Type",
		"application/json",
	)

	req.Header.Set(
		"Accept",
		"application/json",
	)

	client := &http.Client{
		Timeout: 20 * time.Second,
	}

	res, err := client.Do(req)

	if err != nil {
		return nil,
			"failed to reach paystack",
			err
	}

	defer res.Body.Close()

	var provider paystackInitResponse

	if err := json.NewDecoder(
		res.Body,
	).Decode(&provider); err != nil {

		return nil,
			"failed to parse paystack response",
			err
	}

	if !provider.Status {
		return nil,
			provider.Message,
			fmt.Errorf(
				"paystack rejected request: %s",
				provider.Message,
			)
	}

	now := time.Now().UTC()

	_, err = db.MongoClient.
		Database(db.DatabaseName).
		Collection("payment_history").
		UpdateOne(
			context.Background(),

			bson.M{
				"reference": provider.Data.Reference,
			},

			bson.M{
				"$set": bson.M{
					"reference":         provider.Data.Reference,
					"email":             email,
					"plan":              plan.Code,
					"amount":            ngnAmount,
					"currency":          "NGN",
					"tokens_granted":    plan.Tokens,
					"status":            "initialized",
					"channel":           mode,
					"authorization_url": provider.Data.AuthorizationURL,
					"access_code":       provider.Data.AccessCode,
					"created_at":        now,
					"updated_at":        now,
					"credited":          false,
				},
			},

			options.UpdateOne().SetUpsert(true),
		)

	if err != nil {
		return nil,
			"failed to save payment history",
			fmt.Errorf(
				"failed to save initialized payment: %w",
				err,
			)
	}

	out := &models.PaystackInitializeResponse{
		Status:           true,
		Message:          provider.Message,
		AuthorizationURL: provider.Data.AuthorizationURL,
		AccessCode:       provider.Data.AccessCode,
		Reference:        provider.Data.Reference,
		CheckoutMode:     mode,
		Amount:           ngnAmount,
		Currency:         "NGN",
		TokensGranted:    plan.Tokens,
		Plan:             plan.Code,
	}

	if mode == "inline" {
		out.InlinePublicKey = os.Getenv(
			"PAYSTACK_PUBLIC_KEY",
		)
	}

	return out,
		provider.Message,
		nil
}

// ============================================================
// PAYSTACK VERIFY
// ============================================================

func VerifyPaymentAndCredit(
	reference string,
) (*models.PaymentHistory, string, error) {

	reference = strings.TrimSpace(reference)

	if reference == "" {
		return nil,
			"reference is required",
			fmt.Errorf("missing reference")
	}

	if PaystackSecret() == "" {
		return nil,
			"paystack secret key not configured",
			fmt.Errorf("missing PAYSTACK_SECRET_KEY")
	}

	ctx := context.Background()

	database := db.MongoClient.Database(db.DatabaseName)

	paymentCollection := database.Collection("payment_history")
	userCollection := database.Collection("users")

	// ========================================================
	// 1. Find our payment record
	// ========================================================

	var existing models.PaymentHistory

	err := paymentCollection.
		FindOne(
			ctx,
			bson.M{
				"reference": reference,
			},
		).
		Decode(&existing)

	if err != nil {

		if err == mongo.ErrNoDocuments {
			return nil,
				"payment record not found",
				fmt.Errorf(
					"payment %s does not exist in payment_history",
					reference,
				)
		}

		return nil,
			"failed to find payment record",
			fmt.Errorf(
				"failed to find payment %s: %w",
				reference,
				err,
			)
	}

	// ========================================================
	// 2. Already credited?
	// ========================================================

	if existing.Credited {

		return &existing,
			"payment already credited",
			nil
	}

	// ========================================================
	// 3. Verify transaction with Paystack
	// ========================================================

	verifyURL :=
		"https://api.paystack.co/transaction/verify/" +
			url.PathEscape(reference)

	req, err := http.NewRequest(
		http.MethodGet,
		verifyURL,
		nil,
	)

	if err != nil {
		return nil,
			"failed to create verification request",
			err
	}

	req.Header.Set(
		"Authorization",
		"Bearer "+PaystackSecret(),
	)

	req.Header.Set(
		"Accept",
		"application/json",
	)

	client := &http.Client{
		Timeout: 20 * time.Second,
	}

	res, err := client.Do(req)

	if err != nil {
		return nil,
			"failed to reach paystack",
			err
	}

	defer res.Body.Close()

	var provider paystackVerifyResponse

	if err := json.NewDecoder(
		res.Body,
	).Decode(&provider); err != nil {

		return nil,
			"failed to parse paystack verification response",
			err
	}

	// ========================================================
	// 4. Paystack API status
	// ========================================================

	if !provider.Status {

		return nil,
			provider.Message,
			fmt.Errorf(
				"paystack verification failed: %s",
				provider.Message,
			)
	}

	// ========================================================
	// 5. Transaction status
	// ========================================================

	if !strings.EqualFold(
		provider.Data.Status,
		"success",
	) {

		return nil,
			"payment has not been completed",
			fmt.Errorf(
				"paystack transaction status: %s",
				provider.Data.Status,
			)
	}

	// ========================================================
	// 6. Resolve plan
	// ========================================================

	planCode := strings.TrimSpace(existing.Plan)

	if planCode == "" {

		if value, ok :=
			provider.Data.Metadata["plan"].(string); ok {

			planCode = strings.TrimSpace(value)
		}
	}

	plan, ok := ResolvePaymentPlan(planCode)

	if !ok {

		return nil,
			"invalid payment plan",
			fmt.Errorf(
				"unknown payment plan %q",
				planCode,
			)
	}

	// ========================================================
	// 7. Use authenticated payment email first
	// ========================================================

	email := strings.TrimSpace(existing.Email)

	if email == "" {
		email = strings.TrimSpace(
			provider.Data.Customer.Email,
		)
	}

	if email == "" {

		return nil,
			"payment email missing",
			fmt.Errorf("missing payment email")
	}

	// ========================================================
	// 8. Find user BEFORE crediting
	// ========================================================

	var user bson.M

	err = userCollection.
		FindOne(
			ctx,
			bson.M{
				"email": email,
			},
		).
		Decode(&user)

	if err != nil {

		if err == mongo.ErrNoDocuments {

			return nil,
				"user account not found",
				fmt.Errorf(
					"no user found with email %q",
					email,
				)
		}

		return nil,
			"failed to find user",
			fmt.Errorf(
				"failed to find user %q: %w",
				email,
				err,
			)
	}

	// ========================================================
	// 9. Credit user
	// ========================================================

	now := time.Now().UTC()

	updateResult, err := userCollection.
		UpdateOne(
			ctx,

			bson.M{
				"email": email,
			},

			bson.M{
				"$inc": bson.M{
					"tokens_remaining": plan.Tokens,
					"wallet_balance":   plan.Amount,
				},

				"$set": bson.M{
					"updated_at": now,
				},
			},
		)

	if err != nil {

		return nil,
			"failed to credit tokens",
			fmt.Errorf(
				"failed to update user %q: %w",
				email,
				err,
			)
	}

	// ========================================================
	// 10. Ensure Mongo actually matched the user
	// ========================================================

	if updateResult.MatchedCount == 0 {

		return nil,
			"user was not credited",
			fmt.Errorf(
				"MongoDB matched 0 users for email %q",
				email,
			)
	}

	// ========================================================
	// 11. Parse paid_at
	// ========================================================

	var paidAt *time.Time

	if provider.Data.PaidAt != "" {

		if parsed, parseErr :=
			time.Parse(
				time.RFC3339,
				provider.Data.PaidAt,
			); parseErr == nil {

			parsed = parsed.UTC()
			paidAt = &parsed
		}
	}

	// ========================================================
	// 12. Mark payment credited
	// ========================================================

	paymentResult, err := paymentCollection.
		UpdateOne(
			ctx,

			bson.M{
				"reference": reference,
				"credited":  false,
			},

			bson.M{
				"$set": bson.M{
					"reference":         reference,
					"email":             email,
					"plan":              plan.Code,
					"amount":            plan.Amount,
					"currency":          provider.Data.Currency,
					"tokens_granted":    plan.Tokens,
					"status":            "success",
					"channel":           provider.Data.Channel,
					"authorization_url": existing.AuthorizationURL,
					"access_code":       existing.AccessCode,
					"updated_at":        now,
					"paid_at":           paidAt,
					"raw_event":         provider.Message,
					"credited":          true,
				},
			},
		)

	if err != nil {

		return nil,
			"failed to update payment history",
			fmt.Errorf(
				"failed to mark payment as credited: %w",
				err,
			)
	}

	if paymentResult.MatchedCount == 0 {

		// The user has already been credited by this request,
		// but another request claimed the payment record.
		// Do not credit the user again.

		return nil,
			"payment was already processed",
			fmt.Errorf(
				"payment %s was already claimed",
				reference,
			)
	}

	// ========================================================
	// 13. Return success
	// ========================================================

	result := &models.PaymentHistory{
		Reference:        reference,
		Email:            email,
		Plan:             plan.Code,
		Amount:           plan.Amount,
		Currency:         provider.Data.Currency,
		TokensGranted:    plan.Tokens,
		Status:           "success",
		Channel:          provider.Data.Channel,
		AuthorizationURL: existing.AuthorizationURL,
		AccessCode:       existing.AccessCode,
		CreatedAt:        existing.CreatedAt,
		UpdatedAt:        now,
		PaidAt:           paidAt,
		RawEvent:         provider.Message,
		Credited:         true,
	}
	if !provider.Status {
		if existing.Email != "" {
			_ = CreateNotification(
				existing.Email,
				"Payment verification failed",
				fmt.Sprintf("We couldn't verify your payment (ref: %s).", reference),
				"payment_failed",
			)
		}

		return nil,
			provider.Message,
			fmt.Errorf(
				"paystack verification failed: %s",
				provider.Message,
			)
	}
	if !strings.EqualFold(
		provider.Data.Status,
		"success",
	) {
		if existing.Email != "" {
			_ = CreateNotification(
				existing.Email,
				"Payment failed",
				fmt.Sprintf("Your payment (ref: %s) was not completed.", reference),
				"payment_failed",
			)
		}

		return nil,
			"payment has not been completed",
			fmt.Errorf(
				"paystack transaction status: %s",
				provider.Data.Status,
			)
	}
	_ = CreateNotification(
		email,
		"Payment successful",
		fmt.Sprintf("Your payment for the %s plan was successful. %d tokens have been added to your wallet.", plan.Name, plan.Tokens),
		"payment_success",
	)

	return result,
		"payment verified and tokens credited successfully",
		nil
}

// ============================================================
// PAYSTACK SIGNATURE
// ============================================================

func VerifyPaystackSignature(
	secret,
	body,
	signature string,
) bool {

	if secret == "" ||
		signature == "" {

		return false
	}

	mac := hmac.New(
		sha512.New,
		[]byte(secret),
	)

	_, _ = mac.Write(
		[]byte(body),
	)

	expected := hex.EncodeToString(
		mac.Sum(nil),
	)

	return hmac.Equal(
		[]byte(strings.ToLower(expected)),
		[]byte(strings.ToLower(signature)),
	)
}

// ============================================================
// PAYMENT HISTORY
// ============================================================

func GetPaymentHistory(
	reference string,
) (*models.PaymentHistory, error) {

	reference = strings.TrimSpace(reference)

	if reference == "" {
		return nil, fmt.Errorf(
			"payment reference is required",
		)
	}

	var history models.PaymentHistory

	err := db.MongoClient.
		Database(db.DatabaseName).
		Collection("payment_history").
		FindOne(
			context.Background(),
			bson.M{
				"reference": reference,
			},
		).
		Decode(&history)

	if err != nil {
		return nil, err
	}

	return &history, nil
}

// ============================================================
// SJLY CRYPTO PAYMENT ALIASES
// ============================================================

func CreateSJLYPayment(
	email,
	planCode string,
) (*models.CreateCryptoPaymentResponse, error) {
	return CreateCryptoTokenPayment(
		email,
		planCode,
		"SJLY",
	)
}

func SaveCryptoPaymentSignature(
	paymentID,
	signature,
	userWallet string,
) (*models.CryptoPayment, error) {
	paymentID = strings.TrimSpace(paymentID)
	signature = strings.TrimSpace(signature)
	userWallet = strings.TrimSpace(userWallet)

	if paymentID == "" {
		return nil, fmt.Errorf("payment_id is required")
	}

	if signature == "" {
		return nil, fmt.Errorf("signature is required")
	}

	if userWallet == "" {
		return nil, fmt.Errorf("user_wallet is required")
	}

	collection := db.MongoClient.
		Database(db.DatabaseName).
		Collection("crypto_payments")

	var payment models.CryptoPayment

	err := collection.FindOne(
		context.Background(),
		bson.M{"payment_id": paymentID},
	).Decode(&payment)

	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, fmt.Errorf("payment not found")
		}

		return nil, fmt.Errorf("failed to load payment: %w", err)
	}

	now := time.Now().UTC()

	_, err = collection.UpdateOne(
		context.Background(),
		bson.M{"payment_id": paymentID},
		bson.M{
			"$set": bson.M{
				"user_wallet":            userWallet,
				"transaction_signature":  signature,
				"status":                 "verifying",
				"updated_at":             now,
				"verification_submitted": true,
			},
		},
	)

	if err != nil {
		return nil, fmt.Errorf("failed to save payment signature: %w", err)
	}

	payment.UserWallet = userWallet
	payment.TransactionSignature = signature
	payment.Status = "verifying"
	payment.UpdatedAt = now

	return &payment, nil
}

func GetCryptoPayment(
	paymentID string,
) (*models.CryptoPayment, error) {
	paymentID = strings.TrimSpace(paymentID)

	if paymentID == "" {
		return nil, fmt.Errorf("payment_id is required")
	}

	var payment models.CryptoPayment

	err := db.MongoClient.
		Database(db.DatabaseName).
		Collection("crypto_payments").
		FindOne(
			context.Background(),
			bson.M{"payment_id": paymentID},
		).
		Decode(&payment)

	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, fmt.Errorf("payment not found")
		}

		return nil, fmt.Errorf("failed to fetch payment: %w", err)
	}

	return &payment, nil
}

// ============================================================
// GENERAL CRYPTO PAYMENT CREATION
// ============================================================

func CreateCryptoTokenPayment(
	email,
	planCode,
	tokenSymbol string,
) (*models.CreateCryptoPaymentResponse, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return nil, fmt.Errorf("authenticated email is required")
	}

	plan, ok := ResolvePaymentPlan(planCode)
	if !ok {
		return nil, fmt.Errorf("invalid plan selected")
	}

	tokenSymbol = NormalizeCryptoTokenSymbol(tokenSymbol)
	supported := map[string]struct{}{"SJLY": {}, "USDT": {}, "USDC": {}}
	if _, ok := supported[tokenSymbol]; !ok {
		return nil, fmt.Errorf("unsupported crypto token %q", tokenSymbol)
	}

	mint := MintAddressForCryptoToken(tokenSymbol)
	if mint == "" {
		return nil, fmt.Errorf("%s mint address is not configured", tokenSymbol)
	}

	recipient := GaniumCryptoTreasuryWallet()
	if recipient == "" {
		return nil, fmt.Errorf("Ganium crypto receiving wallet is not configured")
	}

	var tokenAmount string
	switch tokenSymbol {
	case "USDT", "USDC":
		tokenAmount = fmt.Sprintf("%d", int64(math.Round(plan.Amount*1_000_000)))
	default:
		const sjlyPerUSD = int64(100000)
		tokenAmount = fmt.Sprintf("%d", int64(math.Round(plan.Amount*float64(sjlyPerUSD))))
	}

	paymentID := fmt.Sprintf("GAN-%s-%d", tokenSymbol, time.Now().UnixNano())
	now := time.Now().UTC()

	payment := models.CryptoPayment{
		PaymentID:       paymentID,
		Email:           email,
		Plan:            plan.Code,
		USDPrice:        plan.Amount,
		TokenAmount:     tokenAmount,
		TokenSymbol:     tokenSymbol,
		TokenMint:       mint,
		Network:         "solana-mainnet",
		RecipientWallet: recipient,
		Status:          "pending",
		TokensGranted:   plan.Tokens,
		CreatedAt:       now,
		UpdatedAt:       now,
		Credited:        false,
	}

	_, err := db.MongoClient.
		Database(db.DatabaseName).
		Collection("crypto_payments").
		InsertOne(context.Background(), payment)
	if err != nil {
		return nil, fmt.Errorf("failed to create crypto payment: %w", err)
	}

	return &models.CreateCryptoPaymentResponse{
		PaymentID:       payment.PaymentID,
		Plan:            payment.Plan,
		USDPrice:        payment.USDPrice,
		TokenSymbol:     payment.TokenSymbol,
		TokenAmount:     payment.TokenAmount,
		TokenMint:       payment.TokenMint,
		Network:         payment.Network,
		RecipientWallet: payment.RecipientWallet,
		TokensGranted:   payment.TokensGranted,
		Status:          payment.Status,
		CreatedAt:       payment.CreatedAt,
	}, nil
}

// ============================================================
// CRYPTO PAYMENT COMPLETE
// ============================================================

func CompleteCryptoPayment(
	paymentID string,
) (*models.CryptoPayment, string, error) {
	paymentID = strings.TrimSpace(paymentID)

	if paymentID == "" {
		return nil, "payment ID is required", errors.New("missing payment ID")
	}

	ctx := context.Background()

	var payment models.CryptoPayment

	err := db.MongoClient.
		Database(db.DatabaseName).
		Collection("crypto_payments").
		FindOne(
			ctx,
			bson.M{
				"payment_id": paymentID,
			},
		).
		Decode(&payment)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, "payment not found", fmt.Errorf("payment %s does not exist", paymentID)
		}

		return nil, "failed to find payment", fmt.Errorf("failed to find payment %s: %w", paymentID, err)
	}

	if payment.Credited {
		return &payment, "payment already completed", nil
	}

	// Check if the payment is still pending
	if payment.Status != "pending" {
		return &payment, "payment is not pending", fmt.Errorf("payment %s is not in pending status", paymentID)
	}

	// ========================================================
	// 1. Find the corresponding user by email
	// ========================================================

	var user bson.M

	err = db.MongoClient.
		Database(db.DatabaseName).
		Collection("users").
		FindOne(
			ctx,
			bson.M{
				"email": payment.Email,
			},
		).
		Decode(&user)

	if err != nil {
		if err == mongo.ErrNoDocuments {
			return nil, "user not found", fmt.Errorf("no user found with email %q", payment.Email)
		}

		return nil, "failed to find user", fmt.Errorf("failed to find user %q: %w", payment.Email, err)
	}

	// ========================================================
	// 2. Credit the user
	// ========================================================

	now := time.Now().UTC()

	updateResult, err := db.MongoClient.
		Database(db.DatabaseName).
		Collection("users").
		UpdateOne(
			ctx,

			bson.M{
				"email": payment.Email,
			},

			bson.M{
				"$inc": bson.M{
					"tokens_remaining": payment.TokensGranted,
					"wallet_balance":   payment.USDPrice,
				},

				"$set": bson.M{
					"updated_at": now,
				},
			},
		)

	if err != nil {
		return nil, "failed to credit tokens", fmt.Errorf("failed to update user %q: %w", payment.Email, err)
	}

	// ========================================================
	// 3. Ensure Mongo actually matched the user
	// ========================================================

	if updateResult.MatchedCount == 0 {
		return nil, "user was not credited", fmt.Errorf("MongoDB matched 0 users for email %q", payment.Email)
	}

	// ========================================================
	// 4. Mark payment as completed
	// ========================================================

	_, err = db.MongoClient.
		Database(db.DatabaseName).
		Collection("crypto_payments").
		UpdateOne(
			ctx,

			bson.M{
				"payment_id": paymentID,
			},

			bson.M{
				"$set": bson.M{
					"status":     "completed",
					"credited":   true,
					"updated_at": now,
				},
			},
		)

	if err != nil {
		return nil, "failed to update payment status", fmt.Errorf("failed to update payment status for %s: %w", paymentID, err)
	}

	// ========================================================
	// 5. Return success
	// ========================================================

	payment.Status = "completed"
	payment.Credited = true

	_ = CreateNotification(
		payment.Email,
		"Payment successful",
		fmt.Sprintf("Your payment (ID: %s) was successful. %d tokens have been added to your wallet.", payment.PaymentID, payment.TokensGranted),
		"payment_success",
	)

	return &payment, "payment completed successfully", nil
}
