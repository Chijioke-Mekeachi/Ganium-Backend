package controllers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"time"

	"ganium/src/db"
	"ganium/src/models"

	"go.mongodb.org/mongo-driver/v2/bson"
)

func InitializePaystackPayment(email string, payload models.PaystackInitializeRequest) (*models.PaystackInitializeResponse, string, error) {
	secret := os.Getenv("PAYSTACK_SECRET_KEY")
	if secret == "" {
		return nil, "paystack secret key not configured", fmt.Errorf("missing PAYSTACK_SECRET_KEY")
	}

	if payload.Email == "" {
		payload.Email = email
	}
	if payload.Currency == "" {
		payload.Currency = "NGN"
	}
	if payload.Amount <= 0 {
		return nil, "amount must be greater than zero", fmt.Errorf("invalid amount")
	}
	if payload.Reference == "" {
		payload.Reference = fmt.Sprintf("ganium_%d", time.Now().UnixNano())
	}

	reqBody := map[string]any{
		"email":    payload.Email,
		"amount":   int64(math.Round(payload.Amount * 100)),
		"currency": payload.Currency,
		"reference": payload.Reference,
	}
	if payload.Callback != "" {
		reqBody["callback_url"] = payload.Callback
	}
	if payload.Plan != "" {
		reqBody["plan"] = payload.Plan
	}

	bodyBytes, _ := json.Marshal(reqBody)
	req, err := http.NewRequest(http.MethodPost, "https://api.paystack.co/transaction/initialize", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, "failed to create paystack request", err
	}
	req.Header.Set("Authorization", "Bearer "+secret)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 20 * time.Second}
	res, err := client.Do(req)
	if err != nil {
		return nil, "failed to reach paystack", err
	}
	defer res.Body.Close()

	var payloadRes struct {
		Status  bool `json:"status"`
		Message string `json:"message"`
		Data    struct {
			AuthorizationURL string `json:"authorization_url"`
			AccessCode       string `json:"access_code"`
			Reference        string `json:"reference"`
		} `json:"data"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payloadRes); err != nil {
		return nil, "failed to parse paystack response", err
	}
	if !payloadRes.Status {
		return nil, payloadRes.Message, fmt.Errorf("paystack rejected request")
	}

	collection := db.MongoClient.Database(db.DatabaseName).Collection("subscription_history")
	_, _ = collection.InsertOne(context.Background(), bson.M{
		"email":            email,
		"reference":        payloadRes.Data.Reference,
		"access_code":      payloadRes.Data.AccessCode,
		"amount":           payload.Amount,
		"currency":         payload.Currency,
		"plan":             payload.Plan,
		"status":           "initialized",
		"created_at":       time.Now().UTC(),
		"provider_response": payloadRes.Message,
	})

	return &models.PaystackInitializeResponse{
		Status:           true,
		Message:          payloadRes.Message,
		AuthorizationURL: payloadRes.Data.AuthorizationURL,
		AccessCode:       payloadRes.Data.AccessCode,
		Reference:        payloadRes.Data.Reference,
	}, payloadRes.Message, nil
}
