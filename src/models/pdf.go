package models

import "time"

type ReceiptRequest struct {
	Reference       string  `json:"reference" bson:"reference"`
	Amount          float64 `json:"amount" bson:"amount"`
	Currency        string  `json:"currency" bson:"currency"`
	Description     string  `json:"description" bson:"description"`
	PayerEmail      string  `json:"payer_email" bson:"payer_email"`
	PayerName       string  `json:"payer_name" bson:"payer_name"`
	TransactionDate  string  `json:"transaction_date,omitempty" bson:"transaction_date,omitempty"`
	PaymentMethod   string  `json:"payment_method,omitempty" bson:"payment_method,omitempty"`
	Status          string  `json:"status,omitempty" bson:"status,omitempty"`
}

type ReceiptData struct {
	Reference      string
	Amount         float64
	Currency       string
	Description    string
	PayerEmail     string
	PayerName      string
	TransactionDate time.Time
	PaymentMethod  string
	Status         string
}

