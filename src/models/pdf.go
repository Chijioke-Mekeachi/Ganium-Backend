package models

import "time"

type ReceiptRequest struct {
	Reference       string  `json:"reference" bson:"reference" example:"PAY-20260821-001"`
	Amount          float64 `json:"amount" bson:"amount" example:"49.99"`
	Currency        string  `json:"currency" bson:"currency" example:"NGN"`
	Description     string  `json:"description" bson:"description" example:"Pro subscription payment"`
	PayerEmail      string  `json:"payer_email" bson:"payer_email" example:"user@example.com"`
	PayerName       string  `json:"payer_name" bson:"payer_name" example:"Jane Doe"`
	TransactionDate string  `json:"transaction_date,omitempty" bson:"transaction_date,omitempty" example:"2026-08-21T08:30:00Z"`
	PaymentMethod   string  `json:"payment_method,omitempty" bson:"payment_method,omitempty" example:"card"`
	Status          string  `json:"status,omitempty" bson:"status,omitempty" example:"success"`
}

type ReceiptData struct {
	Reference       string
	Amount          float64
	Currency        string
	Description     string
	PayerEmail      string
	PayerName       string
	TransactionDate time.Time
	PaymentMethod   string
	Status          string
}
