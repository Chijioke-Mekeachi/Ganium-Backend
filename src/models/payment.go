package models

type PaystackInitializeRequest struct {
	Email     string  `json:"email"`
	Amount    float64 `json:"amount"`
	Currency  string  `json:"currency,omitempty"`
	Plan      string  `json:"plan,omitempty"`
	Reference string  `json:"reference,omitempty"`
	Callback  string  `json:"callback_url,omitempty"`
}

type PaystackInitializeResponse struct {
	Status       bool   `json:"status"`
	Message      string `json:"message"`
	AuthorizationURL string `json:"authorization_url,omitempty"`
	AccessCode   string `json:"access_code,omitempty"`
	Reference    string `json:"reference,omitempty"`
}

