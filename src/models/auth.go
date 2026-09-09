package models

type Login struct {
	Email    string `json:"email" bson:"email" example:"user@example.com"`
	Password string `json:"password" bson:"password" example:"NewPassword123!"`
}

type RegisterRequest struct {
	Email    string `json:"email" example:"user@example.com"`
	Password string `json:"password" example:"NewPassword123!"`
	FullName string `json:"full_name,omitempty" example:"Jane Doe"`
}

type Register struct {
	Email            string `json:"email" bson:"email"`
	Password         string `json:"password" bson:"password"`
	FullName         string `json:"full_name,omitempty" bson:"full_name,omitempty"`
	Role             string `json:"role,omitempty" bson:"role,omitempty"`
	IsVerified       bool   `json:"isVerified" bson:"isVerified"`
	OTPHash          string `json:"otpHash,omitempty" bson:"otpHash,omitempty"`
	OTPExpiry        int64  `json:"otpExpiry,omitempty" bson:"otpExpiry,omitempty"`
	ResetTokenHash   string `json:"resetTokenHash,omitempty" bson:"resetTokenHash,omitempty"`
	ResetTokenExpiry int64  `json:"resetTokenExpiry,omitempty" bson:"resetTokenExpiry,omitempty"`
}

type AuthResponse struct {
	Message string `json:"message"`
	Token   string `json:"token,omitempty"`
	Email   string `json:"email,omitempty"`
}
