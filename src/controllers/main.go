package controllers

import (
	"ganium/src/controllers/auth"
	"ganium/src/models"
)

func RegisterUser(UserData models.Register) (bool, string) {
	return auth.RegisterController(UserData)
}

func LoginUser(userData models.Login) (bool, string, string) {
	return auth.LoginController(userData)
}

func VerifyOTP(email, otp string) (bool, string) {
	return auth.VerifyOTPController(email, otp)
}

func ResendOTP(email string) (bool, string) {
	return auth.ResendOTPController(email)
}

func ForgotPassword(email string) (bool, string) {
	return auth.ForgotPasswordController(email)
}

func ResetPassword(email, token, newPassword string) (bool, string) {
	return auth.ResetPasswordController(email, token, newPassword)
}

func BuildScanPDF(userEmail string, record *models.ScanRecord) ([]byte, error) {
	return buildScanPDF(userEmail, record)
}

func BuildReceiptPDF(userEmail string, receipt models.ReceiptData) ([]byte, error) {
	return buildReceiptPDF(userEmail, receipt)
}
