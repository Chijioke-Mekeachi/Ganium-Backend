package utils

import (
	"fmt"
	"net/smtp"
	"os"
)

// SendEmail sends a plain-text email using SMTP credentials from environment.
// Required env vars: SMTP_USER (your gmail address), SMTP_PASS (app password).
func SendEmail(to, subject, body string) error {
	smtpHost := "smtp.gmail.com"
	smtpPort := "587"
	from := os.Getenv("SMTP_USER")
	pass := os.Getenv("SMTP_PASS")
	if from == "" || pass == "" {
		return fmt.Errorf("smtp credentials not configured")
	}

	// Send HTML email
	msg := "From: " + from + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0;\r\n" +
		"Content-Type: text/html; charset=\"UTF-8\";\r\n\r\n" +
		body

	auth := smtp.PlainAuth("", from, pass, smtpHost)
	addr := smtpHost + ":" + smtpPort

	return smtp.SendMail(addr, auth, from, []string{to}, []byte(msg))
}
