package utils

import (
	"crypto/tls"
	"fmt"
	"net/smtp"
	"os"
)

// SendEmail sends an HTML email using Gmail SMTP over implicit TLS (port 465).
// Required env vars:
//   SMTP_USER - Gmail address
//   SMTP_PASS - Gmail App Password
func SendEmail(to, subject, body string) error {
	smtpHost := "smtp.gmail.com"
	smtpPort := "465"

	from := os.Getenv("SMTP_USER")
	pass := os.Getenv("SMTP_PASS")

	if from == "" || pass == "" {
		return fmt.Errorf("smtp credentials not configured")
	}

	// Build the email message.
	msg := "From: " + from + "\r\n" +
		"To: " + to + "\r\n" +
		"Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/html; charset=\"UTF-8\"\r\n" +
		"\r\n" +
		body

	// Port 465 uses implicit TLS.
	tlsConfig := &tls.Config{
		ServerName: smtpHost,
	}

	conn, err := tls.Dial(
		"tcp",
		smtpHost+":"+smtpPort,
		tlsConfig,
	)
	if err != nil {
		return fmt.Errorf("failed to connect to SMTP server: %w", err)
	}
	defer conn.Close()

	// Create SMTP client over the TLS connection.
	client, err := smtp.NewClient(conn, smtpHost)
	if err != nil {
		return fmt.Errorf("failed to create SMTP client: %w", err)
	}
	defer client.Close()

	// Authenticate with Gmail.
	auth := smtp.PlainAuth(
		"",
		from,
		pass,
		smtpHost,
	)

	if err := client.Auth(auth); err != nil {
		return fmt.Errorf("SMTP authentication failed: %w", err)
	}

	// Specify sender.
	if err := client.Mail(from); err != nil {
		return fmt.Errorf("failed to set sender: %w", err)
	}

	// Specify recipient.
	if err := client.Rcpt(to); err != nil {
		return fmt.Errorf("failed to set recipient: %w", err)
	}

	// Start message data.
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("failed to start email data: %w", err)
	}

	// Write email contents.
	if _, err := writer.Write([]byte(msg)); err != nil {
		writer.Close()
		return fmt.Errorf("failed to write email: %w", err)
	}

	// Finish message.
	if err := writer.Close(); err != nil {
		return fmt.Errorf("failed to close email data: %w", err)
	}

	// Quit SMTP session.
	if err := client.Quit(); err != nil {
		return fmt.Errorf("failed to close SMTP connection: %w", err)
	}

	return nil
}