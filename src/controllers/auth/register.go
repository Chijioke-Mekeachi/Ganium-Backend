package auth

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"time"

	"ganium/src/db"
	"ganium/src/models"
	"ganium/src/utils"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

// genNumericOTP returns an n-digit numeric OTP as a zero-padded string.
func genNumericOTP(n int) (string, error) {
	if n <= 0 {
		return "", nil
	}
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(n)), nil) // 10^n
	num, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	format := fmt.Sprintf("%%0%dd", n)
	return fmt.Sprintf(format, num.Int64()), nil
}

func RegisterController(data models.Register) (bool, string) {
	if err := db.CreateCollection("users"); err != nil {
		// ignore error if collection already exists
	}

	collection := db.MongoClient.Database(db.DatabaseName).Collection("users")

	passwordHash, err := utils.HashPassword(data.Password)
	if err != nil {
		fmt.Println(err)
		return false, "Error hashing password"
	}

	var user models.Register
	err = collection.FindOne(context.Background(), bson.M{"email": data.Email}).Decode(&user)
	if err == nil {
		return false, "email already exists"
	}
	if !errors.Is(err, mongo.ErrNoDocuments) {
		fmt.Println(err)
		return false, "database error"
	}

	otp, err := genNumericOTP(6)
	if err != nil {
		fmt.Println(err)
		return false, "failed to generate otp"
	}
	otpHash, err := utils.HashPassword(otp)
	if err != nil {
		fmt.Println(err)
		return false, "failed to hash otp"
	}

	otpExpiry := time.Now().Add(15 * time.Minute).Unix()

	_, err = collection.InsertOne(context.Background(), bson.M{
		"email":      data.Email,
		"password":   passwordHash,
		"isVerified": false,
		"otpHash":    otpHash,
		"otpExpiry":  otpExpiry,
	})
	if err != nil {
		fmt.Println(err)
		return false, "failed to register user"
	}

	// send OTP email (best-effort) as HTML
	subject := "Your verification OTP"
	body := fmt.Sprintf(`<!doctype html>
<html>
	<body style="font-family: Arial, sans-serif; line-height:1.6;">
		<h2>Your verification code</h2>
		<p style="font-size:18px;">Use the code below to verify your email. It expires in 15 minutes.</p>
		<div style="font-size:28px; font-weight:700; background:#f6f6f6; display:inline-block; padding:12px 18px; border-radius:6px; letter-spacing:4px;">%s</div>
		<p style="color:#666; margin-top:18px;">If you didn't request this, please ignore this email.</p>
	</body>
</html>`, otp)
	if err := utils.SendEmail(data.Email, subject, body); err != nil {
		fmt.Println("warning: failed to send otp email:", err)
		// don't fail registration because of email sending
	}

	return true, "User registered successfully; OTP sent to email"
}
