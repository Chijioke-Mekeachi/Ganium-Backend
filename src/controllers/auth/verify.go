package auth

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"ganium/src/db"
	"ganium/src/models"
	"ganium/src/utils"

	"go.mongodb.org/mongo-driver/v2/bson"
)

func ResendOTPController(email string) (bool, string) {
	collection := db.MongoClient.Database(db.DatabaseName).Collection("users")

	var user models.Register
	if err := collection.FindOne(context.Background(), bson.M{"email": email}).Decode(&user); err != nil {
		return false, "email not found"
	}
	if user.IsVerified {
		return false, "email already verified"
	}

	// generate new numeric 6-digit OTP
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(6), nil) // 10^6
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return false, "failed to generate otp"
	}
	otp := fmt.Sprintf("%06d", n.Int64())
	otpHash, err := utils.HashPassword(otp)
	if err != nil {
		return false, "failed to hash otp"
	}
	otpExpiry := time.Now().Add(15 * time.Minute).Unix()

	_, err = collection.UpdateOne(context.Background(), bson.M{"email": email}, bson.M{"$set": bson.M{"otpHash": otpHash, "otpExpiry": otpExpiry}})
	if err != nil {
		fmt.Println(err)
		return false, "database error"
	}

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
	if err := utils.SendEmail(email, subject, body); err != nil {
		fmt.Println("warning: failed to send otp email:", err)
	}

	return true, "OTP resent"
}

func VerifyOTPController(email, otp string) (bool, string) {
	collection := db.MongoClient.Database(db.DatabaseName).Collection("users")

	var user models.Register
	if err := collection.FindOne(context.Background(), bson.M{"email": email}).Decode(&user); err != nil {
		return false, "invalid email or otp"
	}

	if user.OTPExpiry == 0 || time.Now().Unix() > user.OTPExpiry {
		return false, "otp expired or not set"
	}

	if !utils.CheckPassword(otp, user.OTPHash) {
		return false, "invalid otp"
	}

	_, err := collection.UpdateOne(context.Background(), bson.M{"email": email}, bson.M{"$set": bson.M{"isVerified": true}, "$unset": bson.M{"otpHash": "", "otpExpiry": ""}})
	if err != nil {
		fmt.Println(err)
		return false, "failed to update user"
	}

	return true, "email verified"
}
