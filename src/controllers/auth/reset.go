package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"ganium/src/db"
	"ganium/src/models"
	"ganium/src/utils"

	"go.mongodb.org/mongo-driver/v2/bson"
)

func ForgotPasswordController(email string) (bool, string) {
	collection := db.MongoClient.Database(db.DatabaseName).Collection("users")

	var user models.Register
	if err := collection.FindOne(context.Background(), bson.M{"email": email}).Decode(&user); err != nil {
		return false, "email not found"
	}

	// generate reset token
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return false, "failed to generate token"
	}
	token := hex.EncodeToString(b)
	tokenHash, err := utils.HashPassword(token)
	if err != nil {
		return false, "failed to hash token"
	}
	expiry := time.Now().Add(1 * time.Hour).Unix()

	_, err = collection.UpdateOne(context.Background(), bson.M{"email": email}, bson.M{"$set": bson.M{"resetTokenHash": tokenHash, "resetTokenExpiry": expiry}})
	if err != nil {
		fmt.Println(err)
		return false, "database error"
	}

	subject := "Password reset request"
	body := fmt.Sprintf("Use this token to reset your password: %s\nIt expires in 1 hour.", token)
	if err := utils.SendEmail(email, subject, body); err != nil {
		fmt.Println("warning: failed to send reset email:", err)
	}

	return true, "reset token sent to email"
}

func ResetPasswordController(email, token, newPassword string) (bool, string) {
	collection := db.MongoClient.Database(db.DatabaseName).Collection("users")

	var user models.Register
	if err := collection.FindOne(context.Background(), bson.M{"email": email}).Decode(&user); err != nil {
		return false, "invalid request"
	}

	if user.ResetTokenExpiry == 0 || time.Now().Unix() > user.ResetTokenExpiry {
		return false, "reset token expired or not set"
	}

	if !utils.CheckPassword(token, user.ResetTokenHash) {
		return false, "invalid reset token"
	}

	newHash, err := utils.HashPassword(newPassword)
	if err != nil {
		return false, "failed to hash password"
	}

	_, err = collection.UpdateOne(context.Background(), bson.M{"email": email}, bson.M{"$set": bson.M{"password": newHash}, "$unset": bson.M{"resetTokenHash": "", "resetTokenExpiry": ""}})
	if err != nil {
		fmt.Println(err)
		return false, "failed to update password"
	}

	return true, "password reset successful"
}
