package controllers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"ganium/src/db"
	"ganium/src/utils"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func LogAdminEvent(eventType, title, message, userEmail string) error {
	collection := db.MongoClient.Database(db.DatabaseName).Collection("admin_alerts")
	_, err := collection.InsertOne(context.Background(), bson.M{
		"type":       strings.TrimSpace(eventType),
		"title":      strings.TrimSpace(title),
		"message":    strings.TrimSpace(message),
		"user_email": strings.TrimSpace(userEmail),
		"created_at": time.Now().UTC(),
	})
	return err
}

func AdminLogin(email, password string) (bool, string, string) {
	email = strings.TrimSpace(email)
	password = strings.TrimSpace(password)
	if email == "" || password == "" {
		return false, "admin email and password are required", ""
	}

	// Allow explicit ADMIN_EMAIL/ADMIN_PASSWORD env override even if a user exists
	envEmail := strings.TrimSpace(os.Getenv("ADMIN_EMAIL"))
	envPassword := strings.TrimSpace(os.Getenv("ADMIN_PASSWORD"))
	if envEmail == email && envPassword != "" && envPassword == password {
		token, jwtErr := utils.GenerateJWTWithRole(email, "admin")
		if jwtErr != nil {
			fmt.Printf("AdminLogin: failed to generate token for env admin %s: %v\n", email, jwtErr)
			return false, "failed to generate admin token", ""
		}
		fmt.Printf("AdminLogin: env admin login successful for %s (env override)\n", email)
		return true, "admin login successful", token
	}

	collection := db.MongoClient.Database(db.DatabaseName).Collection("users")
	var user bson.M
	if err := collection.FindOne(context.Background(), bson.M{"email": email}).Decode(&user); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			fmt.Printf("AdminLogin: user not found for email=%s, falling back to env vars\n", email)
			envEmail := strings.TrimSpace(os.Getenv("ADMIN_EMAIL"))
			envPassword := strings.TrimSpace(os.Getenv("ADMIN_PASSWORD"))
			if envEmail == email && envPassword != "" && envPassword == password {
				token, jwtErr := utils.GenerateJWTWithRole(email, "admin")
				if jwtErr != nil {
					fmt.Printf("AdminLogin: failed to generate token for env admin %s: %v\n", email, jwtErr)
					return false, "failed to generate admin token", ""
				}
				fmt.Printf("AdminLogin: env admin login successful for %s\n", email)
				return true, "admin login successful", token
			}
			fmt.Printf("AdminLogin: invalid credentials for env/admin fallback email=%s\n", email)
			return false, "invalid admin credentials", ""
		}
		fmt.Printf("AdminLogin: database error while finding user %s: %v\n", email, err)
		return false, "database error", ""
	}

	role, _ := user["role"].(string)
	isAdmin, _ := user["is_admin"].(bool)
	fmt.Printf("AdminLogin: found user email=%s role=%v is_admin=%v\n", email, role, isAdmin)
	if role != "admin" && !isAdmin {
		fmt.Printf("AdminLogin: user %s is not admin (role=%v is_admin=%v)\n", email, role, isAdmin)
		return false, "invalid admin credentials", ""
	}

	storedPassword, _ := user["password"].(string)
	// Debug: print stored password summary and SHA256 of provided password
	prefix := ""
	if len(storedPassword) > 6 {
		prefix = storedPassword[:6]
	} else {
		prefix = storedPassword
	}
	sha := sha256.Sum256([]byte(password))
	shaHex := hex.EncodeToString(sha[:])
	fmt.Printf("AdminLogin: storedPassword_len=%d prefix=%s provided_password_sha256=%s\n", len(storedPassword), prefix, shaHex)
	fmt.Printf("AdminLogin: storedPassword_full=%s\n", storedPassword)

	if !utils.CheckPassword(password, storedPassword) {
		fmt.Printf("AdminLogin: password mismatch for %s\n", email)
		return false, "invalid admin credentials", ""
	}

	token, err := utils.GenerateJWTWithRole(email, "admin")
	if err != nil {
		return false, "failed to generate admin token", ""
	}

	fmt.Printf("AdminLogin: login successful for %s\n", email)
	return true, "admin login successful", token
}

func GetAdminDashboard() (bson.M, error) {
	ctx := context.Background()
	usersCollection := db.MongoClient.Database(db.DatabaseName).Collection("users")
	paymentsCollection := db.MongoClient.Database(db.DatabaseName).Collection("payment_history")

	userCursor, err := usersCollection.Find(ctx, bson.M{})
	if err != nil {
		return nil, err
	}
	defer userCursor.Close(ctx)

	totalUsers, activeUsers, totalTokensUsed, totalTokensRemaining := 0, 0, 0, 0
	for userCursor.Next(ctx) {
		var user bson.M
		if err := userCursor.Decode(&user); err != nil {
			continue
		}
		totalUsers++
		if status, ok := user["subscription_status"].(string); ok && strings.EqualFold(status, "active") {
			activeUsers++
		}
		if v, ok := user["tokens_used_total"].(int32); ok {
			totalTokensUsed += int(v)
		}
		if v, ok := user["tokens_used_total"].(int64); ok {
			totalTokensUsed += int(v)
		}
		if v, ok := user["tokens_used_total"].(int); ok {
			totalTokensUsed += v
		}
		if v, ok := user["tokens_remaining"].(int32); ok {
			totalTokensRemaining += int(v)
		}
		if v, ok := user["tokens_remaining"].(int64); ok {
			totalTokensRemaining += int(v)
		}
		if v, ok := user["tokens_remaining"].(int); ok {
			totalTokensRemaining += v
		}
	}

	paymentCursor, err := paymentsCollection.Find(ctx, bson.M{"status": "success"})
	if err != nil {
		return nil, err
	}
	defer paymentCursor.Close(ctx)

	totalSpentUSD, totalSpentNGN := 0.0, 0.0
	for paymentCursor.Next(ctx) {
		var payment bson.M
		if err := paymentCursor.Decode(&payment); err != nil {
			continue
		}
		amount := toFloat64(payment["amount"])
		currency := strings.TrimSpace(strings.ToUpper(valueString(payment["currency"])))
		switch currency {
		case "USD":
			totalSpentUSD += amount
		case "NGN":
			totalSpentNGN += amount
		default:
			totalSpentNGN += amount
		}
	}

	return bson.M{
		"total_users":            totalUsers,
		"active_subscriptions":   activeUsers,
		"total_tokens_used":      totalTokensUsed,
		"total_tokens_remaining": totalTokensRemaining,
		"total_spent_usd":        totalSpentUSD,
		"total_spent_ngn":        totalSpentNGN,
		"free_tokens_issued":     totalUsers * 5,
		"generated_at":           time.Now().UTC(),
	}, nil
}

func GetAllUsers() ([]bson.M, error) {
	ctx := context.Background()
	collection := db.MongoClient.Database(db.DatabaseName).Collection("users")
	cursor, err := collection.Find(ctx, bson.M{}, options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(ctx)

	var users []bson.M
	if err := cursor.All(ctx, &users); err != nil {
		return nil, err
	}
	return users, nil
}

func GetUserByEmail(email string) (bson.M, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return nil, fmt.Errorf("email is required")
	}
	collection := db.MongoClient.Database(db.DatabaseName).Collection("users")
	var user bson.M
	if err := collection.FindOne(context.Background(), bson.M{"email": email}).Decode(&user); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, fmt.Errorf("user not found")
		}
		return nil, err
	}
	return user, nil
}

func UpdateUserByEmail(email string, payload bson.M) (bson.M, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return nil, fmt.Errorf("email is required")
	}
	if len(payload) == 0 {
		return GetUserByEmail(email)
	}
	payload["updated_at"] = time.Now().UTC()
	collection := db.MongoClient.Database(db.DatabaseName).Collection("users")
	result, err := collection.UpdateOne(context.Background(), bson.M{"email": email}, bson.M{"$set": payload})
	if err != nil {
		return nil, err
	}
	if result.MatchedCount == 0 {
		return nil, fmt.Errorf("user not found")
	}
	return GetUserByEmail(email)
}

func DeleteUserByEmail(email string) error {
	email = strings.TrimSpace(email)
	if email == "" {
		return fmt.Errorf("email is required")
	}
	database := db.MongoClient.Database(db.DatabaseName)
	if _, err := database.Collection("users").DeleteOne(context.Background(), bson.M{"email": email}); err != nil {
		return err
	}
	_, _ = database.Collection("notifications").DeleteMany(context.Background(), bson.M{"user_id": email})
	_, _ = database.Collection("scan_records").DeleteMany(context.Background(), bson.M{"user_id": email})
	_, _ = database.Collection("payment_history").DeleteMany(context.Background(), bson.M{"email": email})
	_ = LogAdminEvent("user_deleted", "User deleted", fmt.Sprintf("User %s was deleted by an admin.", email), email)
	return nil
}

func GetAdminAlerts() ([]bson.M, error) {
	collection := db.MongoClient.Database(db.DatabaseName).Collection("admin_alerts")
	cursor, err := collection.Find(context.Background(), bson.M{}, options.Find().SetSort(bson.D{{Key: "created_at", Value: -1}}))
	if err != nil {
		return nil, err
	}
	defer cursor.Close(context.Background())
	var alerts []bson.M
	if err := cursor.All(context.Background(), &alerts); err != nil {
		return nil, err
	}
	return alerts, nil
}

func GetPrivacyPolicy() string {
	return "Privacy Policy\n\nWe collect only the information needed to create your account, provide security analysis, process payments, and improve service quality. This includes your email address, full name (if provided), wallet details when connected, token usage, and transactions needed to complete subscription purchases.\n\nWe do not sell your personal information. We use data only to authenticate your account, maintain security features, generate reports, deliver notifications, and support billing or account management.\n\nWe may store logs and event records for fraud prevention, security investigations, and admin oversight. Some records are retained as required to provide the service and comply with legal obligations.\n\nYou can request access to your data, update your profile, or delete your account from the platform.\n\nThis privacy policy may change over time, and updates will be published through the application or API."
}

func toFloat64(value any) float64 {
	switch v := value.(type) {
	case float64:
		return v
	case float32:
		return float64(v)
	case int:
		return float64(v)
	case int32:
		return float64(v)
	case int64:
		return float64(v)
	case string:
		var f float64
		_, _ = fmt.Sscanf(v, "%f", &f)
		return f
	default:
		return 0
	}
}

func valueString(value any) string {
	if value == nil {
		return ""
	}
	switch v := value.(type) {
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	default:
		return fmt.Sprintf("%v", v)
	}
}

func EnsureDefaultAdminAccount() error {
	const adminEmail = "ganium.team@gmail.com"
	const adminPassword = "password123#"

	collection := db.MongoClient.Database(db.DatabaseName).Collection("users")
	var user bson.M
	if err := collection.FindOne(context.Background(), bson.M{"email": adminEmail}).Decode(&user); err == nil {
		updates := bson.M{"role": "admin", "is_admin": true, "updated_at": time.Now().UTC()}
		if _, err := collection.UpdateOne(context.Background(), bson.M{"email": adminEmail}, bson.M{"$set": updates}); err != nil {
			return err
		}
		return nil
	} else if !errors.Is(err, mongo.ErrNoDocuments) {
		return err
	}

	hash, err := utils.HashPassword(adminPassword)
	if err != nil {
		return err
	}

	_, err = collection.InsertOne(context.Background(), bson.M{
		"email":               adminEmail,
		"password":            hash,
		"full_name":           "Ganium Team",
		"role":                "admin",
		"is_admin":            true,
		"tokens_remaining":    0,
		"tokens_used_total":   0,
		"subscription_status": "inactive",
		"wallet_balance":      0,
		"created_at":          time.Now().UTC(),
		"updated_at":          time.Now().UTC(),
		"isVerified":          true,
	})
	return err
}

func generateNumericOTP(length int) (string, error) {
	if length <= 0 {
		return "", nil
	}

	const digits = "0123456789"
	buf := make([]byte, length)
	for i := range buf {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		if err != nil {
			return "", err
		}
		buf[i] = digits[idx.Int64()]
	}
	return string(buf), nil
}

func AdminForgotPassword(email string) (bool, string) {
	email = strings.TrimSpace(email)
	if email == "" {
		return false, "email is required"
	}

	collection := db.MongoClient.Database(db.DatabaseName).Collection("users")
	var user bson.M
	if err := collection.FindOne(context.Background(), bson.M{"email": email}).Decode(&user); err != nil {
		return false, "admin account not found"
	}

	role, _ := user["role"].(string)
	isAdmin, _ := user["is_admin"].(bool)
	if !strings.EqualFold(role, "admin") && !isAdmin {
		return false, "admin account not found"
	}

	otp, err := generateNumericOTP(6)
	if err != nil {
		return false, "failed to generate otp"
	}

	hash, err := utils.HashPassword(otp)
	if err != nil {
		return false, "failed to hash otp"
	}

	expiry := time.Now().Add(10 * time.Minute).Unix()
	if _, err := collection.UpdateOne(context.Background(), bson.M{"email": email}, bson.M{"$set": bson.M{"otpHash": hash, "otpExpiry": expiry}}); err != nil {
		return false, "database error"
	}

	if err := utils.SendEmail(email, "Admin password reset OTP", fmt.Sprintf("Your Ganium admin password reset OTP is %s. It expires in 10 minutes.", otp)); err != nil {
		fmt.Println("warning: failed to send admin reset email:", err)
	}

	return true, "OTP sent to admin email"
}

func AdminResetPassword(email, otp, newPassword string) (bool, string) {
	email = strings.TrimSpace(email)
	otp = strings.TrimSpace(otp)
	newPassword = strings.TrimSpace(newPassword)
	if email == "" || otp == "" || newPassword == "" {
		return false, "email, otp and new password are required"
	}

	collection := db.MongoClient.Database(db.DatabaseName).Collection("users")
	var user bson.M
	if err := collection.FindOne(context.Background(), bson.M{"email": email}).Decode(&user); err != nil {
		return false, "admin account not found"
	}

	role, _ := user["role"].(string)
	isAdmin, _ := user["is_admin"].(bool)
	if !strings.EqualFold(role, "admin") && !isAdmin {
		return false, "admin account not found"
	}

	expiryValue, _ := user["otpExpiry"].(int64)
	if expiryValue == 0 || time.Now().Unix() > expiryValue {
		return false, "otp expired or not set"
	}

	storedHash, _ := user["otpHash"].(string)
	if !utils.CheckPassword(otp, storedHash) {
		return false, "invalid otp"
	}

	newHash, err := utils.HashPassword(newPassword)
	if err != nil {
		return false, "failed to hash password"
	}

	if _, err := collection.UpdateOne(context.Background(), bson.M{"email": email}, bson.M{"$set": bson.M{"password": newHash, "updated_at": time.Now().UTC()}, "$unset": bson.M{"otpHash": "", "otpExpiry": ""}}); err != nil {
		return false, "failed to update password"
	}

	return true, "admin password reset successful"
}
