package auth

import (
	"context"
	"errors"
	"fmt"
	"ganium/src/db"
	"ganium/src/models"
	"ganium/src/utils"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

func LoginController(data models.Login) (bool, string, string) {
	collection := db.MongoClient.Database(db.DatabaseName).Collection("users")

	var user models.Register
	err := collection.FindOne(context.Background(), bson.M{"email": data.Email}).Decode(&user)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return false, "invalid email or password", ""
		}
		fmt.Println(err)
		return false, "database error", ""
	}

	if !utils.CheckPassword(data.Password, user.Password) {
		return false, "invalid email or password", ""
	}

	if !user.IsVerified {
		return false, "email not verified", ""
	}

	token, err := utils.GenerateJWT(user.Email)
	if err != nil {
		fmt.Println(err)
		return false, "failed to generate token", ""
	}

	return true, "login successful", token
}
