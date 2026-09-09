package models


type UserDetails struct{
	Username string `json:"username" bson:"username"`
	Email string `json:"email" bson:"email"`
}