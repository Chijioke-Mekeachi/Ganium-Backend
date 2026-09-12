package main

import (
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	hash := []byte("$2a$10$rxmCXg/WnjrpXC1ybjTYN.vjBHxlR3qCex3tyYlwovb5L56GKobhG")
	password := []byte("password123#")
	err := bcrypt.CompareHashAndPassword(hash, password)
	fmt.Println("bcrypt.CompareHashAndPassword error:", err)
	if err == nil {
		fmt.Println("match")
	} else {
		fmt.Println("no match")
	}
}
