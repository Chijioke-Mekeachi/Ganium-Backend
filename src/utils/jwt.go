package utils

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"time"
)

type jwtHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type jwtClaims struct {
	Email string `json:"email"`
	Exp   int64  `json:"exp"`
	Iat   int64  `json:"iat"`
}

func jwtSecret() []byte {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "ganium-dev-secret"
	}
	return []byte(secret)
}

func base64URL(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func GenerateJWT(email string) (string, error) {
	header := jwtHeader{Alg: "HS256", Typ: "JWT"}
	claims := jwtClaims{
		Email: email,
		Exp:   time.Now().Add(24 * time.Hour).Unix(),
		Iat:   time.Now().Unix(),
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	unsigned := base64URL(headerJSON) + "." + base64URL(claimsJSON)
	mac := hmac.New(sha256.New, jwtSecret())
	_, _ = mac.Write([]byte(unsigned))
	signature := base64URL(mac.Sum(nil))

	return unsigned + "." + signature, nil
}

func ValidateJWT(tokenString string) (map[string]any, error) {
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	unsigned := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, jwtSecret())
	_, _ = mac.Write([]byte(unsigned))
	expectedSig := base64URL(mac.Sum(nil))
	if !hmac.Equal([]byte(expectedSig), []byte(parts[2])) {
		return nil, errors.New("invalid token signature")
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}

	var claims jwtClaims
	if err := json.Unmarshal(payloadBytes, &claims); err != nil {
		return nil, err
	}

	if time.Now().Unix() > claims.Exp {
		return nil, errors.New("token expired")
	}

	return map[string]any{
		"email": claims.Email,
		"exp":   claims.Exp,
		"iat":   claims.Iat,
	}, nil
}
