package security

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token expired")
	ErrInvalidTicket = errors.New("invalid or expired websocket ticket")
)

// JWTClaims represents standard Ganium authentication claims.
type JWTClaims struct {
	UserID    string `json:"user_id"`
	Email     string `json:"email"`
	Role      string `json:"role"`
	IssuedAt  int64  `json:"iat"`
	ExpiresAt int64  `json:"exp"`
}

// TokenManager handles JWT issuance and verification without requiring external heavy dependencies.
type TokenManager struct {
	secret []byte
}

func NewTokenManager(secret string) *TokenManager {
	if secret == "" {
		secret = "ganium-default-secret-key-32-bytes!"
	}
	return &TokenManager{secret: []byte(secret)}
}

// GenerateJWT creates a signed HMAC-SHA256 JWT string.
func (tm *TokenManager) GenerateJWT(userID, email, role string, ttl time.Duration) (string, error) {
	now := time.Now().UTC()
	claims := JWTClaims{
		UserID:    userID,
		Email:     email,
		Role:      role,
		IssuedAt:  now.Unix(),
		ExpiresAt: now.Add(ttl).Unix(),
	}

	headerJSON := `{"alg":"HS256","typ":"JWT"}`
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	headerB64 := base64.RawURLEncoding.EncodeToString([]byte(headerJSON))
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)
	payload := headerB64 + "." + claimsB64

	mac := hmac.New(sha256.New, tm.secret)
	mac.Write([]byte(payload))
	sigB64 := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	return payload + "." + sigB64, nil
}

// ValidateJWT validates the signature and expiration of a JWT.
func (tm *TokenManager) ValidateJWT(tokenStr string) (*JWTClaims, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, ErrInvalidToken
	}

	payload := parts[0] + "." + parts[1]
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrInvalidToken
	}

	mac := hmac.New(sha256.New, tm.secret)
	mac.Write([]byte(payload))
	expectedSig := mac.Sum(nil)

	if !hmac.Equal(sig, expectedSig) {
		return nil, ErrInvalidToken
	}

	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalidToken
	}

	var claims JWTClaims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, ErrInvalidToken
	}

	if time.Now().UTC().Unix() > claims.ExpiresAt {
		return nil, ErrExpiredToken
	}

	return &claims, nil
}

// TicketStore provides single-use, time-bound ticket validation for WebSocket connections.
type TicketStore struct {
	mu      sync.Mutex
	tickets map[string]ticketEntry
	ttl     time.Duration
}

type ticketEntry struct {
	UserID          string
	InvestigationID string
	ExpiresAt       time.Time
}

func NewTicketStore(ttl time.Duration) *TicketStore {
	if ttl <= 0 {
		ttl = 2 * time.Minute
	}
	ts := &TicketStore{
		tickets: make(map[string]ticketEntry),
		ttl:     ttl,
	}
	go ts.cleanupLoop()
	return ts
}

// IssueTicket creates a secure cryptographically random ticket.
func (ts *TicketStore) IssueTicket(userID, investigationID string) (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate ticket: %w", err)
	}
	ticket := hex.EncodeToString(b)

	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.tickets[ticket] = ticketEntry{
		UserID:          userID,
		InvestigationID: investigationID,
		ExpiresAt:       time.Now().Add(ts.ttl),
	}

	return ticket, nil
}

// RedeemTicket validates and immediately burns the ticket (single-use).
func (ts *TicketStore) RedeemTicket(ticket, investigationID string) (string, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	entry, exists := ts.tickets[ticket]
	if !exists {
		return "", ErrInvalidTicket
	}

	// Delete immediately to prevent replay attacks
	delete(ts.tickets, ticket)

	if time.Now().After(entry.ExpiresAt) {
		return "", ErrExpiredToken
	}

	if entry.InvestigationID != "" && entry.InvestigationID != investigationID {
		return "", errors.New("ticket is not valid for this investigation")
	}

	return entry.UserID, nil
}

func (ts *TicketStore) cleanupLoop() {
	ticker := time.NewTicker(time.Minute)
	for range ticker.C {
		ts.mu.Lock()
		now := time.Now()
		for k, v := range ts.tickets {
			if now.After(v.ExpiresAt) {
				delete(ts.tickets, k)
			}
		}
		ts.mu.Unlock()
	}
}
