package controllers

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"ganium/src/db"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

const (
	solanaMainnet = "solana-mainnet"
)

// ============================================================
// RESPONSE TYPES
// ============================================================

type SolanaWalletResponse struct {
	Success                 bool       `json:"success"`
	WalletAddress           string     `json:"wallet_address,omitempty"`
	Network                 string     `json:"network,omitempty"`
	Connected               bool       `json:"connected"`
	WalletConnectedAt       *time.Time `json:"wallet_connected_at,omitempty"`
	Message                 string     `json:"message,omitempty"`
}

type SolanaWalletStatus struct {
	Connected         bool       `json:"connected"`
	WalletAddress     string     `json:"wallet_address,omitempty"`
	Network           string     `json:"network,omitempty"`
	ConnectedAt       *time.Time `json:"connected_at,omitempty"`
}

// ============================================================
// HELPERS
// ============================================================

func usersCollection() *mongo.Collection {
	return db.MongoClient.
		Database(db.DatabaseName).
		Collection("users")
}

func authenticatedEmail(c *gin.Context) (string, error) {
	email := strings.TrimSpace(c.GetString("email"))

	if email == "" {
		return "", errors.New("unauthorized")
	}

	return email, nil
}

// ============================================================
// CONNECT SOLANA WALLET
// ============================================================

func ConnectSolanaWallet(
	c *gin.Context,
	walletAddress string,
	network string,
) (*SolanaWalletResponse, error) {

	email, err := authenticatedEmail(c)

	if err != nil {
		return nil, err
	}

	walletAddress = strings.TrimSpace(walletAddress)
	network = strings.TrimSpace(network)

	if walletAddress == "" {
		return nil, errors.New("wallet_address is required")
	}

	if network == "" {
		network = solanaMainnet
	}

	if network != solanaMainnet {
		return nil, errors.New("only solana-mainnet is supported")
	}

	// Basic Solana public key length validation.
	if len(walletAddress) < 32 || len(walletAddress) > 44 {
		return nil, errors.New("invalid Solana wallet address")
	}

	ctx, cancel := context.WithTimeout(
		c.Request.Context(),
		10*time.Second,
	)
	defer cancel()

	collection := usersCollection()

	// Make sure the authenticated user exists.
	var user bson.M

	err = collection.FindOne(
		ctx,
		bson.M{
			"email": email,
		},
	).Decode(&user)

	if err != nil {

		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, errors.New("user not found")
		}

		return nil, err
	}

	// Prevent one Solana wallet from being connected
	// to multiple Ganium accounts.
	var owner bson.M

	err = collection.FindOne(
		ctx,
		bson.M{
			"solana_wallet_address": walletAddress,
			"email": bson.M{
				"$ne": email,
			},
		},
	).Decode(&owner)

	if err == nil {
		return nil, errors.New(
			"this Solana wallet is already connected to another Ganium account",
		)
	}

	if !errors.Is(err, mongo.ErrNoDocuments) {
		return nil, err
	}

	now := time.Now().UTC()

	_, err = collection.UpdateOne(
		ctx,
		bson.M{
			"email": email,
		},
		bson.M{
			"$set": bson.M{
				"solana_wallet_address":      walletAddress,
				"solana_network":            network,
				"solana_wallet_connected":   true,
				"solana_wallet_connected_at": now,
				"updated_at":                now,
			},
		},
	)

	if err != nil {
		return nil, err
	}

	return &SolanaWalletResponse{
		Success:           true,
		WalletAddress:     walletAddress,
		Network:           network,
		Connected:         true,
		WalletConnectedAt: &now,
		Message:           "Solana wallet connected successfully",
	}, nil
}

// ============================================================
// DISCONNECT
// ============================================================

func DisconnectSolanaWallet(
	c *gin.Context,
) error {

	email, err := authenticatedEmail(c)

	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(
		c.Request.Context(),
		10*time.Second,
	)
	defer cancel()

	now := time.Now().UTC()

	_, err = usersCollection().UpdateOne(
		ctx,
		bson.M{
			"email": email,
		},
		bson.M{
			"$set": bson.M{
				"solana_wallet_connected": false,
				"updated_at":              now,
			},
			"$unset": bson.M{
				"solana_wallet_address":      "",
				"solana_network":             "",
				"solana_wallet_connected_at": "",
			},
		},
	)

	return err
}

// ============================================================
// STATUS
// ============================================================

func GetSolanaWalletStatus(
	c *gin.Context,
) (*SolanaWalletStatus, error) {

	email, err := authenticatedEmail(c)

	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithTimeout(
		c.Request.Context(),
		10*time.Second,
	)
	defer cancel()

	var user struct {
		SolanaWalletAddress     string     `bson:"solana_wallet_address"`
		SolanaNetwork           string     `bson:"solana_network"`
		SolanaWalletConnected   bool       `bson:"solana_wallet_connected"`
		SolanaWalletConnectedAt *time.Time `bson:"solana_wallet_connected_at"`
	}

	err = usersCollection().FindOne(
		ctx,
		bson.M{
			"email": email,
		},
	).Decode(&user)

	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, errors.New("user not found")
		}

		return nil, err
	}

	return &SolanaWalletStatus{
		Connected:     user.SolanaWalletConnected,
		WalletAddress: user.SolanaWalletAddress,
		Network:       user.SolanaNetwork,
		ConnectedAt:   user.SolanaWalletConnectedAt,
	}, nil
}

// ============================================================
// ENVIRONMENT HELPERS
// ============================================================

func SolanaRPCURL() string {
	rpc := strings.TrimSpace(
		os.Getenv("SOLANA_RPC_URL"),
	)

	if rpc == "" {
		return "https://api.mainnet-beta.solana.com"
	}

	return rpc
}

func SJLYMintAddress() string {
	return strings.TrimSpace(
		os.Getenv("SJLY_MINT_ADDRESS"),
	)
}

func SJLYTreasuryWallet() string {
	return strings.TrimSpace(
		os.Getenv("SJLY_TREASURY_WALLET"),
	)
}

func SupportedCryptoTokenSymbols() []string {
	return []string{"SJLY", "USDT", "USDC"}
}

func NormalizeCryptoTokenSymbol(token string) string {
	symbol := strings.ToUpper(strings.TrimSpace(token))
	switch symbol {
	case "USDT", "USDC", "SJLY":
		return symbol
	default:
		return "SJLY"
	}
}

func GaniumCryptoTreasuryWallet() string {
	if wallet := strings.TrimSpace(os.Getenv("GANIUM_CRYPTO_WALLET")); wallet != "" {
		return wallet
	}
	if wallet := strings.TrimSpace(os.Getenv("SJLY_TREASURY_WALLET")); wallet != "" {
		return wallet
	}
	return GaniumSolanaWallet()
}

func MintAddressForCryptoToken(token string) string {
	symbol := NormalizeCryptoTokenSymbol(token)
	switch symbol {
	case "USDT":
		return strings.TrimSpace(os.Getenv("USDT_MINT_ADDRESS"))
	case "USDC":
		return strings.TrimSpace(os.Getenv("USDC_MINT_ADDRESS"))
	default:
		return strings.TrimSpace(os.Getenv("SJLY_MINT_ADDRESS"))
	}
}

// ============================================================
// CONFIGURATION
// ============================================================

func ValidateSolanaConfiguration() error {

	if SJLYMintAddress() == "" {
		return errors.New(
			"SJLY_MINT_ADDRESS is not configured",
		)
	}

	if SJLYTreasuryWallet() == "" {
		return errors.New(
			"SJLY_TREASURY_WALLET is not configured",
		)
	}

	return nil
}

// ============================================================
// DEBUG CONFIG
// ============================================================

func SolanaConfigurationInfo() map[string]interface{} {

	return map[string]interface{}{
		"network":          solanaMainnet,
		"rpc_configured":   SolanaRPCURL() != "",
		"sjly_configured":  SJLYMintAddress() != "",
		"treasury_configured": SJLYTreasuryWallet() != "",
	}
}

// ============================================================
// NOTE
// ============================================================
//
// The actual SJLY transaction verification should NOT trust
// values coming from React Native.
//
// The backend must verify:
//
// 1. transaction signature exists
// 2. transaction is finalized
// 3. transaction sender matches connected wallet
// 4. token mint matches SJLY_MINT_ADDRESS
// 5. destination matches SJLY_TREASURY_WALLET
// 6. transferred amount matches the payment intent
// 7. payment has not already been credited
//
// Those checks belong in the crypto-payment controller once
// the exact existing payment model/controller is integrated.
// ============================================================

var _ = fmt.Sprintf