package main

import (
	_ "ganium/docs"

	"ganium/internal/config"
	"ganium/internal/investigation"
	"ganium/src/db"
	"ganium/src/middleware"
	"ganium/src/routes"
	"ganium/src/utils"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// @title Ganium API
// @version 1.0
// @description Ganium AI scam detection, security investigation, scanning, authentication and payment API.
// @termsOfService https://ganium.ai/terms
//
// @contact.name Ganium Support
// @contact.email support@ganium.ai
//
// @license.name Proprietary
//
// @host localhost:8080
// @BasePath /
//
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description JWT authentication. Enter your token using the format: Bearer <token>.
//
// @tag.name Authentication
// @tag.description User authentication and account management.
//
// @tag.name Investigation
// @tag.description Security investigation endpoints.
//
// @tag.name Scan
// @tag.description Ganium security scanning endpoints.
//
// @tag.name PDF
// @tag.description PDF report generation endpoints.
//
// @tag.name Paystack
// @tag.description Payment and subscription endpoints.
//
// @tag.name Users
// @tag.description Authenticated user profile and account management.
//
// @tag.name Wallet
// @tag.description Read-only wallet and token balance endpoints.
func main() {
	router := gin.Default()

	// Load .env
	_ = utils.LoadDotEnv(".env")

	cfg := config.LoadFromEnv()

	// Warm investigation stack so startup fails fast
	// if the environment is invalid.
	_ = investigation.Default()

	// Connect to MongoDB.
	if err := db.ConnectMongoDB(); err != nil {
		panic(err)
	}

	
	// ============================================================
	// SWAGGER
	// ============================================================

	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// ============================================================
	// PUBLIC AUTHENTICATION ROUTES
	// ============================================================

	router.POST("/register", routes.RegisterRoute)
	router.POST("/login", routes.LoginRoute)
	router.POST("/verify-otp", routes.VerifyOTPRoute)
	router.POST("/resend-otp", routes.ResendOTPRoute)
	router.POST("/forgot-password", routes.ForgotPasswordRoute)
	router.POST("/reset-password", routes.ResetPasswordRoute)

	// ============================================================
	// PAYSTACK CALLBACK
	// ============================================================

	router.GET("/api/paystack/callback", routes.PaystackCallbackRoute)

	// ============================================================
	// AUTHENTICATED ROUTES
	// ============================================================

	authGroup := router.Group("/api")
	authGroup.Use(middleware.JWTAuth())

	// Investigation
	authGroup.POST("/investigate", routes.InvestigateRoute)

	// Scanning
	authGroup.POST("/scan/basic", routes.ScanBasicRoute)
	authGroup.POST("/scan/mid", routes.ScanMidRoute)
	authGroup.POST("/scan/advance", routes.ScanAdvanceRoute)
	authGroup.POST("/scan/message", routes.ScanMessageRoute)
	authGroup.POST("/scan/url", routes.ScanURLRoute)
	authGroup.POST("/scan/wallet", routes.ScanWalletRoute)
	authGroup.POST("/scan/:scanType/pdf", routes.ScanPDFRoute)

	// User profile and wallet
	authGroup.GET("/me", routes.GetMeRoute)
	authGroup.PATCH("/me", routes.UpdateMeRoute)
	authGroup.DELETE("/me", routes.DeleteMeRoute)
	authGroup.GET("/wallet", routes.WalletRoute)
	authGroup.GET("/balance", routes.BalanceRoute)

	// PDF
	authGroup.POST("/receipt/pdf", routes.ReceiptPDFRoute)

	// Paystack
	authGroup.POST("/paystack/initialize", routes.PaystackInitializeRoute)
	authGroup.GET("/paystack/plans", routes.PaystackPlansRoute)
	authGroup.POST("/paystack/verify", routes.PaystackVerifyRoute)
	authGroup.GET("/paystack/stream", routes.PaystackPaymentStreamRoute)

	// Paystack webhook must remain public because
	// Paystack calls it directly.
	router.POST("/paystack/webhook", routes.PaystackWebhookRoute)

	// ============================================================
	// SUPER JELLY / SOLANA CRYPTO PAYMENTS
	// ============================================================

	authGroup.POST(
		"/crypto/payment/create",
		routes.CreateCryptoPaymentRoute,
	)

	authGroup.POST(
		"/crypto/payment/submit",
		routes.SubmitCryptoPaymentRoute,
	)

	authGroup.GET(
		"/crypto/payment/status",
		routes.CryptoPaymentStatusRoute,
	)

	authGroup.GET(
		"/crypto/payment/stream",
		routes.CryptoPaymentStreamRoute,
	)
	// Notifications
	authGroup.GET("/notifications", routes.GetNotificationsRoute)
	authGroup.PATCH("/notifications/:id", routes.UpdateNotificationRoute)
	authGroup.PATCH("/notifications/:id/read", routes.MarkNotificationReadRoute)
	authGroup.DELETE("/notifications/:id", routes.DeleteNotificationRoute)

	authGroup.POST(
		"/wallet/solana/connect",
		routes.ConnectSolanaWalletRoute,
	)

	authGroup.POST(
		"/wallet/solana/disconnect",
		routes.DisconnectSolanaWalletRoute,
	)

	authGroup.GET(
		"/wallet/solana/status",
		routes.SolanaWalletStatusRoute,
	)

	// ============================================================
	// START SERVER
	// ============================================================

	router.Run(cfg.Port)
}
