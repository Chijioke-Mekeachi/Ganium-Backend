package main

import (
	_ "ganium/docs"
	"ganium/src/db"
	"ganium/src/middleware"
	"ganium/src/routes"
	"ganium/src/utils"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

func main() {
	router := gin.Default()

	// load .env file so SMTP_USER/SMTP_PASS from backend/.env are available
	_ = utils.LoadDotEnv(".env")

	err := db.ConnectMongoDB()
	if err != nil {
		panic(err)
	}

	router.POST("/register", routes.RegisterRoute)
	router.POST("/login", routes.LoginRoute)
	router.POST("/verify-otp", routes.VerifyOTPRoute)
	router.POST("/resend-otp", routes.ResendOTPRoute)
	router.POST("/forgot-password", routes.ForgotPasswordRoute)
	router.POST("/reset-password", routes.ResetPasswordRoute)
	router.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	authGroup := router.Group("/api")
	authGroup.Use(middleware.JWTAuth())
	authGroup.POST("/resend-otp", routes.ResendOTPAuthRoute)
	authGroup.POST("/scan/basic", routes.ScanBasicRoute)
	authGroup.POST("/scan/mid", routes.ScanMidRoute)
	authGroup.POST("/scan/advance", routes.ScanAdvanceRoute)
	authGroup.POST("/scan/message", routes.ScanMessageRoute)
	authGroup.POST("/scan/url", routes.ScanURLRoute)
	authGroup.POST("/scan/wallet", routes.ScanWalletRoute)
	authGroup.POST("/scan/:scanType/pdf", routes.ScanPDFRoute)
	authGroup.POST("/receipt/pdf", routes.ReceiptPDFRoute)
	authGroup.POST("/paystack/initialize", routes.PaystackInitializeRoute)
	authGroup.GET("/me", func(c *gin.Context) {
		c.JSON(200, gin.H{"msg": "protected route", "email": c.GetString("email")})
	})

	router.Run(":8008")
}
