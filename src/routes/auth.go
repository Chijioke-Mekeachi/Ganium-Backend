package routes

import (
	"net/http"

	"ganium/src/controllers"
	"ganium/src/models"

	"github.com/gin-gonic/gin"
)

func RegisterRoute(c *gin.Context) {
	var userData models.Register
	if err := c.ShouldBindJSON(&userData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "invalid input"})
		return
	}

	ok, msg := controllers.RegisterUser(userData)
	status := http.StatusOK
	if !ok {
		status = http.StatusBadRequest
	}

	c.JSON(status, gin.H{"msg": msg})
}

func LoginRoute(c *gin.Context) {
	var userData models.Login
	if err := c.ShouldBindJSON(&userData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "invalid input"})
		return
	}

	ok, msg, token := controllers.LoginUser(userData)
	status := http.StatusOK
	if !ok {
		status = http.StatusUnauthorized
		c.JSON(status, gin.H{"msg": msg})
		return
	}

	c.JSON(status, gin.H{"msg": msg, "token": token})
}

func VerifyOTPRoute(c *gin.Context) {
	var payload struct {
		Email string `json:"email"`
		OTP   string `json:"otp"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "invalid input"})
		return
	}
	ok, msg := controllers.VerifyOTP(payload.Email, payload.OTP)
	status := http.StatusOK
	if !ok {
		status = http.StatusBadRequest
	}
	c.JSON(status, gin.H{"msg": msg})
}

func ResendOTPRoute(c *gin.Context) {
	var payload struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "invalid input"})
		return
	}
	ok, msg := controllers.ResendOTP(payload.Email)
	status := http.StatusOK
	if !ok {
		status = http.StatusBadRequest
	}
	c.JSON(status, gin.H{"msg": msg})
}

// ResendOTPAuthRoute resends OTP for the authenticated user (reads email from context)
func ResendOTPAuthRoute(c *gin.Context) {
	email := c.GetString("email")
	if email == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"msg": "unauthorized"})
		return
	}
	ok, msg := controllers.ResendOTP(email)
	status := http.StatusOK
	if !ok {
		status = http.StatusBadRequest
	}
	c.JSON(status, gin.H{"msg": msg})
}

func ForgotPasswordRoute(c *gin.Context) {
	var payload struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "invalid input"})
		return
	}
	ok, msg := controllers.ForgotPassword(payload.Email)
	status := http.StatusOK
	if !ok {
		status = http.StatusBadRequest
	}
	c.JSON(status, gin.H{"msg": msg})
}

func ResetPasswordRoute(c *gin.Context) {
	var payload struct {
		Email       string `json:"email"`
		Token       string `json:"token"`
		NewPassword string `json:"newPassword"`
	}
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "invalid input"})
		return
	}
	ok, msg := controllers.ResetPassword(payload.Email, payload.Token, payload.NewPassword)
	status := http.StatusOK
	if !ok {
		status = http.StatusBadRequest
	}
	c.JSON(status, gin.H{"msg": msg})
}
