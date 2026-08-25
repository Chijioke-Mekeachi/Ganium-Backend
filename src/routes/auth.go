package routes

import (
	"net/http"

	"ganium/src/controllers"
	"ganium/src/models"

	"github.com/gin-gonic/gin"
)

// ============================================================
// REQUEST MODELS
// ============================================================

// VerifyOTPRequest represents an OTP verification request.
type VerifyOTPRequest struct {
	Email string `json:"email" example:"user@example.com"`
	OTP   string `json:"otp" example:"123456"`
}

// ResendOTPRequest represents an OTP resend request.
type ResendOTPRequest struct {
	Email string `json:"email" example:"user@example.com"`
}

// ForgotPasswordRequest represents a forgot-password request.
type ForgotPasswordRequest struct {
	Email string `json:"email" example:"user@example.com"`
}

// ResetPasswordRequest represents a password reset request.
type ResetPasswordRequest struct {
	Email       string `json:"email" example:"user@example.com"`
	Token       string `json:"token" example:"reset-token"`
	NewPassword string `json:"newPassword" example:"NewPassword123!"`
}

// ============================================================
// REGISTER
// ============================================================

// RegisterRoute godoc
// @Summary Register a new user
// @Description Creates a new Ganium user account.
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body models.RegisterRequest true "Registration details"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Router /register [post]
func RegisterRoute(c *gin.Context) {
	var payload models.RegisterRequest

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "invalid input",
		})
		return
	}

	ok, msg := controllers.RegisterUser(models.Register{
		Email:    payload.Email,
		Password: payload.Password,
		FullName: payload.FullName,
	})

	status := http.StatusOK

	if !ok {
		status = http.StatusBadRequest
	}

	c.JSON(status, gin.H{
		"msg": msg,
	})
}

// ============================================================
// LOGIN
// ============================================================

// LoginRoute godoc
// @Summary Login
// @Description Authenticates a Ganium user and returns a JWT token.
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body models.Login true "Login credentials"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /login [post]
func LoginRoute(c *gin.Context) {
	var userData models.Login

	if err := c.ShouldBindJSON(&userData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "invalid input",
		})
		return
	}

	ok, msg, token := controllers.LoginUser(userData)

	status := http.StatusOK

	if !ok {
		status = http.StatusUnauthorized

		c.JSON(status, gin.H{
			"msg": msg,
		})

		return
	}

	c.JSON(status, gin.H{
		"msg":   msg,
		"token": token,
	})
}

// ============================================================
// VERIFY OTP
// ============================================================

// VerifyOTPRoute godoc
// @Summary Verify OTP
// @Description Verifies the OTP sent to a user's email address.
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body VerifyOTPRequest true "OTP verification details"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Router /verify-otp [post]
func VerifyOTPRoute(c *gin.Context) {
	var payload VerifyOTPRequest

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "invalid input",
		})
		return
	}

	ok, msg := controllers.VerifyOTP(
		payload.Email,
		payload.OTP,
	)

	status := http.StatusOK

	if !ok {
		status = http.StatusBadRequest
	}

	c.JSON(status, gin.H{
		"msg": msg,
	})
}

// ============================================================
// RESEND OTP
// ============================================================

// ResendOTPRoute godoc
// @Summary Resend OTP
// @Description Resends a verification OTP to the specified email address.
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body ResendOTPRequest true "Email address"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Router /resend-otp [post]
func ResendOTPRoute(c *gin.Context) {
	var payload ResendOTPRequest

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "invalid input",
		})
		return
	}

	ok, msg := controllers.ResendOTP(payload.Email)

	status := http.StatusOK

	if !ok {
		status = http.StatusBadRequest
	}

	c.JSON(status, gin.H{
		"msg": msg,
	})
}

// ============================================================
// FORGOT PASSWORD
// ============================================================

// ForgotPasswordRoute godoc
// @Summary Forgot password
// @Description Starts the password recovery process for a user.
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body ForgotPasswordRequest true "Email address"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Router /forgot-password [post]
func ForgotPasswordRoute(c *gin.Context) {
	var payload ForgotPasswordRequest

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "invalid input",
		})
		return
	}

	ok, msg := controllers.ForgotPassword(payload.Email)

	status := http.StatusOK

	if !ok {
		status = http.StatusBadRequest
	}

	c.JSON(status, gin.H{
		"msg": msg,
	})
}

// ============================================================
// RESET PASSWORD
// ============================================================

// ResetPasswordRoute godoc
// @Summary Reset password
// @Description Resets a user's password using a valid reset token.
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body ResetPasswordRequest true "Password reset details"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Router /reset-password [post]
func ResetPasswordRoute(c *gin.Context) {
	var payload ResetPasswordRequest

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "invalid input",
		})
		return
	}

	ok, msg := controllers.ResetPassword(
		payload.Email,
		payload.Token,
		payload.NewPassword,
	)

	status := http.StatusOK

	if !ok {
		status = http.StatusBadRequest
	}

	c.JSON(status, gin.H{
		"msg": msg,
	})
}
