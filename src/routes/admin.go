package routes

import (
	"net/http"
	"strings"

	"ganium/src/controllers"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// ============================================================
// REQUEST MODELS
// ============================================================

type AdminLoginRequest struct {
	Email    string `json:"email" example:"ganium.team@gmail.com"`
	Password string `json:"password" example:"StrongPassword123!"`
}

type AdminForgotPasswordRequest struct {
	Email string `json:"email" example:"ganium.team@gmail.com"`
}

type AdminResetPasswordRequest struct {
	Email       string `json:"email" example:"ganium.team@gmail.com"`
	OTP         string `json:"otp" example:"123456"`
	NewPassword string `json:"newPassword" example:"NewPassword123!"`
}

// ============================================================
// ADMIN AUTH
// ============================================================

// AdminLoginRoute godoc
// @Summary Admin login
// @Description Authenticates an administrator and returns a JWT token.
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body AdminLoginRequest true "Admin login credentials"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /admin/login [post]
func AdminLoginRoute(c *gin.Context) {
	var payload AdminLoginRequest

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "invalid input"})
		return
	}

	ok, msg, token := controllers.AdminLogin(payload.Email, payload.Password)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"msg": msg})
		return
	}

	c.JSON(http.StatusOK, gin.H{"msg": msg, "token": token})
}

// ============================================================
// ADMIN DASHBOARD
// ============================================================

// AdminDashboardRoute godoc
// @Summary Get admin dashboard
// @Description Returns the administrator dashboard summary and alert metrics.
// @Tags Admin
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/admin/dashboard [get]
func AdminDashboardRoute(c *gin.Context) {
	dashboard, err := controllers.GetAdminDashboard()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"msg": "admin dashboard", "data": dashboard})
}

// AdminUsersRoute godoc
// @Summary List users
// @Description Returns all registered users for the platform admin.
// @Tags Admin
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/admin/users [get]
func AdminUsersRoute(c *gin.Context) {
	users, err := controllers.GetAllUsers()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"msg": "users", "data": users})
}

// AdminUserDetailRoute godoc
// @Summary Get user details
// @Description Returns the profile and account details for a single user.
// @Tags Admin
// @Produce json
// @Security BearerAuth
// @Param email path string true "User email"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/users/{email} [get]
func AdminUserDetailRoute(c *gin.Context) {
	email := strings.TrimSpace(c.Param("email"))
	if email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "email is required"})
		return
	}

	user, err := controllers.GetUserByEmail(email)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"msg": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"msg": "user", "data": user})
}

// AdminUpdateUserRoute godoc
// @Summary Update user details
// @Description Updates a user's profile data from the admin console.
// @Tags Admin
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param email path string true "User email"
// @Param request body map[string]interface{} true "User fields to update"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/admin/users/{email} [patch]
func AdminUpdateUserRoute(c *gin.Context) {
	email := strings.TrimSpace(c.Param("email"))
	if email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "email is required"})
		return
	}

	var payload bson.M
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "invalid input"})
		return
	}

	user, err := controllers.UpdateUserByEmail(email, payload)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"msg": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"msg": "user updated", "data": user})
}

// AdminDeleteUserRoute godoc
// @Summary Delete user
// @Description Deletes a user account from the admin panel.
// @Tags Admin
// @Produce json
// @Security BearerAuth
// @Param email path string true "User email"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/admin/users/{email} [delete]
func AdminDeleteUserRoute(c *gin.Context) {
	email := strings.TrimSpace(c.Param("email"))
	if email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "email is required"})
		return
	}

	if err := controllers.DeleteUserByEmail(email); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"msg": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"msg": "user deleted"})
}

// AdminAlertsRoute godoc
// @Summary Get admin alerts
// @Description Returns recent security and account alerts for the admin overview.
// @Tags Admin
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/admin/alerts [get]
func AdminAlertsRoute(c *gin.Context) {
	alerts, err := controllers.GetAdminAlerts()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"msg": "admin alerts", "data": alerts})
}

// PrivacyPolicyRoute godoc
// @Summary Get privacy policy
// @Description Returns the public privacy policy for the Ganium platform.
// @Tags Authentication
// @Produce json
// @Success 200 {object} map[string]interface{}
// @Router /privacy-policy [get]
func PrivacyPolicyRoute(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"msg":  "privacy policy",
		"data": controllers.GetPrivacyPolicy(),
	})
}

// AdminForgotPasswordRoute godoc
// @Summary Admin forgot password
// @Description Starts the password recovery process for an admin account.
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body AdminForgotPasswordRequest true "Admin email"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Router /admin/forgot-password [post]
func AdminForgotPasswordRoute(c *gin.Context) {
	var payload AdminForgotPasswordRequest
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "invalid input"})
		return
	}

	ok, msg := controllers.AdminForgotPassword(payload.Email)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"msg": msg})
		return
	}

	c.JSON(http.StatusOK, gin.H{"msg": msg})
}

// AdminResetPasswordRoute godoc
// @Summary Admin reset password
// @Description Resets an admin password using a valid OTP.
// @Tags Authentication
// @Accept json
// @Produce json
// @Param request body AdminResetPasswordRequest true "Admin reset details"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Router /admin/reset-password [post]
func AdminResetPasswordRoute(c *gin.Context) {
	var payload AdminResetPasswordRequest
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "invalid input"})
		return
	}

	ok, msg := controllers.AdminResetPassword(payload.Email, payload.OTP, payload.NewPassword)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"msg": msg})
		return
	}

	c.JSON(http.StatusOK, gin.H{"msg": msg})
}
