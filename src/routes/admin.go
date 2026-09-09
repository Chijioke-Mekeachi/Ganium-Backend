package routes

import (
	"net/http"
	"strings"

	"ganium/src/controllers"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/v2/bson"
)

func AdminLoginRoute(c *gin.Context) {
	var payload struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

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

func AdminDashboardRoute(c *gin.Context) {
	dashboard, err := controllers.GetAdminDashboard()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"msg": "admin dashboard", "data": dashboard})
}

func AdminUsersRoute(c *gin.Context) {
	users, err := controllers.GetAllUsers()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"msg": "users", "data": users})
}

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

func AdminAlertsRoute(c *gin.Context) {
	alerts, err := controllers.GetAdminAlerts()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"msg": "admin alerts", "data": alerts})
}

func PrivacyPolicyRoute(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"msg":  "privacy policy",
		"data": controllers.GetPrivacyPolicy(),
	})
}

func AdminForgotPasswordRoute(c *gin.Context) {
	var payload struct {
		Email string `json:"email"`
	}
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

func AdminResetPasswordRoute(c *gin.Context) {
	var payload struct {
		Email       string `json:"email"`
		OTP         string `json:"otp"`
		NewPassword string `json:"newPassword"`
	}
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