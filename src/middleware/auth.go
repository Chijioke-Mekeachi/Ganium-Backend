package middleware

import (
	"net/http"
	"strings"

	"ganium/src/utils"

	"github.com/gin-gonic/gin"
)

func JWTAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if header == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"msg": "missing authorization header"})
			return
		}

		tokenString := strings.TrimPrefix(header, "Bearer ")
		if tokenString == header {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"msg": "invalid authorization format"})
			return
		}

		claims, err := utils.ValidateJWT(tokenString)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"msg": "invalid or expired token"})
			return
		}

		if email, ok := claims["email"].(string); ok {
			c.Set("email", email)
		}
		if role, ok := claims["role"].(string); ok {
			c.Set("role", role)
		}
		c.Next()
	}
}

func RequireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		role := strings.ToLower(c.GetString("role"))
		if role != "admin" && role != "super_admin" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"msg": "admin access required"})
			return
		}
		c.Next()
	}
}
