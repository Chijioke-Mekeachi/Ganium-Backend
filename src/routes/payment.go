package routes

import (
	"net/http"

	"ganium/src/controllers"
	"ganium/src/models"

	"github.com/gin-gonic/gin"
)

func PaystackInitializeRoute(c *gin.Context) {
	email := c.GetString("email")
	var payload models.PaystackInitializeRequest
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "invalid input"})
		return
	}

	result, msg, err := controllers.InitializePaystackPayment(email, payload)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"msg": msg})
		return
	}
	c.JSON(http.StatusOK, gin.H{"msg": msg, "data": result})
}

