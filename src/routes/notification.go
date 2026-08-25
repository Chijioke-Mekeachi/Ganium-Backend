package routes

import (
	"net/http"

	"ganium/src/controllers"
	"ganium/src/models"

	"github.com/gin-gonic/gin"
)

// ============================================================
// NOTIFICATIONS
// ============================================================

// GetNotificationsRoute godoc
// @Summary List notifications
// @Description Returns all notifications belonging to the authenticated user, newest first.
// @Tags Notifications
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/notifications [get]
func GetNotificationsRoute(c *gin.Context) {
	email := c.GetString("email")
	if email == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"msg": "unauthorized"})
		return
	}

	notifications, err := controllers.GetNotifications(email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"msg":  "notifications",
		"data": notifications,
	})
}

// DeleteNotificationRoute godoc
// @Summary Delete a notification
// @Description Deletes a single notification belonging to the authenticated user.
// @Tags Notifications
// @Produce json
// @Security BearerAuth
// @Param id path string true "Notification ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/notifications/{id} [delete]
func DeleteNotificationRoute(c *gin.Context) {
	email := c.GetString("email")
	if email == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"msg": "unauthorized"})
		return
	}

	id := c.Param("id")

	if err := controllers.DeleteNotification(email, id); err != nil {
		status := http.StatusNotFound
		if err.Error() == "invalid notification id" {
			status = http.StatusBadRequest
		}
		c.JSON(status, gin.H{"msg": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"msg": "notification deleted"})
}

// UpdateNotificationRoute godoc
// @Summary Update a notification
// @Description Updates editable fields on a notification belonging to the authenticated user.
// @Tags Notifications
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param id path string true "Notification ID"
// @Param request body models.NotificationUpdateRequest true "Notification update"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/notifications/{id} [patch]
func UpdateNotificationRoute(c *gin.Context) {
	email := c.GetString("email")
	if email == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"msg": "unauthorized"})
		return
	}

	id := c.Param("id")

	var payload models.NotificationUpdateRequest
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "invalid input"})
		return
	}

	notification, err := controllers.UpdateNotification(email, id, payload)
	if err != nil {
		status := http.StatusNotFound
		if err.Error() == "invalid notification id" {
			status = http.StatusBadRequest
		}
		c.JSON(status, gin.H{"msg": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"msg":  "notification updated",
		"data": notification,
	})
}

// MarkNotificationReadRoute godoc
// @Summary Mark a notification as read
// @Description Marks a single notification as read for the authenticated user.
// @Tags Notifications
// @Produce json
// @Security BearerAuth
// @Param id path string true "Notification ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/notifications/{id}/read [patch]
func MarkNotificationReadRoute(c *gin.Context) {
	email := c.GetString("email")
	if email == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"msg": "unauthorized"})
		return
	}

	id := c.Param("id")

	notification, err := controllers.MarkNotificationAsRead(email, id)
	if err != nil {
		status := http.StatusNotFound
		if err.Error() == "invalid notification id" {
			status = http.StatusBadRequest
		}
		c.JSON(status, gin.H{"msg": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"msg":  "notification marked as read",
		"data": notification,
	})
}