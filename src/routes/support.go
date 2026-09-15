package routes

import (
	"errors"
	"net/http"
	"strings"

	"ganium/src/controllers"
	"ganium/src/models"

	"github.com/gin-gonic/gin"
)

// ============================================================
// USER SUPPORT ROUTES
// ============================================================

// CreateSupportConversationRoute godoc
// @Summary Create a support conversation
// @Description Creates a new support conversation for the authenticated user and stores the initial message.
// @Tags Support
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body models.CreateSupportConversationRequest true "Support conversation details"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/support/conversations [post]
func CreateSupportConversationRoute(c *gin.Context) {
	email := c.GetString("email")
	if email == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"msg": "unauthorized"})
		return
	}
	var payload models.CreateSupportConversationRequest
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "invalid input"})
		return
	}
	conversation, message, err := controllers.CreateSupportConversation(email, payload)
	if err != nil {
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, controllers.ErrSupportUnauthorized):
			status = http.StatusUnauthorized
		case errors.Is(err, controllers.ErrSupportForbidden):
			status = http.StatusForbidden
		case strings.Contains(err.Error(), "not found"):
			status = http.StatusNotFound
		}
		c.JSON(status, gin.H{"msg": controllers.FormatSupportError(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"msg": "support conversation created", "data": gin.H{"conversation": conversation, "message": message}})
}

// GetSupportConversationsRoute godoc
// @Summary List customer support conversations
// @Description Returns the authenticated user's support conversations with pagination.
// @Tags Support
// @Produce json
// @Security BearerAuth
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Page size" default(20)
// @Success 200 {object} models.SupportConversationListResponse
// @Failure 401 {object} map[string]string
// @Router /api/support/conversations [get]
func GetSupportConversationsRoute(c *gin.Context) {
	email := c.GetString("email")
	if email == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"msg": "unauthorized"})
		return
	}
	page := controllers.SupportQueryParamInt(c.Query("page"), 1)
	limit := controllers.SupportQueryParamInt(c.Query("limit"), 20)
	conversations, total, err := controllers.GetUserSupportConversations(email, page, limit)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"msg": controllers.FormatSupportError(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"msg": "support conversations", "data": gin.H{"conversations": conversations, "page": page, "limit": limit, "total": total}})
}

// GetSupportConversationRoute godoc
// @Summary Get a conversation
// @Description Returns a single support conversation owned by the authenticated user.
// @Tags Support
// @Produce json
// @Security BearerAuth
// @Param conversationId path string true "Conversation ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/support/conversations/{conversationId} [get]
func GetSupportConversationRoute(c *gin.Context) {
	email := c.GetString("email")
	if email == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"msg": "unauthorized"})
		return
	}
	conversation, err := controllers.GetSupportConversationForUser(email, c.Param("conversationId"))
	if err != nil {
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, controllers.ErrSupportForbidden):
			status = http.StatusForbidden
		case errors.Is(err, controllers.ErrSupportConversationNotFound):
			status = http.StatusNotFound
		case errors.Is(err, controllers.ErrInvalidSupportConversationID):
			status = http.StatusBadRequest
		}
		c.JSON(status, gin.H{"msg": controllers.FormatSupportError(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"msg": "conversation", "data": conversation})
}

// GetSupportConversationMessagesRoute godoc
// @Summary Get messages in a conversation
// @Description Returns all messages in the authenticated user's conversation.
// @Tags Support
// @Produce json
// @Security BearerAuth
// @Param conversationId path string true "Conversation ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/support/conversations/{conversationId}/messages [get]
func GetSupportConversationMessagesRoute(c *gin.Context) {
	email := c.GetString("email")
	if email == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"msg": "unauthorized"})
		return
	}
	messages, err := controllers.GetSupportConversationMessagesForUser(email, c.Param("conversationId"))
	if err != nil {
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, controllers.ErrSupportForbidden):
			status = http.StatusForbidden
		case errors.Is(err, controllers.ErrSupportConversationNotFound):
			status = http.StatusNotFound
		}
		c.JSON(status, gin.H{"msg": controllers.FormatSupportError(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"msg": "messages", "data": messages})
}

// SendSupportMessageRoute godoc
// @Summary Send a message in a support conversation
// @Description Sends a new message from the authenticated user into their support conversation.
// @Tags Support
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param conversationId path string true "Conversation ID"
// @Param request body models.SupportMessageRequest true "Message details"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/support/conversations/{conversationId}/messages [post]
func SendSupportMessageRoute(c *gin.Context) {
	email := c.GetString("email")
	if email == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"msg": "unauthorized"})
		return
	}
	var payload models.SupportMessageRequest
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "invalid input"})
		return
	}
	message, err := controllers.SendSupportMessage(email, c.Param("conversationId"), payload)
	if err != nil {
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, controllers.ErrSupportForbidden):
			status = http.StatusForbidden
		case errors.Is(err, controllers.ErrSupportConversationNotFound):
			status = http.StatusNotFound
		}
		c.JSON(status, gin.H{"msg": controllers.FormatSupportError(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"msg": "message sent", "data": message})
}

// CloseSupportConversationRoute godoc
// @Summary Close a support conversation
// @Description Closes the authenticated user's support conversation.
// @Tags Support
// @Produce json
// @Security BearerAuth
// @Param conversationId path string true "Conversation ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/support/conversations/{conversationId}/close [post]
func CloseSupportConversationRoute(c *gin.Context) {
	email := c.GetString("email")
	if email == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"msg": "unauthorized"})
		return
	}
	conversation, err := controllers.CloseSupportConversation(email, c.Param("conversationId"))
	if err != nil {
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, controllers.ErrSupportForbidden):
			status = http.StatusForbidden
		case errors.Is(err, controllers.ErrSupportConversationNotFound):
			status = http.StatusNotFound
		}
		c.JSON(status, gin.H{"msg": controllers.FormatSupportError(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"msg": "conversation closed", "data": conversation})
}

// ============================================================
// ADMIN SUPPORT ROUTES
// ============================================================

// AdminListSupportConversationsRoute godoc
// @Summary List support conversations for admins
// @Description Returns customer support conversations with optional filters for status, customer, assignment, date, and search.
// @Tags Support
// @Produce json
// @Security BearerAuth
// @Param status query string false "Status"
// @Param customer query string false "Customer email or user ID"
// @Param assignedTo query string false "Assigned support user ID"
// @Param date query string false "Date filter in RFC3339 format"
// @Param search query string false "Search text"
// @Param page query int false "Page number" default(1)
// @Param limit query int false "Page size" default(20)
// @Success 200 {object} models.SupportConversationListResponse
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Router /api/admin/support/conversations [get]
func AdminListSupportConversationsRoute(c *gin.Context) {
	email := c.GetString("email")
	if email == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"msg": "unauthorized"})
		return
	}
	page := controllers.SupportQueryParamInt(c.Query("page"), 1)
	limit := controllers.SupportQueryParamInt(c.Query("limit"), 20)
	conversations, total, err := controllers.AdminListSupportConversations(email, page, limit, c.Query("status"), c.Query("customer"), c.Query("assignedTo"), c.Query("search"), c.Query("date"))
	if err != nil {
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, controllers.ErrSupportForbidden):
			status = http.StatusForbidden
		case errors.Is(err, controllers.ErrSupportConversationNotFound):
			status = http.StatusNotFound
		}
		c.JSON(status, gin.H{"msg": controllers.FormatSupportError(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"msg": "support conversations", "data": gin.H{"conversations": conversations, "page": page, "limit": limit, "total": total}})
}

// AdminGetSupportConversationRoute godoc
// @Summary Get a conversation for admin support
// @Description Returns a specific support conversation and its messages to an authorized support/admin user.
// @Tags Support
// @Produce json
// @Security BearerAuth
// @Param conversationId path string true "Conversation ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/support/conversations/{conversationId} [get]
func AdminGetSupportConversationRoute(c *gin.Context) {
	email := c.GetString("email")
	if email == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"msg": "unauthorized"})
		return
	}
	conversation, messages, err := controllers.GetAdminSupportConversation(email, c.Param("conversationId"))
	if err != nil {
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, controllers.ErrSupportForbidden):
			status = http.StatusForbidden
		case errors.Is(err, controllers.ErrSupportConversationNotFound):
			status = http.StatusNotFound
		}
		c.JSON(status, gin.H{"msg": controllers.FormatSupportError(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"msg": "conversation", "data": gin.H{"conversation": conversation, "messages": messages}})
}

// AdminSendSupportReplyRoute godoc
// @Summary Reply to a support conversation
// @Description Allows an admin/support user to reply to a customer message in the conversation.
// @Tags Support
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param conversationId path string true "Conversation ID"
// @Param request body models.SupportMessageRequest true "Message details"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/support/conversations/{conversationId}/messages [post]
func AdminSendSupportReplyRoute(c *gin.Context) {
	email := c.GetString("email")
	if email == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"msg": "unauthorized"})
		return
	}
	var payload models.SupportMessageRequest
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "invalid input"})
		return
	}
	message, err := controllers.SendAdminSupportReply(email, c.Param("conversationId"), payload)
	if err != nil {
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, controllers.ErrSupportForbidden):
			status = http.StatusForbidden
		case errors.Is(err, controllers.ErrSupportConversationNotFound):
			status = http.StatusNotFound
		}
		c.JSON(status, gin.H{"msg": controllers.FormatSupportError(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"msg": "reply sent", "data": message})
}

// AdminUpdateSupportConversationRoute godoc
// @Summary Update support conversation details
// @Description Allows admins/support users to update conversation status or assignment.
// @Tags Support
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param conversationId path string true "Conversation ID"
// @Param request body models.SupportConversationUpdateRequest true "Conversation update"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/admin/support/conversations/{conversationId} [patch]
func AdminUpdateSupportConversationRoute(c *gin.Context) {
	email := c.GetString("email")
	if email == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"msg": "unauthorized"})
		return
	}
	var payload models.SupportConversationUpdateRequest
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "invalid input"})
		return
	}
	conversation, err := controllers.UpdateSupportConversationByAdmin(email, c.Param("conversationId"), payload)
	if err != nil {
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, controllers.ErrSupportForbidden):
			status = http.StatusForbidden
		case errors.Is(err, controllers.ErrSupportConversationNotFound):
			status = http.StatusNotFound
		}
		c.JSON(status, gin.H{"msg": controllers.FormatSupportError(err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{"msg": "conversation updated", "data": conversation})
}
