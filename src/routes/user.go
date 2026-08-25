package routes

import (
	"net/http"

	"ganium/src/controllers"
	"ganium/src/models"

	"github.com/gin-gonic/gin"
)

// ============================================================
// USER PROFILE
// ============================================================

// GetMeRoute godoc
// @Summary Get current user profile
// @Description Returns the authenticated user's profile, token counts, and wallet balance.
// @Tags Users
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.UserProfileResponse
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/me [get]
func GetMeRoute(c *gin.Context) {
	email := c.GetString("email")
	if email == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"msg": "unauthorized"})
		return
	}

	profile, err := controllers.GetCurrentUserProfile(email)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"msg": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"msg":  "profile",
		"data": profile,
	})
}

// UpdateMeRoute godoc
// @Summary Update current user profile
// @Description Updates editable profile fields for the authenticated user.
// @Tags Users
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body models.UserProfileUpdateRequest true "Profile update"
// @Success 200 {object} models.UserProfileResponse
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/me [patch]
func UpdateMeRoute(c *gin.Context) {
	email := c.GetString("email")
	if email == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"msg": "unauthorized"})
		return
	}

	var payload models.UserProfileUpdateRequest
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "invalid input"})
		return
	}

	profile, err := controllers.UpdateCurrentUserProfile(email, payload)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"msg": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"msg":  "profile updated",
		"data": profile,
	})
}

// DeleteMeRoute godoc
// @Summary Delete current user account
// @Description Deletes the authenticated user's account and related scans and payment history.
// @Tags Users
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/me [delete]
func DeleteMeRoute(c *gin.Context) {
	email := c.GetString("email")
	if email == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"msg": "unauthorized"})
		return
	}

	if err := controllers.DeleteCurrentUser(email); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"msg": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"msg": "account deleted",
	})
}

// ============================================================
// WALLET
// ============================================================

// WalletRoute godoc
// @Summary Get wallet summary
// @Description Returns the authenticated user's token balance and wallet value. This endpoint is read-only.
// @Tags Wallet
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.WalletSummary
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/wallet [get]
func WalletRoute(c *gin.Context) {
	email := c.GetString("email")
	if email == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"msg": "unauthorized"})
		return
	}

	wallet, err := controllers.GetWalletSummary(email)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"msg": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"msg":  "wallet",
		"data": wallet,
	})
}

// BalanceRoute godoc
// @Summary Get balance and pricing
// @Description Returns the current wallet balance together with the token pricing plans. The base plan is $1 for 10 tokens.
// @Tags Wallet
// @Produce json
// @Security BearerAuth
// @Success 200 {object} models.BalanceSummary
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/balance [get]
func BalanceRoute(c *gin.Context) {
	email := c.GetString("email")
	if email == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"msg": "unauthorized"})
		return
	}

	balance, err := controllers.GetBalanceSummary(email)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"msg": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"msg":  "balance",
		"data": balance,
	})
}
// ============================================================
// SOLANA WALLET CONNECT
// ============================================================

type ConnectSolanaWalletRequest struct {
	WalletAddress string `json:"wallet_address"`
	Network       string `json:"network"`
}

// ConnectSolanaWalletRoute godoc
// @Summary Connect Solana wallet
// @Description Connects the authenticated user's Solana wallet.
// @Tags Wallet
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body ConnectSolanaWalletRequest true "Solana wallet"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 409 {object} map[string]string
// @Router /api/wallet/solana/connect [post]
func ConnectSolanaWalletRoute(c *gin.Context) {

	if c.GetString("email") == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"msg": "unauthorized",
		})
		return
	}

	var payload ConnectSolanaWalletRequest

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "invalid input",
		})
		return
	}

	result, err := controllers.ConnectSolanaWallet(
		c,
		payload.WalletAddress,
		payload.Network,
	)

	if err != nil {

		status := http.StatusBadRequest

		if err.Error() ==
			"this Solana wallet is already connected to another Ganium account" {
			status = http.StatusConflict
		}

		if err.Error() == "unauthorized" {
			status = http.StatusUnauthorized
		}

		c.JSON(status, gin.H{
			"msg": err.Error(),
		})

		return
	}

	c.JSON(http.StatusOK, gin.H{
		"msg":  "wallet connected",
		"data": result,
	})
}

// ============================================================
// SOLANA WALLET DISCONNECT
// ============================================================

// DisconnectSolanaWalletRoute godoc
// @Summary Disconnect Solana wallet
// @Description Disconnects the authenticated user's Solana wallet.
// @Tags Wallet
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]string
// @Router /api/wallet/solana/disconnect [post]
func DisconnectSolanaWalletRoute(c *gin.Context) {

	if c.GetString("email") == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"msg": "unauthorized",
		})
		return
	}

	if err := controllers.DisconnectSolanaWallet(c); err != nil {

		if err.Error() == "unauthorized" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"msg": err.Error(),
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "failed to disconnect wallet",
		})

		return
	}

	c.JSON(http.StatusOK, gin.H{
		"msg": "wallet disconnected",
		"data": gin.H{
			"connected": false,
		},
	})
}

// ============================================================
// SOLANA WALLET STATUS
// ============================================================

// SolanaWalletStatusRoute godoc
// @Summary Get Solana wallet status
// @Description Returns the authenticated user's connected Solana wallet.
// @Tags Wallet
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/wallet/solana/status [get]
func SolanaWalletStatusRoute(c *gin.Context) {

	if c.GetString("email") == "" {
		c.JSON(http.StatusUnauthorized, gin.H{
			"msg": "unauthorized",
		})
		return
	}

	status, err := controllers.GetSolanaWalletStatus(c)

	if err != nil {

		if err.Error() == "unauthorized" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"msg": err.Error(),
			})
			return
		}

		if err.Error() == "user not found" {
			c.JSON(http.StatusNotFound, gin.H{
				"msg": err.Error(),
			})
			return
		}

		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "failed to get wallet status",
		})

		return
	}

	c.JSON(http.StatusOK, gin.H{
		"msg":  "wallet status",
		"data": status,
	})
}
