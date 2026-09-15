package routes

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"ganium/src/controllers"

	"github.com/gin-gonic/gin"
)

// ============================================================
// REQUEST MODELS
// ============================================================

type PaystackInitializeRequest struct {
	Plan           string `json:"plan" example:"pro"`
	PlanCode       string `json:"plan_code" example:"pro"`
	PlanCodeCamel  string `json:"planCode" example:"pro"`
	PlanName       string `json:"planName" example:"Pro"`
	Reference      string `json:"reference" example:"GANIUM-123456"`
	CallbackURL    string `json:"callback_url" example:"https://app.ganium.ai/payment/callback"`
	CallbackURLAlt string `json:"callbackUrl" example:"https://app.ganium.ai/payment/callback"`
	Callback       string `json:"callback" example:"https://app.ganium.ai/payment/callback"`
	Mode           string `json:"mode" example:"hosted"`
}

type PaystackVerifyRequest struct {
	Reference string `json:"reference" example:"GANIUM-123456"`
}

// ============================================================
// SOLANA / SJLY REQUEST MODELS
// ============================================================

// CreateCryptoPaymentRequest creates a new crypto payment intent for SJLY, USDT, or USDC.
type CreateCryptoPaymentRequest struct {
	Plan  string `json:"plan" example:"pro"`
	Token string `json:"token,omitempty" example:"USDT"`
}

// SubmitCryptoPaymentRequest submits the Solana transaction
// signature after the user signs the transaction in their wallet.
type SubmitCryptoPaymentRequest struct {
	PaymentID  string `json:"payment_id" example:"GAN-SJLY-123456789"`
	Signature  string `json:"signature" example:"5abc123..."`
	UserWallet string `json:"user_wallet" example:"7abc123..."`
}

// ============================================================
// PAYSTACK INITIALIZE
// ============================================================

// PaystackInitializeRoute godoc
// @Summary Initialize Paystack payment
// @Description Initializes a Paystack payment transaction.
// @Tags Paystack
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body PaystackInitializeRequest true "Payment initialization"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/paystack/initialize [post]
func PaystackInitializeRoute(c *gin.Context) {

	email := c.GetString("email")

	var payload PaystackInitializeRequest

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "invalid input",
		})
		return
	}

	planCode := controllers.NormalizePaymentPlanInput(
		payload.Plan,
		payload.PlanCode,
		payload.PlanCodeCamel,
		payload.PlanName,
	)

	if planCode == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "plan is required",
		})
		return
	}

	callbackURL := controllers.NormalizePaymentPlanInput(
		payload.CallbackURL,
		payload.CallbackURLAlt,
		payload.Callback,
	)

	result, msg, err := controllers.InitializePaymentForPlan(
		email,
		planCode,
		payload.Reference,
		callbackURL,
		payload.Mode,
	)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": msg,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"msg":  msg,
		"data": result,
	})
}

// ============================================================
// PAYMENT PLANS
// ============================================================

// PaystackPlansRoute godoc
// @Summary Get payment plans
// @Description Returns available Ganium subscription plans.
// @Tags Paystack
// @Produce json
// @Security BearerAuth
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]string
// @Router /api/paystack/plans [get]
func PaystackPlansRoute(c *gin.Context) {

	c.JSON(http.StatusOK, gin.H{
		"msg":  "payment plans",
		"data": controllers.GetPaymentPlans(),
	})
}

// ============================================================
// PAYSTACK VERIFY
// ============================================================

// PaystackVerifyRoute godoc
// @Summary Verify Paystack payment
// @Description Verifies a Paystack transaction and credits the user's account.
// @Tags Paystack
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body PaystackVerifyRequest false "Payment verification request"
// @Param reference query string false "Payment reference"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 403 {object} map[string]string
// @Router /api/paystack/verify [post]
func PaystackVerifyRoute(c *gin.Context) {

	email := c.GetString("email")

	var payload PaystackVerifyRequest

	if err := c.ShouldBindJSON(&payload); err != nil {
		// Reference may also be supplied through query parameters.
		_ = err
	}

	if payload.Reference == "" {
		payload.Reference = c.Query("reference")
	}

	if payload.Reference == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "reference is required",
		})
		return
	}

	history, err := controllers.GetPaymentHistory(
		payload.Reference,
	)

	if err == nil {

		if history.Email != "" &&
			!strings.EqualFold(history.Email, email) {

			c.JSON(http.StatusForbidden, gin.H{
				"msg": "payment does not belong to authenticated user",
			})

			return
		}
	}

	result, msg, err := controllers.VerifyPaymentAndCredit(
		payload.Reference,
	)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": msg,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"msg":  msg,
		"data": result,
	})
}

// ============================================================
// PAYSTACK WEBHOOK
// ============================================================

// PaystackWebhookRoute godoc
// @Summary Paystack webhook
// @Description Receives and verifies Paystack webhook events.
// @Tags Paystack
// @Accept json
// @Produce json
// @Param x-paystack-signature header string true "Paystack webhook signature"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /paystack/webhook [post]
func PaystackWebhookRoute(c *gin.Context) {

	signature := c.GetHeader(
		"x-paystack-signature",
	)

	raw, err := c.GetRawData()

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "failed to read webhook body",
		})
		return
	}

	secret := controllers.PaystackSecret()

	if secret == "" ||
		!controllers.VerifyPaystackSignature(
			secret,
			string(raw),
			signature,
		) {

		c.JSON(http.StatusUnauthorized, gin.H{
			"msg": "invalid signature",
		})
		return
	}

	var payload struct {
		Event string `json:"event"`

		Data struct {
			Reference string `json:"reference"`
		} `json:"data"`
	}

	if err := json.Unmarshal(
		raw,
		&payload,
	); err != nil {

		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "invalid webhook payload",
		})
		return
	}

	if payload.Data.Reference == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "missing reference",
		})
		return
	}

	result, msg, err := controllers.VerifyPaymentAndCredit(
		payload.Data.Reference,
	)

	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": msg,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"msg":   "webhook processed",
		"data":  result,
		"event": payload.Event,
	})
}

// ============================================================
// PAYSTACK CALLBACK
// ============================================================

// PaystackCallbackRoute godoc
// @Summary Paystack callback
// @Description Handles Paystack payment callback.
// @Tags Paystack
// @Produce json
// @Param reference query string true "Paystack transaction reference"
// @Param status query string false "Payment status"
// @Success 302
// @Failure 400 {object} map[string]string
// @Router /api/paystack/callback [get]
func PaystackCallbackRoute(c *gin.Context) {

	reference := c.Query("reference")
	status := c.Query("status")

	if reference == "" {

		var payload struct {
			Reference string `json:"reference"`
			Status    string `json:"status"`
		}

		if err := c.ShouldBindJSON(
			&payload,
		); err == nil {

			reference = payload.Reference

			if status == "" {
				status = payload.Status
			}
		}
	}

	if reference == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "reference is required",
		})
		return
	}

	if status == "" {
		status = "success"
	}

	redirectTo := controllers.BuildAppPaymentRedirect(
		reference,
		status,
	)

	if u, err := url.Parse(
		redirectTo,
	); err == nil {

		c.Redirect(
			http.StatusFound,
			u.String(),
		)

		return
	}

	c.JSON(http.StatusOK, gin.H{
		"msg":         "payment callback received",
		"reference":   reference,
		"status":      status,
		"redirect_to": redirectTo,
	})
}

// ============================================================
// PAYSTACK PAYMENT STREAM
// ============================================================

// PaystackPaymentStreamRoute godoc
// @Summary Stream payment status
// @Description Streams Paystack payment status updates using SSE.
// @Tags Paystack
// @Produce text/event-stream
// @Security BearerAuth
// @Param reference query string true "Paystack payment reference"
// @Success 200 {string} string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/paystack/stream [get]
func PaystackPaymentStreamRoute(c *gin.Context) {

	email := c.GetString("email")
	reference := c.Query("reference")

	if reference == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "reference is required",
		})
		return
	}

	c.Header(
		"Content-Type",
		"text/event-stream",
	)

	c.Header(
		"Cache-Control",
		"no-cache",
	)

	c.Header(
		"Connection",
		"keep-alive",
	)

	c.Header(
		"X-Accel-Buffering",
		"no",
	)

	flusher, ok := c.Writer.(http.Flusher)

	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "streaming not supported",
		})
		return
	}

	send := func(
		event string,
		data any,
	) {

		b, _ := json.Marshal(data)

		fmt.Fprintf(
			c.Writer,
			"event: %s\n",
			event,
		)

		fmt.Fprintf(
			c.Writer,
			"data: %s\n\n",
			string(b),
		)

		flusher.Flush()
	}

	send(
		"connected",
		gin.H{
			"status": "connected",
		},
	)

	ticker := time.NewTicker(
		4 * time.Second,
	)

	defer ticker.Stop()

	for {

		select {

		case <-c.Request.Context().Done():
			return

		case <-ticker.C:

			history, err :=
				controllers.GetPaymentHistory(
					reference,
				)

			if err != nil {

				send(
					"error",
					gin.H{
						"msg": "payment not found",
					},
				)

				return
			}

			if history.Email != "" &&
				!strings.EqualFold(
					history.Email,
					email,
				) {

				send(
					"error",
					gin.H{
						"msg": "forbidden",
					},
				)

				return
			}

			send(
				"payment",
				gin.H{
					"reference":      history.Reference,
					"status":         history.Status,
					"plan":           history.Plan,
					"tokens_granted": history.TokensGranted,
					"credited":       history.Credited,
				},
			)

			if history.Status == "success" ||
				history.Status == "failed" {

				return
			}
		}
	}
}

// ============================================================
// ============================================================
// SOLANA / SJLY PAYMENT ROUTES
// ============================================================
// ============================================================

// ------------------------------------------------------------
// CREATE SJLY PAYMENT
// ------------------------------------------------------------

// CreateCryptoPaymentRoute godoc
// @Summary Create crypto payment
// @Description Creates a pending crypto payment intent for SJLY, USDT, or USDC.
// @Tags Crypto Payments
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body CreateCryptoPaymentRequest true "Crypto payment"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/crypto/payment/create [post]
func CreateCryptoPaymentRoute(c *gin.Context) {

	email := c.GetString("email")

	var payload CreateCryptoPaymentRequest

	if err := c.ShouldBindJSON(
		&payload,
	); err != nil {

		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "invalid input",
		})

		return
	}

	plan := strings.TrimSpace(
		payload.Plan,
	)

	if plan == "" {

		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "plan is required",
		})

		return
	}

	payment, err :=
		controllers.CreateCryptoTokenPayment(
			email,
			plan,
			controllers.NormalizeCryptoTokenSymbol(payload.Token),
		)

	if err != nil {

		c.JSON(http.StatusBadRequest, gin.H{
			"msg": err.Error(),
		})

		return
	}

	c.JSON(http.StatusOK, gin.H{
		"msg":  "crypto payment created",
		"data": payment,
	})
}

// ============================================================
// SUBMIT SJLY TRANSACTION
// ============================================================

// SubmitCryptoPaymentRoute godoc
// @Summary Submit crypto transaction
// @Description Saves the Solana transaction signature for verification of a crypto payment.
// @Tags Crypto Payments
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body SubmitCryptoPaymentRequest true "Transaction"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Router /api/crypto/payment/submit [post]
func SubmitCryptoPaymentRoute(c *gin.Context) {

	var payload SubmitCryptoPaymentRequest

	if err := c.ShouldBindJSON(
		&payload,
	); err != nil {

		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "invalid input",
		})

		return
	}

	paymentID := strings.TrimSpace(
		payload.PaymentID,
	)

	signature := strings.TrimSpace(
		payload.Signature,
	)

	userWallet := strings.TrimSpace(
		payload.UserWallet,
	)

	if paymentID == "" {

		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "payment_id is required",
		})

		return
	}

	if signature == "" {

		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "signature is required",
		})

		return
	}

	if userWallet == "" {

		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "user_wallet is required",
		})

		return
	}

	payment, err :=
		controllers.SaveCryptoPaymentSignature(
			paymentID,
			signature,
			userWallet,
		)

	if err != nil {

		c.JSON(http.StatusBadRequest, gin.H{
			"msg": err.Error(),
		})

		return
	}

	c.JSON(http.StatusOK, gin.H{
		"msg":  "transaction submitted for verification",
		"data": payment,
	})
}

// ============================================================
// GET CRYPTO PAYMENT STATUS
// ============================================================

// CryptoPaymentStatusRoute godoc
// @Summary Get crypto payment status
// @Description Returns the current status of a crypto payment.
// @Tags Crypto Payments
// @Produce json
// @Security BearerAuth
// @Param payment_id query string true "Crypto payment ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/crypto/payment/status [get]
func CryptoPaymentStatusRoute(c *gin.Context) {

	email := c.GetString("email")

	paymentID := strings.TrimSpace(
		c.Query("payment_id"),
	)

	if paymentID == "" {

		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "payment_id is required",
		})

		return
	}

	payment, err :=
		controllers.GetCryptoPayment(
			paymentID,
		)

	if err != nil {

		c.JSON(http.StatusNotFound, gin.H{
			"msg": "payment not found",
		})

		return
	}

	// Never allow one authenticated user to inspect
	// another user's payment.
	if payment.Email != "" &&
		!strings.EqualFold(
			payment.Email,
			email,
		) {

		c.JSON(http.StatusForbidden, gin.H{
			"msg": "payment does not belong to authenticated user",
		})

		return
	}

	c.JSON(http.StatusOK, gin.H{
		"msg":  "crypto payment status",
		"data": payment,
	})
}

// ============================================================
// CRYPTO PAYMENT STREAM
// ============================================================

// CryptoPaymentStreamRoute godoc
// @Summary Stream crypto payment status
// @Description Streams the crypto payment status using Server-Sent Events.
// @Tags Crypto Payments
// @Produce text/event-stream
// @Security BearerAuth
// @Param payment_id query string true "Crypto payment ID"
// @Success 200 {string} string
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 404 {object} map[string]string
// @Router /api/crypto/payment/stream [get]
func CryptoPaymentStreamRoute(c *gin.Context) {

	email := c.GetString("email")

	paymentID := strings.TrimSpace(
		c.Query("payment_id"),
	)

	if paymentID == "" {

		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "payment_id is required",
		})

		return
	}

	c.Header(
		"Content-Type",
		"text/event-stream",
	)

	c.Header(
		"Cache-Control",
		"no-cache",
	)

	c.Header(
		"Connection",
		"keep-alive",
	)

	c.Header(
		"X-Accel-Buffering",
		"no",
	)

	flusher, ok :=
		c.Writer.(http.Flusher)

	if !ok {

		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": "streaming not supported",
		})

		return
	}

	send := func(
		event string,
		data any,
	) {

		b, _ := json.Marshal(data)

		fmt.Fprintf(
			c.Writer,
			"event: %s\n",
			event,
		)

		fmt.Fprintf(
			c.Writer,
			"data: %s\n\n",
			string(b),
		)

		flusher.Flush()
	}

	send(
		"connected",
		gin.H{
			"status":     "connected",
			"payment_id": paymentID,
		},
	)

	ticker := time.NewTicker(
		3 * time.Second,
	)

	defer ticker.Stop()

	for {

		select {

		case <-c.Request.Context().Done():
			return

		case <-ticker.C:

			payment, err :=
				controllers.GetCryptoPayment(
					paymentID,
				)

			if err != nil {

				send(
					"error",
					gin.H{
						"msg": "payment not found",
					},
				)

				return
			}

			if payment.Email != "" &&
				!strings.EqualFold(
					payment.Email,
					email,
				) {

				send(
					"error",
					gin.H{
						"msg": "forbidden",
					},
				)

				return
			}

			send(
				"payment",
				gin.H{
					"payment_id":     payment.PaymentID,
					"status":         payment.Status,
					"signature":      payment.TransactionSignature,
					"tokens_granted": payment.TokensGranted,
					"credited":       payment.Credited,
				},
			)

			if payment.Status == "success" ||
				payment.Status == "failed" {

				return
			}
		}
	}
}
