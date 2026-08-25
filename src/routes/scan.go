package routes

import (
	"net/http"
	"strings"
	"time"

	"ganium/internal/security"
	"ganium/src/controllers"
	"ganium/src/models"

	"github.com/gin-gonic/gin"
)

// ============================================================
// REQUEST MODELS
// ============================================================

type ScanRequest struct {
	Content string `json:"content" example:"Congratulations! You have won a prize. Click this link now."`
}

type BasicScanRequest struct {
	Content string `json:"content" example:"Your account will be suspended unless you confirm your password now."`
}

type MidScanRequest struct {
	Content string `json:"content" example:"We detected unusual activity. Please update your payment details immediately."`
}

type AdvanceScanRequest struct {
	Content string `json:"content" example:"Claim your reward at https://secure-login-example.com/verify before it expires."`
}

type MessageScanRequest struct {
	Content string `json:"content" example:"Please send the 0.5 ETH to this address right away so we can release the funds."`
}

type URLScanRequest struct {
	Content string `json:"content" example:"https://secure-login-example.com/account/verify?session=123"`
}

type WalletScanRequest struct {
	Content string `json:"content" example:"0x3fD2b5e4c7A9E2d6C1b8F0a3D4e5F67890123456"`
}

// ============================================================
// INTERNAL HELPERS
// ============================================================

func bindScanPayload(c *gin.Context) (string, bool) {
	var payload ScanRequest

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "invalid input",
		})
		return "", false
	}

	if payload.Content == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "content is required",
		})
		return "", false
	}

	return payload.Content, true
}

func normalizeURLContent(content string) (string, bool) {
	trimmed := strings.TrimSpace(content)
	if trimmed == "" {
		return "", false
	}

	if _, err := security.ValidateTargetURL(trimmed); err == nil {
		return trimmed, true
	}

	if !strings.HasPrefix(trimmed, "http://") && !strings.HasPrefix(trimmed, "https://") {
		candidate := "https://" + trimmed
		if _, err := security.ValidateTargetURL(candidate); err == nil {
			return candidate, true
		}
	}

	return "", false
}

func scanResponse(
	c *gin.Context,
	ok bool,
	msg string,
	record *models.ScanRecord,
	err error,
) {
	if !ok {
		status := http.StatusBadRequest

		if err != nil {
			status = http.StatusInternalServerError
		}

		c.JSON(status, gin.H{
			"msg": msg,
		})

		return
	}

	c.JSON(http.StatusOK, gin.H{
		"msg":  msg,
		"data": record,
	})
}

func sendPDF(
	c *gin.Context,
	filename string,
	pdf []byte,
	err error,
) {
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"msg": err.Error(),
		})
		return
	}

	c.Header("Content-Type", "application/pdf")

	c.Header(
		"Content-Disposition",
		`attachment; filename="`+filename+`"`,
	)

	c.Data(
		http.StatusOK,
		"application/pdf",
		pdf,
	)
}

// ============================================================
// BASIC SCAN
// ============================================================

// ScanBasicRoute godoc
// @Summary Basic security scan
// @Description Performs a basic security scan on supplied content.
// @Tags Scan
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body BasicScanRequest true "Text content to scan"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/scan/basic [post]
func ScanBasicRoute(c *gin.Context) {
	email := c.GetString("email")

	content, ok := bindScanPayload(c)

	if !ok {
		return
	}

	resOK, msg, record, err := controllers.ScanBasic(
		email,
		content,
	)

	scanResponse(
		c,
		resOK,
		msg,
		record,
		err,
	)
}

// ============================================================
// MID SCAN
// ============================================================

// ScanMidRoute godoc
// @Summary Mid-level security scan
// @Description Performs a mid-level security scan on supplied content.
// @Tags Scan
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body MidScanRequest true "Text content to scan"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/scan/mid [post]
func ScanMidRoute(c *gin.Context) {
	email := c.GetString("email")

	content, ok := bindScanPayload(c)

	if !ok {
		return
	}

	resOK, msg, record, err := controllers.ScanMid(
		email,
		content,
	)

	scanResponse(
		c,
		resOK,
		msg,
		record,
		err,
	)
}

// ============================================================
// ADVANCED SCAN
// ============================================================

// ScanAdvanceRoute godoc
// @Summary Advanced security scan
// @Description Performs an advanced security scan on supplied content.
// @Tags Scan
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body AdvanceScanRequest true "Text content to scan"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/scan/advance [post]
func ScanAdvanceRoute(c *gin.Context) {
	email := c.GetString("email")

	content, ok := bindScanPayload(c)

	if !ok {
		return
	}

	resOK, msg, record, err := controllers.ScanAdvance(
		email,
		content,
	)

	scanResponse(
		c,
		resOK,
		msg,
		record,
		err,
	)
}

// ============================================================
// MESSAGE SCAN
// ============================================================

// ScanMessageRoute godoc
// @Summary Scan message
// @Description Analyzes a message for scams, phishing, and malicious content.
// @Tags Scan
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body MessageScanRequest true "Message content to scan"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/scan/message [post]
func ScanMessageRoute(c *gin.Context) {
	email := c.GetString("email")

	content, ok := bindScanPayload(c)

	if !ok {
		return
	}

	resOK, msg, record, err := controllers.ScanMessage(
		email,
		content,
	)

	scanResponse(
		c,
		resOK,
		msg,
		record,
		err,
	)
}

// ============================================================
// URL SCAN
// ============================================================

// ScanURLRoute godoc
// @Summary Scan URL
// @Description Analyzes a URL for malicious, phishing, and scam indicators.
// @Tags Scan
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body URLScanRequest true "URL to scan"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/scan/url [post]
func ScanURLRoute(c *gin.Context) {
	email := c.GetString("email")

	content, ok := bindScanPayload(c)

	if !ok {
		return
	}

	content, ok = normalizeURLContent(content)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "invalid URL target",
		})
		return
	}

	resOK, msg, record, err := controllers.ScanURL(
		email,
		content,
	)

	scanResponse(
		c,
		resOK,
		msg,
		record,
		err,
	)
}

// ============================================================
// WALLET SCAN
// ============================================================

// ScanWalletRoute godoc
// @Summary Scan wallet
// @Description Analyzes a cryptocurrency wallet address for suspicious activity.
// @Tags Scan
// @Accept json
// @Produce json
// @Security BearerAuth
// @Param request body WalletScanRequest true "Wallet address to scan"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/scan/wallet [post]
func ScanWalletRoute(c *gin.Context) {
	email := c.GetString("email")

	content, ok := bindScanPayload(c)

	if !ok {
		return
	}

	resOK, msg, record, err := controllers.ScanWallet(
		email,
		content,
	)

	scanResponse(
		c,
		resOK,
		msg,
		record,
		err,
	)
}

// ============================================================
// SCAN PDF
// ============================================================

// ScanPDFRoute godoc
// @Summary Generate scan PDF
// @Description Generates a PDF report for a security scan.
// @Tags PDF
// @Accept json
// @Produce application/pdf
// @Security BearerAuth
// @Param scanType path string true "Scan type" Enums(basic,mid,advance,message,url,wallet)
// @Param request body ScanRequest true "Content to scan for the selected scanType"
// @Success 200 {file} file
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/scan/{scanType}/pdf [post]
func ScanPDFRoute(c *gin.Context) {
	email := c.GetString("email")

	content, ok := bindScanPayload(c)

	if !ok {
		return
	}

	scanType := c.Param("scanType")

	var (
		resOK  bool
		msg    string
		record *models.ScanRecord
		err    error
	)

	switch scanType {
	case "basic":
		resOK, msg, record, err = controllers.ScanBasic(
			email,
			content,
		)

	case "mid":
		resOK, msg, record, err = controllers.ScanMid(
			email,
			content,
		)

	case "advance":
		resOK, msg, record, err = controllers.ScanAdvance(
			email,
			content,
		)

	case "message":
		resOK, msg, record, err = controllers.ScanMessage(
			email,
			content,
		)

	case "url":
		content, ok = normalizeURLContent(content)
		if !ok {
			c.JSON(http.StatusBadRequest, gin.H{
				"msg": "invalid URL target",
			})
			return
		}

		resOK, msg, record, err = controllers.ScanURL(
			email,
			content,
		)

	case "wallet":
		resOK, msg, record, err = controllers.ScanWallet(
			email,
			content,
		)

	default:
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "invalid scan type",
		})
		return
	}

	if !resOK {
		scanResponse(
			c,
			resOK,
			msg,
			record,
			err,
		)
		return
	}

	pdfBytes, pdfErr := controllers.BuildScanPDF(
		email,
		record,
	)

	sendPDF(
		c,
		"scan-report.pdf",
		pdfBytes,
		pdfErr,
	)
}

// ============================================================
// RECEIPT PDF
// ============================================================

// ReceiptPDFRoute godoc
// @Summary Generate payment receipt PDF
// @Description Generates a PDF payment receipt for a transaction.
// @Tags PDF
// @Accept json
// @Produce application/pdf
// @Security BearerAuth
// @Param request body models.ReceiptRequest true "Receipt information"
// @Success 200 {file} file
// @Failure 400 {object} map[string]string
// @Failure 401 {object} map[string]string
// @Failure 500 {object} map[string]string
// @Router /api/receipt/pdf [post]
func ReceiptPDFRoute(c *gin.Context) {
	email := c.GetString("email")

	var payload models.ReceiptRequest

	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "invalid input",
		})
		return
	}

	if payload.Reference == "" ||
		payload.Amount <= 0 ||
		payload.Currency == "" {

		c.JSON(http.StatusBadRequest, gin.H{
			"msg": "reference, amount, and currency are required",
		})

		return
	}

	parsed := models.ReceiptData{
		Reference:     payload.Reference,
		Amount:        payload.Amount,
		Currency:      payload.Currency,
		Description:   payload.Description,
		PayerEmail:    payload.PayerEmail,
		PayerName:     payload.PayerName,
		PaymentMethod: payload.PaymentMethod,
		Status:        payload.Status,
	}

	if payload.TransactionDate != "" {
		if t, err := time.Parse(
			time.RFC3339,
			payload.TransactionDate,
		); err == nil {

			parsed.TransactionDate = t
		} else {
			parsed.TransactionDate = time.Now().UTC()
		}
	} else {
		parsed.TransactionDate = time.Now().UTC()
	}

	if parsed.PayerEmail == "" {
		parsed.PayerEmail = email
	}

	pdfBytes, pdfErr := controllers.BuildReceiptPDF(
		email,
		parsed,
	)

	sendPDF(
		c,
		"payment-receipt.pdf",
		pdfBytes,
		pdfErr,
	)
}
