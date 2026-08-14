package routes

import (
	"net/http"
	"time"

	"ganium/src/controllers"
	"ganium/src/models"

	"github.com/gin-gonic/gin"
)

type scanPayload struct {
	Content string `json:"content"`
}

func bindScanPayload(c *gin.Context) (string, bool) {
	var payload scanPayload
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "invalid input"})
		return "", false
	}
	if payload.Content == "" {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "content is required"})
		return "", false
	}
	return payload.Content, true
}

func scanResponse(c *gin.Context, ok bool, msg string, record *models.ScanRecord, err error) {
	if !ok {
		status := http.StatusBadRequest
		if err != nil {
			status = http.StatusInternalServerError
		}
		c.JSON(status, gin.H{"msg": msg})
		return
	}
	c.JSON(http.StatusOK, gin.H{"msg": msg, "data": record})
}

func sendPDF(c *gin.Context, filename string, pdf []byte, err error) {
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"msg": err.Error()})
		return
	}
	c.Header("Content-Type", "application/pdf")
	c.Header("Content-Disposition", `attachment; filename="`+filename+`"`)
	c.Data(http.StatusOK, "application/pdf", pdf)
}

func ScanBasicRoute(c *gin.Context) {
	email := c.GetString("email")
	content, ok := bindScanPayload(c)
	if !ok {
		return
	}
	resOK, msg, record, err := controllers.ScanBasic(email, content)
	scanResponse(c, resOK, msg, record, err)
}

func ScanMidRoute(c *gin.Context) {
	email := c.GetString("email")
	content, ok := bindScanPayload(c)
	if !ok {
		return
	}
	resOK, msg, record, err := controllers.ScanMid(email, content)
	scanResponse(c, resOK, msg, record, err)
}

func ScanAdvanceRoute(c *gin.Context) {
	email := c.GetString("email")
	content, ok := bindScanPayload(c)
	if !ok {
		return
	}
	resOK, msg, record, err := controllers.ScanAdvance(email, content)
	scanResponse(c, resOK, msg, record, err)
}

func ScanMessageRoute(c *gin.Context) {
	email := c.GetString("email")
	content, ok := bindScanPayload(c)
	if !ok {
		return
	}
	resOK, msg, record, err := controllers.ScanMessage(email, content)
	scanResponse(c, resOK, msg, record, err)
}

func ScanURLRoute(c *gin.Context) {
	email := c.GetString("email")
	content, ok := bindScanPayload(c)
	if !ok {
		return
	}
	resOK, msg, record, err := controllers.ScanURL(email, content)
	scanResponse(c, resOK, msg, record, err)
}

func ScanWalletRoute(c *gin.Context) {
	email := c.GetString("email")
	content, ok := bindScanPayload(c)
	if !ok {
		return
	}
	resOK, msg, record, err := controllers.ScanWallet(email, content)
	scanResponse(c, resOK, msg, record, err)
}

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
		resOK, msg, record, err = controllers.ScanBasic(email, content)
	case "mid":
		resOK, msg, record, err = controllers.ScanMid(email, content)
	case "advance":
		resOK, msg, record, err = controllers.ScanAdvance(email, content)
	case "message":
		resOK, msg, record, err = controllers.ScanMessage(email, content)
	case "url":
		resOK, msg, record, err = controllers.ScanURL(email, content)
	case "wallet":
		resOK, msg, record, err = controllers.ScanWallet(email, content)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"msg": "invalid scan type"})
		return
	}
	if !resOK {
		scanResponse(c, resOK, msg, record, err)
		return
	}

	pdfBytes, pdfErr := controllers.BuildScanPDF(email, record)
	sendPDF(c, "scan-report.pdf", pdfBytes, pdfErr)
}

func ReceiptPDFRoute(c *gin.Context) {
	email := c.GetString("email")
	var payload models.ReceiptRequest
	if err := c.ShouldBindJSON(&payload); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "invalid input"})
		return
	}
	if payload.Reference == "" || payload.Amount <= 0 || payload.Currency == "" {
		c.JSON(http.StatusBadRequest, gin.H{"msg": "reference, amount, and currency are required"})
		return
	}

	parsed := models.ReceiptData{
		Reference:    payload.Reference,
		Amount:       payload.Amount,
		Currency:     payload.Currency,
		Description:  payload.Description,
		PayerEmail:   payload.PayerEmail,
		PayerName:    payload.PayerName,
		PaymentMethod: payload.PaymentMethod,
		Status:       payload.Status,
	}
	if payload.TransactionDate != "" {
		if t, err := time.Parse(time.RFC3339, payload.TransactionDate); err == nil {
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
	pdfBytes, pdfErr := controllers.BuildReceiptPDF(email, parsed)
	sendPDF(c, "payment-receipt.pdf", pdfBytes, pdfErr)
}
