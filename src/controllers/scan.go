package controllers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"ganium/internal/investigation"
	"ganium/internal/security"
	"ganium/pkg/types"
	"ganium/src/db"
	"ganium/src/models"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

type geminiScanResult struct {
	Content         string `json:"content"`
	ContentType     string `json:"content_type"`
	RiskScore       string `json:"risk_score"`
	Classification  string `json:"classification"`
	Explanation     string `json:"explanation"`
	Recommendations string `json:"recommendations"`
}

type scanMode string

const (
	scanModeBasic   scanMode = "basic"
	scanModeMid     scanMode = "mid"
	scanModeAdvance scanMode = "advance"
	scanModeURL     scanMode = "url"
	scanModeWallet  scanMode = "wallet"
	scanModeMessage scanMode = "message"
	scanModeText    scanMode = "text"
)

func ScanContent(userEmail string, payload models.RecordScanRequest) (bool, string, *models.ScanRecord, error) {
	users := db.MongoClient.Database(db.DatabaseName).Collection("users")
	scans := db.MongoClient.Database(db.DatabaseName).Collection("scan_records")

	if err := users.FindOne(context.Background(), bson.M{"email": userEmail}).Err(); err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return false, "user not found", nil, err
		}
		return false, "database error", nil, err
	}

	mode := resolveScanMode(payload.ScanType, payload.ContentType, payload.Content)
	targetType := resolvedInvestigationTargetType(mode, payload.ContentType, payload.Content)
	result, err := investigation.Default().Investigate(context.Background(), investigation.Request{
		TargetType: targetType,
		Target:     payload.Content,
		Source:     payload.ContentType,
	})
	if err != nil {
		_ = CreateNotification(userEmail, "Scan failed", "We couldn't complete your scan: "+err.Error(), "scan_failed")
		return false, err.Error(), nil, err
	}

	assessment := result.Assessment
	if assessment == nil {
		_ = CreateNotification(userEmail, "Scan failed", "Scan assessment was unavailable. Please try again.", "scan_failed")
		return false, "assessment unavailable", nil, fmt.Errorf("empty assessment")
	}

	tokenCost := assessment.TokensUsed
	if tokenCost <= 0 {
		tokenCost = 1
	}
	now := time.Now().UTC()
	record := models.ScanRecord{
		ID:              primitive.NewObjectID(),
		UserID:          userEmail,
		Content:         payload.Content,
		ContentType:     string(result.Evidence.TargetType),
		RiskScore:       strconv.Itoa(assessment.RiskScore),
		Classification:  strings.ToLower(string(assessment.Verdict)),
		Explanation:     assessment.Summary,
		Recommendations: strings.Join(assessment.RecommendedActions, "; "),
		TokensUsed:      tokenCost,
		CreatedAt:       now,
	}

	_, err = scans.InsertOne(context.Background(), record)
	if err != nil {
		_ = CreateNotification(userEmail, "Scan failed", "Your scan completed but could not be saved.", "scan_failed")
		return false, "failed to store scan", nil, err
	}
	// Redis cache invalidation removed

	_, _ = users.UpdateOne(context.Background(), bson.M{"email": userEmail}, bson.M{
		"$inc": bson.M{"tokens_used_total": tokenCost, "tokens_remaining": -tokenCost, "wallet_balance": -(float64(tokenCost) / 10.0)},
		"$set": bson.M{"last_scan_at": now, "updated_at": now},
	})
	// Redis cache invalidation removed

	_ = CreateNotification(
		userEmail,
		"Scan complete",
		fmt.Sprintf("Your %s scan finished with verdict: %s.", mode, record.Classification),
		"scan_complete",
	)

	fmt.Println(record)

	return true, "scan completed", &record, nil
}

func ScanBasic(userEmail string, content string) (bool, string, *models.ScanRecord, error) {
	return ScanContent(userEmail, models.RecordScanRequest{
		Content:     content,
		ScanType:    string(scanModeBasic),
		ContentType: "text",
	})
}

func ScanMid(userEmail string, content string) (bool, string, *models.ScanRecord, error) {
	return ScanContent(userEmail, models.RecordScanRequest{
		Content:     content,
		ScanType:    string(scanModeMid),
		ContentType: "text",
	})
}

func ScanAdvance(userEmail string, content string) (bool, string, *models.ScanRecord, error) {
	return ScanContent(userEmail, models.RecordScanRequest{
		Content:     content,
		ScanType:    string(scanModeAdvance),
		ContentType: "text",
	})
}

func ScanMessage(userEmail string, content string) (bool, string, *models.ScanRecord, error) {
	return ScanContent(userEmail, models.RecordScanRequest{
		Content:     content,
		ScanType:    string(scanModeMessage),
		ContentType: "message",
	})
}

func ScanURL(userEmail string, content string) (bool, string, *models.ScanRecord, error) {
	return ScanContent(userEmail, models.RecordScanRequest{
		Content:     content,
		ScanType:    string(scanModeURL),
		ContentType: "url",
	})
}

func ScanWallet(userEmail string, content string) (bool, string, *models.ScanRecord, error) {
	return ScanContent(userEmail, models.RecordScanRequest{
		Content:     content,
		ScanType:    string(scanModeWallet),
		ContentType: "wallet",
	})
}

func resolveScanMode(scanType, contentType, content string) scanMode {
	value := strings.ToLower(strings.TrimSpace(scanType))
	if value == "" {
		value = strings.ToLower(strings.TrimSpace(contentType))
	}
	if value == "" {
		return scanModeBasic
	}

	switch value {
	case "url", "link":
		return scanModeURL
	case "wallet", "address", "crypto":
		return scanModeWallet
	case "message":
		return scanModeMessage
	case "text", "content":
		return scanModeText
	case string(scanModeBasic), string(scanModeMid), string(scanModeAdvance):
		return scanMode(value)
	default:
		if looksLikeURL(content) {
			return scanModeURL
		}
		if looksLikeWallet(content) {
			return scanModeWallet
		}
		return scanModeBasic
	}
}

func resolvedInvestigationTargetType(mode scanMode, contentType, content string) types.TargetType {
	switch mode {
	case scanModeURL:
		return types.TargetTypeURL
	case scanModeWallet:
		return types.TargetTypeWallet
	case scanModeMessage:
		return types.TargetTypeMessage
	case scanModeText, scanModeBasic, scanModeMid, scanModeAdvance:
		switch strings.ToLower(strings.TrimSpace(contentType)) {
		case "url":
			return types.TargetTypeURL
		case "wallet":
			return types.TargetTypeWallet
		case "message":
			return types.TargetTypeMessage
		}
		if looksLikeURL(content) {
			return types.TargetTypeURL
		}
		if looksLikeWallet(content) {
			return types.TargetTypeWallet
		}
		return types.TargetTypeMessage
	default:
		if looksLikeURL(content) {
			return types.TargetTypeURL
		}
		if looksLikeWallet(content) {
			return types.TargetTypeWallet
		}
		return types.TargetTypeMessage
	}
}

func buildEvidenceBundle(mode scanMode, content string) (string, string, error) {
	switch mode {
	case scanModeURL:
		return buildURLEvidence(content), "url", nil
	case scanModeWallet:
		return buildWalletEvidence(content), "wallet", nil
	case scanModeMessage, scanModeText, scanModeBasic, scanModeMid, scanModeAdvance:
		return buildTextEvidence(content, mode), "text", nil
	default:
		return buildTextEvidence(content, scanModeBasic), "text", nil
	}
}

func buildTextEvidence(content string, mode scanMode) string {
	level := string(mode)
	if level == "" {
		level = string(scanModeBasic)
	}
	return fmt.Sprintf(`Scan level: %s
Type: text
Input:
%s`, level, content)
}

func buildURLEvidence(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Sprintf("URL analysis input: %s\nParse error: %v", raw, err)
	}

	summary := []string{
		"Scan level: advance",
		"Type: url",
		"Input URL: " + raw,
		"Scheme: " + parsed.Scheme,
		"Host: " + parsed.Host,
		"Path: " + parsed.Path,
		"Query: " + parsed.RawQuery,
		"Is HTTPS: " + fmt.Sprintf("%t", parsed.Scheme == "https"),
		"Looks like redirector: " + fmt.Sprintf("%t", looksLikeRedirector(parsed)),
	}

	if hostInfo := fetchHostEvidence(parsed); hostInfo != "" {
		summary = append(summary, hostInfo)
	}
	if headInfo := fetchHTTPEvidence(raw); headInfo != "" {
		summary = append(summary, headInfo)
	}

	return strings.Join(summary, "\n")
}

func buildWalletEvidence(raw string) string {
	trimmed := strings.TrimSpace(raw)
	return fmt.Sprintf(`Scan level: mid
Type: wallet
Input wallet/address:
%s
Heuristic:
- Check for address format
- Watch for repeated use, typo variants, and suspicious prefixes
- If this looks like an ENS name or wallet address, analyze it as crypto-related content`, trimmed)
}

func fetchHostEvidence(parsed *url.URL) string {
	host := strings.TrimSpace(parsed.Hostname())
	if host == "" {
		return ""
	}

	ips, err := netLookupIP(host)
	if err != nil || len(ips) == 0 {
		return "DNS: no IPs resolved"
	}

	var parts []string
	for _, ip := range ips {
		parts = append(parts, ip.String())
	}
	return "DNS IPs: " + strings.Join(parts, ", ")
}

func fetchHTTPEvidence(raw string) string {
	parsed, err := security.ValidateTargetURL(raw)
	if err != nil {
		return "HTTP fetch blocked: " + err.Error()
	}

	client := security.SafeHTTPClient(8*time.Second, 5)
	req, err := http.NewRequest(http.MethodGet, parsed.String(), nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; GaniumScanner/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return "HTTP fetch error: " + err.Error()
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	snippet := strings.TrimSpace(string(body))
	if len(snippet) > 700 {
		snippet = snippet[:700]
	}

	return fmt.Sprintf("HTTP status: %d\nServer: %s\nContent-Type: %s\nBody snippet: %s", resp.StatusCode, resp.Header.Get("Server"), resp.Header.Get("Content-Type"), snippet)
}

func looksLikeURL(content string) bool {
	trimmed := strings.TrimSpace(strings.ToLower(content))
	return strings.HasPrefix(trimmed, "http://") || strings.HasPrefix(trimmed, "https://") || strings.Contains(trimmed, ".")
}

func looksLikeWallet(content string) bool {
	trimmed := strings.TrimSpace(content)
	return regexp.MustCompile(`^(0x[a-fA-F0-9]{40}|[a-zA-Z0-9_.-]+\.eth)$`).MatchString(trimmed)
}

func looksLikeRedirector(parsed *url.URL) bool {
	host := strings.ToLower(parsed.Hostname())
	return strings.Contains(host, "link") || strings.Contains(host, "redirect") || strings.Contains(host, "go.")
}

func analyzeWithGemini(content, contentType string, mode scanMode, evidence string) (*geminiScanResult, error) {
	apiKey := strings.TrimSpace(os.Getenv("GEMINI_API_KEY"))
	if apiKey == "" {
		return nil, fmt.Errorf("missing GEMINI_API_KEY")
	}

	model := strings.TrimSpace(os.Getenv("GEMINI_MODEL"))
	if model == "" {
		model = "gemini-3.7-flash"
	}

	systemPrompt := `You are Ganium's scam detection engine.
Return only valid JSON with this exact schema:
{
  "content": "original input",
  "content_type": "url|text|wallet|message|other",
  "risk_score": "0-100 as a string",
  "classification": "safe|suspicious|scam|error",
  "explanation": "short clear reason",
  "recommendations": "practical next steps"
}

Decision rules:
- basic: quick content-only analysis
- mid: content + heuristics + direct metadata
- advance: content + heuristics + live URL evidence when available
- If scan type is missing, default to basic
- If input is malformed or unavailable, use classification error
- Keep reasoning grounded in provided evidence only
- Do not add markdown or extra keys`

	prompt := fmt.Sprintf(`Scan mode: %s
Declared content type: %s
User input:
%s

Evidence bundle:
%s

Use the evidence bundle when available. If the input is a URL, assess phishing, redirects, login traps, brand impersonation, suspicious hosting, and content clues. If it is a wallet, assess format, chain-like appearance, and scam-likelihood from the string itself. If it is a message, assess persuasion, urgency, payment requests, and social engineering.
`, mode, contentType, content, evidence)

	body := map[string]any{
		"contents": []map[string]any{
			{
				"role":  "user",
				"parts": []map[string]any{{"text": systemPrompt + "\n\n" + prompt}},
			},
		},
		"generationConfig": map[string]any{
			"temperature":        0.2,
			"maxOutputTokens":    700,
			"response_mime_type": "application/json",
		},
	}

	payload, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost,
		fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s", model, apiKey),
		bytes.NewReader(payload),
	)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("gemini api error: %s", strings.TrimSpace(string(respBody)))
	}

	var outer struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
	}
	if err := json.Unmarshal(respBody, &outer); err != nil {
		return nil, err
	}
	if len(outer.Candidates) == 0 || len(outer.Candidates[0].Content.Parts) == 0 {
		return nil, fmt.Errorf("empty gemini response")
	}

	raw := strings.TrimSpace(outer.Candidates[0].Content.Parts[0].Text)
	raw = strings.TrimPrefix(raw, "```json")
	raw = strings.TrimPrefix(raw, "```")
	raw = strings.TrimSuffix(raw, "```")
	raw = strings.TrimSpace(raw)

	var result geminiScanResult
	if err := json.Unmarshal([]byte(raw), &result); err != nil {
		return nil, err
	}
	if result.Content == "" {
		result.Content = content
	}
	if result.ContentType == "" {
		result.ContentType = contentType
	}
	if result.Classification == "" {
		result.Classification = "error"
	}
	if result.RiskScore == "" {
		result.RiskScore = "50"
	}
	return &result, nil
}

func netLookupIP(host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(context.Background(), "ip", host)
}