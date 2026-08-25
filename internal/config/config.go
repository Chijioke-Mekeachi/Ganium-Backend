package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

// Config encapsulates backend runtime configuration.
type Config struct {
	Environment        string
	Port               string
	MongoURI           string
	DatabaseName       string
	JWTSecret          string
	GeminiAPIKey       string
	GeminiModel        string
	VirusTotalAPIKey   string
	AbuseIPDBAPIKey    string
	EtherscanAPIKey    string
	SolanaRPCURL       string
	EthereumRPCURL     string
	HTTPTimeout        time.Duration
	MaxRedirects       int
	MaxBodySizeBytes   int64
	AllowedOrigins     []string
	RateLimitPerMinute int
	RateLimitBurst     int
	WebSocketTicketTTL time.Duration
}

// LoadFromEnv loads and sanitizes configuration from environment variables.
func LoadFromEnv() *Config {
	env := getEnv("APP_ENV", "production")
	port := getEnv("PORT", "8008")
	if !strings.HasPrefix(port, ":") {
		port = ":" + port
	}

	originsRaw := getEnv("ALLOWED_ORIGINS", "*")
	origins := strings.Split(originsRaw, ",")
	for i := range origins {
		origins[i] = strings.TrimSpace(origins[i])
	}

	rateLimit, _ := strconv.Atoi(getEnv("RATE_LIMIT_PER_MINUTE", "60"))
	if rateLimit <= 0 {
		rateLimit = 60
	}

	burst, _ := strconv.Atoi(getEnv("RATE_LIMIT_BURST", "20"))
	if burst <= 0 {
		burst = 20
	}

	maxBodySize, _ := strconv.ParseInt(getEnv("MAX_BODY_SIZE_BYTES", "524288"), 10, 64) // 512KB default
	if maxBodySize <= 0 {
		maxBodySize = 524288
	}

	

	return &Config{
		Environment:        env,
		Port:               port,
		MongoURI:           getEnv("MONGO_URI", "mongodb://localhost:27017"),
		DatabaseName:       getEnv("MONGO_DATABASE", "ganium"),
		JWTSecret:          getEnv("JWT_SECRET", "ganium-secure-default-change-in-production"),
		GeminiAPIKey:       getEnv("GEMINI_API_KEY", getEnv("GOOGLE_API_KEY", "")),
		GeminiModel:        getEnv("GEMINI_MODEL", "gemini-3.7-flash"),
		VirusTotalAPIKey:   getEnv("VIRUSTOTAL_API_KEY", ""),
		AbuseIPDBAPIKey:    getEnv("ABUSEIPDB_API_KEY", ""),
		EtherscanAPIKey:    getEnv("ETHERSCAN_API_KEY", ""),
		SolanaRPCURL:       getEnv("SOLANA_RPC_URL", "https://api.mainnet-beta.solana.com"),
		EthereumRPCURL:     getEnv("ETHEREUM_RPC_URL", "https://cloudflare-eth.com"),
		HTTPTimeout:        8 * time.Second,
		MaxRedirects:       5,
		MaxBodySizeBytes:   maxBodySize,
		AllowedOrigins:     origins,
		RateLimitPerMinute: rateLimit,
		RateLimitBurst:     burst,
		WebSocketTicketTTL: 2 * time.Minute,
	}
}



func getEnv(key, fallback string) string {
	if value, exists := os.LookupEnv(key); exists {
		trimmed := strings.TrimSpace(value)
		if trimmed != "" {
			return trimmed
		}
	}
	return fallback
}
