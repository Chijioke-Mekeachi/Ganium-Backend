package db

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Database configuration (can be overridden via env vars)
var DatabaseURL = `mongodb://localhost:27017`
var DatabaseName = "ganium"

const CollectionName = "ganium"

// MongoClient is the shared client reused across the application.
var MongoClient *mongo.Client

var clientMu sync.Mutex

// getEnvInt reads an integer env var with a fallback default.
func getEnvInt(key string, fallback int) int {
	s := strings.TrimSpace(os.Getenv(key))
	if s == "" {
		return fallback
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return fallback
	}
	return v
}

// GetMongoClient returns a shared, lazily-initialized MongoDB client.
// It uses a mutex to ensure only one connection attempt runs at a time.
// If an initialization attempt fails, it does not permanently cache the
// failure — subsequent calls will retry connecting.
func GetMongoClient(ctx context.Context) (*mongo.Client, error) {
	if MongoClient != nil {
		return MongoClient, nil
	}

	clientMu.Lock()
	defer clientMu.Unlock()

	if MongoClient != nil {
		return MongoClient, nil
	}

	// Allow env overrides for URL and DB name.
	if uri := strings.TrimSpace(os.Getenv("MONGO_URI")); uri != "" {
		DatabaseURL = uri
	}
	if dbName := strings.TrimSpace(os.Getenv("MONGO_DATABASE")); dbName != "" {
		DatabaseName = dbName
	}

	// Connection pool and timeout defaults (conservative for small/medium APIs).
	maxPool := uint64(getEnvInt("MONGO_MAX_POOL_SIZE", 20))
	minPool := uint64(getEnvInt("MONGO_MIN_POOL_SIZE", 0))
	maxConnIdleMinutes := getEnvInt("MONGO_MAX_CONN_IDLE_MINUTES", 5)
	serverSelectionTimeoutMs := getEnvInt("MONGO_SERVER_SELECTION_TIMEOUT_MS", 10000)
	connectTimeoutMs := getEnvInt("MONGO_CONNECT_TIMEOUT_MS", 10000)

	clientOpts := options.Client().ApplyURI(DatabaseURL).
		SetMaxPoolSize(maxPool).
		SetMinPoolSize(minPool).
		SetMaxConnIdleTime(time.Duration(maxConnIdleMinutes) * time.Minute).
		SetServerSelectionTimeout(time.Duration(serverSelectionTimeoutMs) * time.Millisecond).
		SetConnectTimeout(time.Duration(connectTimeoutMs) * time.Millisecond)

	client, err := mongo.Connect(clientOpts)
	if err != nil {
		return nil, fmt.Errorf("connect mongo: %w", err)
	}

	// Verify connection with a short ping timeout.
	pingCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := client.Ping(pingCtx, nil); err != nil {
		_ = client.Disconnect(context.Background())
		return nil, fmt.Errorf("ping mongo: %w", err)
	}

	MongoClient = client
	return MongoClient, nil
}

// ConnectMongoDB is kept for backward compatibility and is used by main.go
// to eagerly establish a connection during startup. It delegates to
// GetMongoClient and uses a background context.
func ConnectMongoDB() error {
	ctx := context.Background()
	_, err := GetMongoClient(ctx)
	return err
}

// DisconnectMongoDB cleanly disconnects the shared client. Call this on
// graceful shutdown only.
func DisconnectMongoDB(ctx context.Context) error {
	clientMu.Lock()
	defer clientMu.Unlock()
	if MongoClient == nil {
		return nil
	}
	err := MongoClient.Disconnect(ctx)
	MongoClient = nil
	return err
}

func CreateCollection(arg string) error {
	if MongoClient == nil {
		return fmt.Errorf("database is not initialized")
	}
	return MongoClient.Database(DatabaseName).CreateCollection(context.Background(), arg)
}
