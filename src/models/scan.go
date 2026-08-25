package models

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"time"

	"ganium/internal/config"
	"ganium/src/db"

	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

type RecordScanRequest struct {
	Content         string `json:"content" bson:"content"`
	ContentType     string `json:"content_type" bson:"content_type"`
	RiskScore       string `json:"risk_score" bson:"risk_score"`
	Classification  string `json:"classification" bson:"classification"`
	Explanation     string `json:"explanation" bson:"explanation"`
	Recommendations string `json:"recommendations" bson:"recommendations"`
	ScanType        string `json:"scan_type" bson:"scan_type"`
}

func GetScanByID(ctx context.Context, id string) (*ScanRecord, error) {
	objectID, err := bson.ObjectIDFromHex(id)
	if err != nil {
		return nil, err
	}

	key := scanCacheKey(id)
	if db.RedisClient != nil {
		cached, cacheErr := db.RedisClient.Get(ctx, key).Bytes()
		if cacheErr == nil {
			var record ScanRecord
			if err := json.Unmarshal(cached, &record); err == nil {
				return &record, nil
			}
		}
	}

	var record ScanRecord
	err = db.MongoClient.
		Database(db.DatabaseName).
		Collection("scan_records").
		FindOne(ctx, bson.M{"_id": objectID}).
		Decode(&record)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return nil, fmt.Errorf("scan not found")
		}
		return nil, err
	}

	if db.RedisClient != nil {
		if encoded, marshalErr := json.Marshal(record); marshalErr == nil {
			cfg := config.LoadFromEnv()
			_ = db.RedisClient.Set(ctx, key, encoded, jitterTTL(cfg.ScanCacheTTL)).Err()
		}
	}

	return &record, nil
}

func InvalidateScanCache(ctx context.Context, id string) error {
	if db.RedisClient == nil {
		return nil
	}
	return db.RedisClient.Del(ctx, scanCacheKey(id)).Err()
}

func scanCacheKey(id string) string {
	return "scan:" + id
}

func jitterTTL(base time.Duration) time.Duration {
	if base <= 0 {
		return base
	}
	variation := base / 5
	if variation <= 0 {
		return base
	}
	return base - variation + time.Duration(rand.Int64N(int64(variation*2)+1))
}

// ScanRecord represents a record of a scan performed on some content.

type ScanRecord struct {
	ID              primitive.ObjectID `json:"id" bson:"_id,omitempty"`
	UserID          string             `json:"user_id" bson:"user_id"`
	Content         string             `json:"content" bson:"content"`
	ContentType     string             `json:"content_type" bson:"content_type"`
	RiskScore       string             `json:"risk_score" bson:"risk_score"`
	Classification  string             `json:"classification" bson:"classification"`
	Explanation     string             `json:"explanation" bson:"explanation"`
	Recommendations string             `json:"recommendations" bson:"recommendations"`
	TokensUsed      int                `json:"tokens_used" bson:"tokens_used"`
	CreatedAt       time.Time          `json:"created_at" bson:"created_at"`
}
