package db

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

var RedisHost = "localhost"
var RedisPort = "6379"
var RedisPassword = ""
var RedisDB = 0

var RedisClient *redis.Client

func ConnectRedis() error {
	if host := strings.TrimSpace(os.Getenv("REDIS_HOST")); host != "" {
		RedisHost = host
	}
	if port := strings.TrimSpace(os.Getenv("REDIS_PORT")); port != "" {
		RedisPort = port
	}
	RedisPassword = strings.TrimSpace(os.Getenv("REDIS_PASSWORD"))
	if database, err := strconv.Atoi(strings.TrimSpace(os.Getenv("REDIS_DB"))); err == nil && database >= 0 {
		RedisDB = database
	}

	client := redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%s", RedisHost, RedisPort),
		Password: RedisPassword,
		DB:       RedisDB,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return err
	}

	RedisClient = client

	return nil
}
