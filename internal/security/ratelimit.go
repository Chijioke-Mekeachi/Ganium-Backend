package security

import (
	"sync"
	"time"
)

// RateLimiter provides in-memory token bucket rate limiting.
type RateLimiter struct {
	mu           sync.Mutex
	clients      map[string]*clientBucket
	rate         float64 // tokens per second
	burst        int
	cleanupCycle time.Duration
}

type clientBucket struct {
	tokens     float64
	lastRefill time.Time
}

// NewRateLimiter initializes a rate limiter.
func NewRateLimiter(ratePerMinute int, burst int) *RateLimiter {
	if ratePerMinute <= 0 {
		ratePerMinute = 60
	}
	if burst <= 0 {
		burst = 20
	}

	rl := &RateLimiter{
		clients:      make(map[string]*clientBucket),
		rate:         float64(ratePerMinute) / 60.0,
		burst:        burst,
		cleanupCycle: 5 * time.Minute,
	}

	go rl.cleanupLoop()

	return rl
}

// Allow checks if a request from key is permitted.
func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	bucket, exists := rl.clients[key]
	if !exists {
		rl.clients[key] = &clientBucket{
			tokens:     float64(rl.burst - 1),
			lastRefill: now,
		}
		return true
	}

	// Refill tokens
	elapsed := now.Sub(bucket.lastRefill).Seconds()
	bucket.tokens += elapsed * rl.rate
	if bucket.tokens > float64(rl.burst) {
		bucket.tokens = float64(rl.burst)
	}
	bucket.lastRefill = now

	if bucket.tokens >= 1.0 {
		bucket.tokens -= 1.0
		return true
	}

	return false
}

func (rl *RateLimiter) cleanupLoop() {
	ticker := time.NewTicker(rl.cleanupCycle)
	for range ticker.C {
		rl.mu.Lock()
		now := time.Now()
		for key, bucket := range rl.clients {
			if now.Sub(bucket.lastRefill) > 10*time.Minute {
				delete(rl.clients, key)
			}
		}
		rl.mu.Unlock()
	}
}
