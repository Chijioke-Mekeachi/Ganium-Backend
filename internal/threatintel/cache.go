package threatintel

import (
	"sync"
	"time"

	"ganium/pkg/types"
)

// Cache defines the threat intelligence caching interface.
type Cache interface {
	Get(key string) (types.ThreatIntelligenceEvidence, bool)
	Set(key string, evidence types.ThreatIntelligenceEvidence)
}

type inMemoryCacheEntry struct {
	evidence  types.ThreatIntelligenceEvidence
	expiresAt time.Time
}

// InMemoryCache implements Cache using a concurrent map with expiration.
type InMemoryCache struct {
	mu      sync.RWMutex
	entries map[string]inMemoryCacheEntry
	ttl     time.Duration
}

func NewInMemoryCache(ttl time.Duration) *InMemoryCache {
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	c := &InMemoryCache{
		entries: make(map[string]inMemoryCacheEntry),
		ttl:     ttl,
	}
	go c.cleanupLoop()
	return c
}

func (c *InMemoryCache) Get(key string) (types.ThreatIntelligenceEvidence, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return types.ThreatIntelligenceEvidence{}, false
	}
	return entry.evidence, true
}

func (c *InMemoryCache) Set(key string, evidence types.ThreatIntelligenceEvidence) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries[key] = inMemoryCacheEntry{
		evidence:  evidence,
		expiresAt: time.Now().Add(c.ttl),
	}
}

func (c *InMemoryCache) cleanupLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for k, v := range c.entries {
			if now.After(v.expiresAt) {
				delete(c.entries, k)
			}
		}
		c.mu.Unlock()
	}
}
