package client

import (
	"sync"
	"time"
)

const defaultTTL = time.Hour

type cacheEntry struct {
	body   []byte
	expiry time.Time
}

// ttlCache is a tiny concurrency-safe in-memory cache with per-entry expiry.
// NVD is slow and rate-limited, so caching raw responses keyed by request URL
// is a big latency win for repeated lookups.
type ttlCache struct {
	mu      sync.RWMutex
	entries map[string]cacheEntry
	ttl     time.Duration
}

var defaultCache = newCache(defaultTTL)

func newCache(ttl time.Duration) *ttlCache {
	return &ttlCache{entries: make(map[string]cacheEntry), ttl: ttl}
}

func (c *ttlCache) get(key string) ([]byte, bool) {
	if c.ttl <= 0 {
		return nil, false
	}

	c.mu.RLock()
	e, ok := c.entries[key]
	c.mu.RUnlock()

	if !ok || time.Now().After(e.expiry) {
		return nil, false
	}
	return e.body, true
}

func (c *ttlCache) set(key string, body []byte) {
	if c.ttl <= 0 {
		return
	}

	c.mu.Lock()
	c.entries[key] = cacheEntry{body: body, expiry: time.Now().Add(c.ttl)}
	c.mu.Unlock()
}
