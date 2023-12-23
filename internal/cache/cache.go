package cache

import (
	"sync"

	"github.com/outofoffice3/policy-general/internal/shared"
)

// Cache interface for storing and retrieving compliance results.
type Cache interface {
	Set(key CacheKey, value shared.ComplianceResult)
	Get(key CacheKey) (shared.ComplianceResult, bool)
}

// memoryCache implements the Cache interface using sync.Map.
type memoryCache struct {
	store sync.Map
}

type CacheKey struct {
	PK string
	SK string
}

func (ck CacheKey) String() string {
	return ck.PK + "||" + ck.SK
}

// NewCache creates a new instance of a Cache using memoryCache.
func NewCache() Cache {
	return &memoryCache{}
}

// Set stores a key-value pair in the cache.
func (c *memoryCache) Set(key CacheKey, value shared.ComplianceResult) {
	c.store.Store(key.String(), value)
}

// Get retrieves a value from the cache based on its key.
func (c *memoryCache) Get(key CacheKey) (shared.ComplianceResult, bool) {
	result, exists := c.store.Load(key.String())
	if !exists {
		return shared.ComplianceResult{}, false
	}
	return result.(shared.ComplianceResult), true
}
