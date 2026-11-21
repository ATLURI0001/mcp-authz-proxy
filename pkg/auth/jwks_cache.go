package auth

import (
	"context"
	"crypto"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrKeyNotFound   = errors.New("jwks: key id not found")
	ErrCacheClosed   = errors.New("jwks: cache has been closed")
	ErrCooldownActive = errors.New("jwks: refresh cooldown active")
)

// KeyFetcher defines the function signature for fetching public keys from an IdP JWKS endpoint.
type KeyFetcher func(ctx context.Context) (map[string]crypto.PublicKey, error)

// JWKSCacheConfig holds configuration parameters for the rotary cache.
type JWKSCacheConfig struct {
	TTL              time.Duration
	RefreshInterval  time.Duration
	MinRefreshInterval time.Duration // Cooldown between on-demand refreshes
	GracePeriod      time.Duration // Time to serve expired keys if IdP is down
}

func DefaultJWKSCacheConfig() JWKSCacheConfig {
	return JWKSCacheConfig{
		TTL:                1 * time.Hour,
		RefreshInterval:    15 * time.Minute,
		MinRefreshInterval: 5 * time.Second,
		GracePeriod:        6 * time.Hour,
	}
}

// CacheStats provides operational telemetry for JWKS lookups.
type CacheStats struct {
	Hits            uint64
	Misses          uint64
	Refreshes       uint64
	RefreshFailures uint64
	ActiveKeys      int
	LastRefreshedAt time.Time
}

type cachedKey struct {
	key       crypto.PublicKey
	fetchedAt time.Time
}

// JWKSCache represents a high-performance in-memory rotary cache for JWKS keys.
type JWKSCache struct {
	config  JWKSCacheConfig
	fetcher KeyFetcher

	mu              sync.RWMutex
	keys            map[string]cachedKey
	lastRefresh     time.Time
	lastRefreshFail time.Time

	stats struct {
		hits            atomic.Uint64
		misses          atomic.Uint64
		refreshes       atomic.Uint64
		refreshFailures atomic.Uint64
	}

	refreshMu sync.Mutex // Guards on-demand refresh execution
	ctx       context.Context
	cancel    context.CancelFunc
	closed    atomic.Bool
}

// NewJWKSCache initializes a new JWKSCache with an initial sync and background rotary.
func NewJWKSCache(ctx context.Context, fetcher KeyFetcher, cfg JWKSCacheConfig) (*JWKSCache, error) {
	if cfg.TTL <= 0 {
		cfg.TTL = DefaultJWKSCacheConfig().TTL
	}
	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = DefaultJWKSCacheConfig().RefreshInterval
	}
	if cfg.MinRefreshInterval <= 0 {
		cfg.MinRefreshInterval = DefaultJWKSCacheConfig().MinRefreshInterval
	}
	if cfg.GracePeriod <= 0 {
		cfg.GracePeriod = DefaultJWKSCacheConfig().GracePeriod
	}

	cCtx, cancel := context.WithCancel(ctx)
	c := &JWKSCache{
		config:  cfg,
		fetcher: fetcher,
		keys:    make(map[string]cachedKey),
		ctx:     cCtx,
		cancel:  cancel,
	}

	// Perform initial fetch
	if fetcher != nil {
		if err := c.refresh(cCtx); err != nil {
			// Do not fail startup if initial fetch fails, but record error
			c.stats.refreshFailures.Add(1)
		}
	}

	go c.rotaryLoop()

	return c, nil
}

// GetKey retrieves a public key by key ID (kid), triggering on-demand refresh if missing.
func (c *JWKSCache) GetKey(ctx context.Context, kid string) (crypto.PublicKey, error) {
	if c.closed.Load() {
		return nil, ErrCacheClosed
	}

	now := time.Now()

	// 1. Fast read lock lookup
	c.mu.RLock()
	entry, exists := c.keys[kid]
	c.mu.RUnlock()

	if exists {
		// Verify if entry is within TTL + GracePeriod
		if now.Sub(entry.fetchedAt) <= c.config.TTL+c.config.GracePeriod {
			c.stats.hits.Add(1)
			return entry.key, nil
		}
	}

	// 2. Cache miss or expired entry: attempt on-demand refresh
	c.stats.misses.Add(1)
	if err := c.TriggerRefresh(ctx); err != nil && !errors.Is(err, ErrCooldownActive) {
		// If refresh failed but we have a grace-period key, return it
		if exists && now.Sub(entry.fetchedAt) <= c.config.TTL+c.config.GracePeriod {
			return entry.key, nil
		}
		return nil, err
	}

	// 3. Post-refresh lookup
	c.mu.RLock()
	entry, exists = c.keys[kid]
	c.mu.RUnlock()

	if !exists {
		return nil, ErrKeyNotFound
	}

	return entry.key, nil
}

// TriggerRefresh triggers an on-demand refresh respecting minimum cooldown limits.
func (c *JWKSCache) TriggerRefresh(ctx context.Context) error {
	if c.closed.Load() {
		return ErrCacheClosed
	}

	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()

	c.mu.RLock()
	last := c.lastRefresh
	c.mu.RUnlock()

	if time.Since(last) < c.config.MinRefreshInterval {
		return ErrCooldownActive
	}

	return c.refresh(ctx)
}

func (c *JWKSCache) refresh(ctx context.Context) error {
	if c.fetcher == nil {
		return nil
	}

	newKeys, err := c.fetcher(ctx)
	now := time.Now()

	if err != nil {
		c.mu.Lock()
		c.lastRefreshFail = now
		c.mu.Unlock()
		c.stats.refreshFailures.Add(1)
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.lastRefresh = now
	c.stats.refreshes.Add(1)

	// Replace active key registry
	for kid, k := range newKeys {
		c.keys[kid] = cachedKey{
			key:       k,
			fetchedAt: now,
		}
	}

	return nil
}

func (c *JWKSCache) rotaryLoop() {
	ticker := time.NewTicker(c.config.RefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			_ = c.refresh(c.ctx)
		}
	}
}

// Stats returns current operational telemetry.
func (c *JWKSCache) Stats() CacheStats {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return CacheStats{
		Hits:            c.stats.hits.Load(),
		Misses:          c.stats.misses.Load(),
		Refreshes:       c.stats.refreshes.Load(),
		RefreshFailures: c.stats.refreshFailures.Load(),
		ActiveKeys:      len(c.keys),
		LastRefreshedAt: c.lastRefresh,
	}
}

// Close terminates the background rotary loop.
func (c *JWKSCache) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		c.cancel()
	}
	return nil
}
