package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/nats-io/nats.go"
)

// Config holds the plugin configuration
type Config struct {
	Enabled      bool     `json:"enabled,omitempty"`
	NatsURL      string   `json:"natsUrl,omitempty"`
	NatsToken    string   `json:"natsToken,omitempty"`
	AuthSubject  string   `json:"authSubject,omitempty"`
	Timeout      string   `json:"timeout,omitempty"`
	CacheEnabled bool     `json:"cacheEnabled,omitempty"`
	CacheTTL     string   `json:"cacheTTL,omitempty"`
	HeaderName   string   `json:"headerName,omitempty"`   // e.g., "Authorization"
	AllowedPaths []string `json:"allowedPaths,omitempty"` // Paths to skip auth
}

// CreateConfig creates the default plugin configuration
func CreateConfig() *Config {
	return &Config{
		Enabled:      true,
		NatsURL:      "nats://localhost:4222",
		AuthSubject:  "auth.verify",
		Timeout:      "2s",
		CacheEnabled: true,
		CacheTTL:     "5m",
		HeaderName:   "Authorization",
		AllowedPaths: []string{},
	}
}

// AuthPlugin holds the plugin state
type AuthPlugin struct {
	next     http.Handler
	name     string
	config   *Config
	natsConn *nats.Conn
	cache    *authCache
	timeout  time.Duration
	cacheTTL time.Duration
}

// authCache provides simple in-memory caching
type authCache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	ttl     time.Duration
}

type cacheEntry struct {
	valid     bool
	expiresAt time.Time
	userId    string
	metadata  map[string]string
}

// AuthRequest is sent to the auth microservice
type AuthRequest struct {
	Token   string            `json:"token"`
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers,omitempty"`
}

// AuthResponse is received from the auth microservice
type AuthResponse struct {
	Valid    bool              `json:"valid"`
	UserId   string            `json:"userId,omitempty"`
	Metadata map[string]string `json:"metadata,omitempty"`
	Error    string            `json:"error,omitempty"`
}

// New creates a new AuthPlugin
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if !config.Enabled {
		return next, nil
	}

	timeout, err := time.ParseDuration(config.Timeout)
	if err != nil {
		return nil, fmt.Errorf("invalid timeout: %w", err)
	}

	cacheTTL, err := time.ParseDuration(config.CacheTTL)
	if err != nil {
		return nil, fmt.Errorf("invalid cache TTL: %w", err)
	}

	// Connect to NATS
	opts := []nats.Option{
		nats.Name("Traefik Auth Plugin"),
		nats.Timeout(timeout),
		nats.ReconnectWait(2 * time.Second),
		nats.MaxReconnects(-1), // Infinite reconnects
	}

	if config.NatsToken != "" {
		opts = append(opts, nats.Token(config.NatsToken))
	}

	nc, err := nats.Connect(config.NatsURL, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to NATS: %w", err)
	}

	plugin := &AuthPlugin{
		next:     next,
		name:     name,
		config:   config,
		natsConn: nc,
		timeout:  timeout,
		cacheTTL: cacheTTL,
	}

	if config.CacheEnabled {
		plugin.cache = newAuthCache(cacheTTL)
		go plugin.cache.cleanupExpired()
	}

	return plugin, nil
}

func (a *AuthPlugin) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// Check if path is in allowed list (skip auth)
	for _, path := range a.config.AllowedPaths {
		if req.URL.Path == path {
			a.next.ServeHTTP(rw, req)
			return
		}
	}

	// Extract token from header
	token := req.Header.Get(a.config.HeaderName)
	if token == "" {
		http.Error(rw, "Unauthorized: Missing authentication token", http.StatusUnauthorized)
		return
	}

	// Check cache first
	if a.config.CacheEnabled {
		if entry, valid := a.cache.get(token); valid {
			// Add user info to request headers
			req.Header.Set("X-User-Id", entry.userId)
			for k, v := range entry.metadata {
				req.Header.Set(fmt.Sprintf("X-Auth-%s", k), v)
			}
			a.next.ServeHTTP(rw, req)
			return
		}
	}

	// Authenticate via NATS
	authReq := AuthRequest{
		Token:  token,
		Method: req.Method,
		Path:   req.URL.Path,
		Headers: map[string]string{
			"User-Agent": req.Header.Get("User-Agent"),
			"X-Real-IP":  req.Header.Get("X-Real-IP"),
		},
	}

	reqData, err := json.Marshal(authReq)
	if err != nil {
		http.Error(rw, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Send request and wait for response
	msg, err := a.natsConn.Request(a.config.AuthSubject, reqData, a.timeout)
	if err != nil {
		http.Error(rw, "Authentication Service Unavailable", http.StatusServiceUnavailable)
		return
	}

	var authResp AuthResponse
	if err := json.Unmarshal(msg.Data, &authResp); err != nil {
		http.Error(rw, "Invalid Authentication Response", http.StatusInternalServerError)
		return
	}

	if !authResp.Valid {
		http.Error(rw, fmt.Sprintf("Unauthorized: %s", authResp.Error), http.StatusUnauthorized)
		return
	}

	// Cache successful authentication
	if a.config.CacheEnabled {
		a.cache.set(token, &cacheEntry{
			valid:     true,
			expiresAt: time.Now().Add(a.cacheTTL),
			userId:    authResp.UserId,
			metadata:  authResp.Metadata,
		})
	}

	// Add user info to request headers
	req.Header.Set("X-User-Id", authResp.UserId)
	for k, v := range authResp.Metadata {
		req.Header.Set(fmt.Sprintf("X-Auth-%s", k), v)
	}

	a.next.ServeHTTP(rw, req)
}

// Cache implementation
func newAuthCache(ttl time.Duration) *authCache {
	return &authCache{
		entries: make(map[string]*cacheEntry),
		ttl:     ttl,
	}
}

func (c *authCache) get(token string) (*cacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := hashToken(token)
	entry, exists := c.entries[key]
	if !exists {
		return nil, false
	}

	if time.Now().After(entry.expiresAt) {
		return nil, false
	}

	return entry, entry.valid
}

func (c *authCache) set(token string, entry *cacheEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()

	key := hashToken(token)
	c.entries[key] = entry
}

func (c *authCache) cleanupExpired() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		now := time.Now()
		for key, entry := range c.entries {
			if now.After(entry.expiresAt) {
				delete(c.entries, key)
			}
		}
		c.mu.Unlock()
	}
}

func hashToken(token string) string {
	hash := sha256.Sum256([]byte(token))
	return hex.EncodeToString(hash[:])
}
