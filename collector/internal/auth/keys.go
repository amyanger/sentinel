// Package auth handles API key storage and request authentication.
// Keys are shared-secret bearer tokens. Comparison is constant-time.
package auth

import (
	"crypto/subtle"
	"strings"
	"sync"
)

// KeyStore maps client names to their API keys. Thread-safe.
type KeyStore struct {
	mu   sync.RWMutex
	keys map[string]string // key -> client name
}

func NewKeyStore() *KeyStore {
	return &KeyStore{keys: make(map[string]string)}
}

// Add registers an API key for a client name.
func (ks *KeyStore) Add(clientName, apiKey string) {
	ks.mu.Lock()
	defer ks.mu.Unlock()
	ks.keys[apiKey] = clientName
}

// Verify checks whether apiKey matches any registered key.
// Returns the associated client name and true on success.
// Uses constant-time comparison to avoid timing side channels.
func (ks *KeyStore) Verify(apiKey string) (string, bool) {
	if apiKey == "" {
		return "", false
	}
	ks.mu.RLock()
	defer ks.mu.RUnlock()
	for storedKey, name := range ks.keys {
		if subtle.ConstantTimeCompare([]byte(storedKey), []byte(apiKey)) == 1 {
			return name, true
		}
	}
	return "", false
}

// AdminStore maps admin names to their API keys. Thread-safe.
// Admin keys grant fleet-wide read access on /v1/events[/{id}] and are
// distinct from client keys to prevent accidental privilege escalation
// from a leaked endpoint credential.
type AdminStore struct {
	mu   sync.RWMutex
	keys map[string]string // key -> admin name
}

func NewAdminStore() *AdminStore {
	return &AdminStore{keys: make(map[string]string)}
}

// Add registers an API key for an admin name.
func (as *AdminStore) Add(adminName, apiKey string) {
	as.mu.Lock()
	defer as.mu.Unlock()
	as.keys[apiKey] = adminName
}

// Verify checks whether apiKey matches any registered admin key.
// Returns the associated admin name and true on success.
func (as *AdminStore) Verify(apiKey string) (string, bool) {
	if apiKey == "" {
		return "", false
	}
	as.mu.RLock()
	defer as.mu.RUnlock()
	for storedKey, name := range as.keys {
		if subtle.ConstantTimeCompare([]byte(storedKey), []byte(apiKey)) == 1 {
			return name, true
		}
	}
	return "", false
}

// ParseBearer extracts the token from an "Authorization: Bearer <token>"
// header value. Returns (token, true) on success. Scheme match is
// case-insensitive.
func ParseBearer(header string) (string, bool) {
	const prefix = "bearer "
	if len(header) <= len(prefix) {
		return "", false
	}
	if !strings.EqualFold(header[:len(prefix)], prefix) {
		return "", false
	}
	token := strings.TrimSpace(header[len(prefix):])
	if token == "" {
		return "", false
	}
	return token, true
}
