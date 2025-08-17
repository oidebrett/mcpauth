package server

import (
	"sync"
	"time"
)

// SessionStore provides a concurrency-safe store for session data.
type SessionStore struct {
	mu      sync.RWMutex
	byState map[string]SessionData
	byCode  map[string]SessionData
	byToken map[string]SessionData
}

// NewSessionStore creates a new SessionStore.
func NewSessionStore() *SessionStore {
	return &SessionStore{
		byState: make(map[string]SessionData),
		byCode:  make(map[string]SessionData),
		byToken: make(map[string]SessionData),
	}
}

// SaveState stores session data by the state parameter.
func (s *SessionStore) SaveState(state string, data SessionData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byState[state] = data
}

// GetByState retrieves session data by the state parameter.
func (s *SessionStore) GetByState(state string) (SessionData, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, ok := s.byState[state]
	return data, ok
}

// DeleteState removes session data associated with a state.
func (s *SessionStore) DeleteState(state string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byState, state)
}

// SaveCode stores session data by the authorization code.
func (s *SessionStore) SaveCode(code string, data SessionData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byCode[code] = data
}

// GetByCode retrieves session data by the authorization code.
func (s *SessionStore) GetByCode(code string) (SessionData, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, ok := s.byCode[code]
	return data, ok
}

// DeleteCode removes session data associated with an authorization code.
func (s *SessionStore) DeleteCode(code string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byCode, code)
}

// SaveToken stores session data by the access token for quick validation.
func (s *SessionStore) SaveToken(token string, data SessionData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if token != "" {
		s.byToken[token] = data
	}
}

// GetByToken retrieves session data by the access token and checks for expiry.
func (s *SessionStore) GetByToken(token string) (SessionData, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, ok := s.byToken[token]
	if !ok {
		return SessionData{}, false
	}

	// Check for expiry
	if time.Now().After(data.ExpiresAt) {
		// Token is expired, don't return it.
		// A separate cleanup process could remove expired tokens from the store.
		return SessionData{}, false
	}
	return data, true
}
