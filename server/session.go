package server

import (
	"sync"
	"time"
	"fmt"
	"github.com/rs/zerolog/log"
	"github.com/golang-jwt/jwt/v5"
)

var jwtSecret = []byte("my-secret-key") // ⚠️ move to config/env

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

func toStringSlice(val interface{}) []string {
    if arr, ok := val.([]interface{}); ok {
        out := make([]string, 0, len(arr))
        for _, v := range arr {
            if s, ok := v.(string); ok {
                out = append(out, s)
            }
        }
        return out
    }
    return nil
}

// GetByToken retrieves session data by the access token and checks for expiry.
// Falls back to validating a JWT if not found in the session store.
func (s *SessionStore) GetByToken(token string) (SessionData, bool) {
    s.mu.RLock()
    data, ok := s.byToken[token]
    s.mu.RUnlock()

    // First check in-memory session
    if ok {
        if time.Now().After(data.ExpiresAt) {
            return SessionData{}, false
        }
        return data, true
    }

    // --- Fallback: validate JWT ---
    claims, err := validateJWT(token)
    if err != nil {
        return SessionData{}, false
    }

    exp, ok := (*claims)["exp"].(float64)
    if !ok {
        return SessionData{}, false
    }

    // Extract email (if present in JWT claims)
    var email string
    if rawEmail, ok := (*claims)["email"].(string); ok {
        email = rawEmail
    }

    // Extract scopes (if present in JWT claims)
    var scopes []string
    if rawScopes, ok := (*claims)["scopes"]; ok {
        scopes = toStringSlice(rawScopes)
    }

    session := SessionData{
        AccessToken: token,
        ExpiresAt:   time.Unix(int64(exp), 0),
        Email:       email,
        Scopes:      scopes,
    }

    return session, true
}

// CleanupExpired removes expired sessions from the store.
func (s *SessionStore) CleanupExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now()
	cleaned := 0
	for token, data := range s.byToken {
		if now.After(data.ExpiresAt) {
			delete(s.byToken, token)
			cleaned++
		}
	}
	if cleaned > 0 {
		log.Info().Int("count", cleaned).Msg("Cleaned up expired sessions")
	}
}

// mintCFAuthorizationJWT creates a signed JWT for the CF_Authorization cookie.
func mintCFAuthorizationJWT(email string, scopes []string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"sub":    email,
		"email":  email,
		"scopes": scopes,
		"iat":    now.Unix(),
		"exp":    now.Add(ttl).Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSecret)
}

func validateJWT(tokenStr string) (*jwt.MapClaims, error) {
    parsed, err := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
        // Ensure HMAC is used
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
        }
        return jwtSecret, nil
    })
    if err != nil || !parsed.Valid {
        return nil, fmt.Errorf("invalid token: %w", err)
    }

    claims, ok := parsed.Claims.(jwt.MapClaims)
    if !ok {
        return nil, fmt.Errorf("invalid claims type")
    }
    return &claims, nil
}