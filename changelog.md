Heres what another AI agent suggested

Perfect 👍 — let’s rewrite your session handling into a concurrency-safe `SessionStore` and fix the lifecycle issues (state vs. code, token lookup, cleanup).

Here’s a **drop-in refactor** of your session storage:

---

### 1. New `SessionStore`

```go
package server

import (
	"sync"
	"time"
)

type SessionStore struct {
	mu       sync.RWMutex
	byState  map[string]SessionData
	byCode   map[string]SessionData
	byToken  map[string]SessionData
}

func NewSessionStore() *SessionStore {
	return &SessionStore{
		byState: make(map[string]SessionData),
		byCode:  make(map[string]SessionData),
		byToken: make(map[string]SessionData),
	}
}

func (s *SessionStore) SaveState(state string, data SessionData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.byState[state] = data
}

func (s *SessionStore) GetByState(state string) (SessionData, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, ok := s.byState[state]
	return data, ok
}

func (s *SessionStore) PromoteCode(state, code string, data SessionData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byState, state)
	s.byCode[code] = data
}

func (s *SessionStore) GetByCode(code string) (SessionData, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, ok := s.byCode[code]
	return data, ok
}

func (s *SessionStore) SaveToken(data SessionData) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if data.AccessToken != "" {
		s.byToken[data.AccessToken] = data
	}
}

func (s *SessionStore) GetByToken(token string) (SessionData, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	data, ok := s.byToken[token]
	if !ok {
		return SessionData{}, false
	}
	// Check expiry
	if time.Now().After(data.ExpiresAt) {
		return SessionData{}, false
	}
	return data, true
}

func (s *SessionStore) DeleteCode(code string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byCode, code)
}
```

---

### 2. Update `Server` struct

```go
type Server struct {
	Router        *gin.Engine
	Sessions      *SessionStore
	Clients       map[string]Client
	Provider      providers.Provider
	ProtectedPath string
	OAuthDomain   string
	DevMode       bool
	AllowedEmails []string
}
```

And in `NewServer`:

```go
server := &Server{
	Router:        router,
	Sessions:      NewSessionStore(),
	Clients:       make(map[string]Client),
	ProtectedPath: protectedPath,
	OAuthDomain:   oauthDomain,
	DevMode:       devMode,
	AllowedEmails: []string{},
}
```

---

### 3. Fix `authorizeHandler`

```go
// Store session by state
s.Sessions.SaveState(state, SessionData{
	State:        state,
	CodeVerifier: codeVerifier,
	ClientID:     clientID,
	RedirectURI:  redirectURI,
	Nonce:        nonce,
})
```

---

### 4. Fix `callbackHandler`

```go
sessionData, exists := s.Sessions.GetByState(state)
if !exists {
	c.JSON(400, gin.H{"error": "invalid_request", "error_description": "Invalid state"})
	return
}

// Exchange tokens...
sessionData.AccessToken = accessToken
sessionData.IDToken = idToken
sessionData.Email = email
sessionData.ExpiresAt = time.Now().Add(time.Hour)

// Promote state → code mapping
s.Sessions.PromoteCode(state, code, sessionData)
// Save token for lookup
s.Sessions.SaveToken(sessionData)
```

---

### 5. Fix `tokenHandler`

```go
sessionData, found := s.Sessions.GetByCode(code)
if !found {
	c.JSON(400, gin.H{"error": "invalid_grant", "error_description": "Invalid authorization code"})
	return
}

// return tokens...
c.JSON(200, gin.H{
	"access_token": sessionData.AccessToken,
	"token_type":   "Bearer",
	"expires_in":   int(time.Until(sessionData.ExpiresAt).Seconds()),
	"id_token":     sessionData.IDToken,
})

// One-time code → delete after use
s.Sessions.DeleteCode(code)
```

---

### 6. Fix `sseHandler` (token validation)

```go
sessionData, ok := s.Sessions.GetByToken(token)
if !ok {
	c.Header("WWW-Authenticate", s.buildWWWAuthenticateHeader()+" error=\"invalid_token\"")
	c.JSON(401, gin.H{"status": 401, "message": "Invalid or expired token"})
	return
}
```

---

✅ **What we fixed**

* **Concurrency safety**: sessions now protected by `sync.RWMutex`.
* **State/code lifecycle**: state is temporary, gets promoted to code, then removed.
* **Token lookup**: direct lookup instead of scanning entire session map.
* **Expiry handling**: invalid/expired tokens are rejected properly.
* **Memory cleanup**: no dangling state entries.

---


