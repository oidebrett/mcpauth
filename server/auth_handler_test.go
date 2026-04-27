package server

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// newTestServer builds a minimal Server suitable for authHandler tests — no DB required.
func newTestServer() *Server {
	gin.SetMode(gin.TestMode)
	router := gin.New()
	s := &Server{
		Router:   router,
		Sessions: NewSessionStore(),
	}
	router.Any("/auth", s.authHandler)
	return s
}

func TestAuthHandler_StaticToken_Accepted(t *testing.T) {
	t.Setenv("AUTHORIZATION_BEARER_TOKEN", "supersecret")

	s := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	req.Header.Set("Authorization", "Bearer supersecret")
	w := httptest.NewRecorder()

	s.Router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Header().Get("X-Forwarded-User") != "static-authorized-user" {
		t.Fatalf("expected X-Forwarded-User=static-authorized-user, got %q", w.Header().Get("X-Forwarded-User"))
	}
}

func TestAuthHandler_StaticToken_WrongToken_Rejected(t *testing.T) {
	t.Setenv("AUTHORIZATION_BEARER_TOKEN", "supersecret")

	s := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	req.Header.Set("Authorization", "Bearer wrongtoken")
	w := httptest.NewRecorder()

	s.Router.ServeHTTP(w, req)

	// Wrong token falls through to session lookup which will find nothing → 401
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestAuthHandler_StaticTokenEnvUnset_FallsThrough(t *testing.T) {
	t.Setenv("AUTHORIZATION_BEARER_TOKEN", "")

	s := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	req.Header.Set("Authorization", "Bearer anytoken")
	w := httptest.NewRecorder()

	s.Router.ServeHTTP(w, req)

	// No static token configured, no session → 401 via normal OAuth path
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestAuthHandler_NoToken_Rejected(t *testing.T) {
	t.Setenv("AUTHORIZATION_BEARER_TOKEN", "")

	s := newTestServer()
	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	w := httptest.NewRecorder()

	s.Router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}

func TestAuthHandler_SessionToken_Accepted(t *testing.T) {
	t.Setenv("AUTHORIZATION_BEARER_TOKEN", "")

	s := newTestServer()

	// Seed a valid session token
	s.Sessions.SaveToken("valid-session-token", SessionData{
		Email:     "user@example.com",
		ExpiresAt: time.Now().Add(time.Hour),
	})

	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	req.Header.Set("Authorization", "Bearer valid-session-token")
	w := httptest.NewRecorder()

	s.Router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Header().Get("X-Forwarded-User") != "user@example.com" {
		t.Fatalf("expected X-Forwarded-User=user@example.com, got %q", w.Header().Get("X-Forwarded-User"))
	}
}

func TestAuthHandler_StaticToken_DoesNotInterfereWithSession(t *testing.T) {
	t.Setenv("AUTHORIZATION_BEARER_TOKEN", "supersecret")

	s := newTestServer()

	// A different valid session token should still work via normal OAuth path
	s.Sessions.SaveToken("valid-session-token", SessionData{
		Email:     "user@example.com",
		ExpiresAt: time.Now().Add(time.Hour),
	})

	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	req.Header.Set("Authorization", "Bearer valid-session-token")
	w := httptest.NewRecorder()

	s.Router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Header().Get("X-Forwarded-User") != "user@example.com" {
		t.Fatalf("expected X-Forwarded-User=user@example.com, got %q", w.Header().Get("X-Forwarded-User"))
	}
}
