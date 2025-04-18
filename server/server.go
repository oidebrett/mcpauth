package server

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"

	"mcpauth/server/providers/google"
)

// Client represents an OAuth client
type Client struct {
	ClientID     string   `json:"client_id"`
	ClientName   string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
	// Add other client properties as needed
}

// Server represents the OAuth server
type Server struct {
	Router         *gin.Engine
	Sessions       map[string]SessionData
	Clients        map[string]Client
	GoogleProvider *google.Provider
	ProtectedPath  string
	BaseDomain     string
	DevMode        bool
}

// SessionData stores OAuth state and session information
type SessionData struct {
	State        string
	CodeVerifier string
	ClientID     string
	RedirectURI  string
	Nonce        string
	AccessToken  string
	IDToken      string
	ExpiresAt    time.Time
}

// NewServer creates a new server instance
func NewServer(protectedPath, baseDomain string, devMode bool) *Server {
	router := gin.Default()

	server := &Server{
		Router:        router,
		Sessions:      make(map[string]SessionData),
		Clients:       make(map[string]Client),
		ProtectedPath: protectedPath,
		BaseDomain:    baseDomain,
		DevMode:       devMode,
	}

	// Set up routes
	router.GET("/.well-known/oauth-authorization-server", server.oauthAuthorizationServerHandler)
	router.POST("/register", server.registerHandler)
	router.GET("/authorize", server.authorizeHandler)
	router.GET("/callback", server.callbackHandler)
	router.POST("/token", server.tokenHandler)
	router.GET(protectedPath, server.unauthorizedHandler) // Changed to unauthorizedHandler

	return server
}

// SetGoogleOAuthConfig sets the Google OAuth configuration
func (s *Server) SetGoogleOAuthConfig(clientID, clientSecret, redirectURI string, scopes []string) {
	s.GoogleProvider = google.NewProvider(clientID, clientSecret, redirectURI, scopes)
}

// SetupRoutes configures all the routes for the server
func (s *Server) SetupRoutes() {
	// Add a health check endpoint
	s.Router.GET("/health", s.healthCheckHandler)

	// Add OAuth authorization server metadata endpoint
	s.Router.GET("/.well-known/oauth-authorization-server", s.oauthAuthorizationServerHandler)

	// Add OPTIONS handler for the OAuth authorization server metadata endpoint
	s.Router.OPTIONS("/.well-known/oauth-authorization-server", s.optionsHandler)

	// Add OAuth client registration endpoint
	s.Router.POST("/register", s.registerHandler)
	s.Router.OPTIONS("/register", s.optionsHandler)

	// OAuth endpoints
	s.Router.GET("/authorize", s.authorizeHandler)
	s.Router.GET("/callback", s.callbackHandler)
	s.Router.POST("/token", s.tokenHandler)
	s.Router.OPTIONS("/token", s.optionsHandler)

	// Add SSE endpoint
	s.Router.GET("/sse", s.sseHandler)
}

// unauthorizedHandler returns a 401 Unauthorized response
func (s *Server) unauthorizedHandler(c *gin.Context) {
	log.Info().Str("path", c.Request.URL.Path).Msg("Received request to protected path")

	// Set WWW-Authenticate header
	c.Header("WWW-Authenticate", "Basic realm=\"mcpauth\"")

	c.JSON(401, gin.H{
		"status":  401,
		"message": "Unauthorized",
	})
}

// healthCheckHandler returns a 200 OK response
func (s *Server) healthCheckHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"status":  200,
		"message": "OK",
	})
}

// oauthAuthorizationServerHandler handles requests for OAuth authorization server metadata
func (s *Server) oauthAuthorizationServerHandler(c *gin.Context) {
	log.Info().Str("path", c.Request.URL.Path).Msg("Received request for OAuth authorization server metadata")

	// Set CORS headers
	origin := c.Request.Header.Get("Origin")
	if origin == "" {
		origin = "*"
	}
	c.Header("Access-Control-Allow-Origin", origin)
	c.Header("Access-Control-Allow-Methods", "GET, OPTIONS")
	c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")

	// Determine protocol based on dev mode
	protocol := "https"
	if s.DevMode {
		protocol = "http"
	}

	// Check for X-Forwarded-Host header to support proxying
	baseDomain := s.BaseDomain
	forwardedHost := c.Request.Header.Get("X-Forwarded-Host")
	if forwardedHost != "" {
		log.Info().Str("forwarded_host", forwardedHost).Msg("Using forwarded host for OAuth metadata")
		baseDomain = forwardedHost
	}

	c.JSON(200, gin.H{
		"issuer":                                fmt.Sprintf("%s://%s", protocol, baseDomain),
		"authorization_endpoint":                fmt.Sprintf("%s://%s/authorize", protocol, baseDomain),
		"token_endpoint":                        fmt.Sprintf("%s://%s/token", protocol, baseDomain),
		"registration_endpoint":                 fmt.Sprintf("%s://%s/register", protocol, baseDomain),
		"response_types_supported":              []string{"code"},
		"response_modes_supported":              []string{"query"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"revocation_endpoint":                   fmt.Sprintf("%s://%s/token", protocol, baseDomain),
		"code_challenge_methods_supported":      []string{"plain", "S256"},
	})
}

// optionsHandler handles OPTIONS requests with CORS headers
func (s *Server) optionsHandler(c *gin.Context) {
	// Get the Origin header from the request
	origin := c.Request.Header.Get("Origin")
	if origin == "" {
		origin = "*"
	}

	// Set CORS headers to match the working example
	c.Header("Access-Control-Allow-Origin", origin)
	c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")
	c.Header("Access-Control-Max-Age", "86400") // 24 hours
	c.Header("Access-Control-Allow-Credentials", "true")

	// Respond with 204 No Content
	c.Status(204)
}

// registerHandler handles client registration
func (s *Server) registerHandler(c *gin.Context) {
	log.Info().Str("path", c.Request.URL.Path).Msg("Received client registration request")

	// Set CORS headers
	origin := c.Request.Header.Get("Origin")
	if origin == "" {
		origin = "*"
	}
	c.Header("Access-Control-Allow-Origin", origin)
	c.Header("Access-Control-Allow-Methods", "POST, OPTIONS")
	c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type, mcp-protocol-version")
	c.Header("Access-Control-Allow-Credentials", "true")

	var registration struct {
		ClientName   string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
	}

	if err := c.BindJSON(&registration); err != nil {
		c.JSON(400, gin.H{"error": "invalid_request"})
		return
	}

	// Generate a client ID
	clientID := "client-" + generateRandomString(16)

	// Store the client
	s.Clients[clientID] = Client{
		ClientID:     clientID,
		ClientName:   registration.ClientName,
		RedirectURIs: registration.RedirectURIs,
	}

	log.Info().
		Str("client_id", clientID).
		Str("client_name", registration.ClientName).
		Interface("redirect_uris", registration.RedirectURIs).
		Msg("Registered new client")

	// Return the client credentials
	c.JSON(201, gin.H{
		"client_id":     clientID,
		"client_name":   registration.ClientName,
		"redirect_uris": registration.RedirectURIs,
	})
}

// Generate a random string for state, nonce, etc.
func generateRandomString(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)[:length]
}

// authorizeHandler initiates the OAuth flow
func (s *Server) authorizeHandler(c *gin.Context) {
	log.Info().Str("path", c.Request.URL.Path).Msg("Received authorization request")

	// Check if Google provider is configured
	if s.GoogleProvider == nil {
		log.Error().Msg("Google provider not configured")
		c.JSON(500, gin.H{
			"error":             "server_error",
			"error_description": "OAuth provider not configured",
		})
		return
	}

	// Get query parameters
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	responseType := c.Query("response_type")
	scope := c.Query("scope")
	state := c.Query("state")

	log.Debug().
		Str("client_id", clientID).
		Str("redirect_uri", redirectURI).
		Str("response_type", responseType).
		Str("scope", scope).
		Str("state", state).
		Msg("Authorization request parameters")

	// Validate response type
	if responseType != "code" {
		c.JSON(400, gin.H{
			"error":             "unsupported_response_type",
			"error_description": "Only 'code' response type is supported",
		})
		return
	}

	// Generate a random state if not provided
	if state == "" {
		state = generateRandomString(32)
	}

	// Generate a code verifier and nonce
	codeVerifier := generateRandomString(64)
	nonce := generateRandomString(32)

	// Store session data
	s.Sessions[state] = SessionData{
		State:        state,
		CodeVerifier: codeVerifier,
		ClientID:     clientID,
		RedirectURI:  redirectURI,
		Nonce:        nonce,
	}

	log.Debug().Str("state", state).Msg("Stored session data")

	// Redirect to Google OAuth
	authURL := s.GoogleProvider.GetAuthURL(state, codeVerifier, nonce)
	c.Redirect(http.StatusTemporaryRedirect, authURL)
}

// callbackHandler processes the OAuth callback from Google
func (s *Server) callbackHandler(c *gin.Context) {
	log.Info().Str("path", c.Request.URL.Path).Msg("Received callback from Google")

	// Get the authorization code and state from the request
	code := c.Query("code")
	state := c.Query("state")

	log.Debug().Str("code", code).Str("state", state).Msg("Callback parameters")

	// Validate state parameter to prevent CSRF
	sessionData, exists := s.Sessions[state]
	if !exists {
		log.Error().Str("state", state).Msg("Invalid state parameter")
		c.JSON(400, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid state parameter",
		})
		return
	}

	// Exchange the authorization code for tokens
	accessToken, idToken, err := s.GoogleProvider.ExchangeToken(code, sessionData.CodeVerifier)
	if err != nil {
		log.Error().Err(err).Msg("Failed to exchange token")
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	log.Debug().
		Str("access_token_length", fmt.Sprintf("%d", len(accessToken))).
		Str("id_token_length", fmt.Sprintf("%d", len(idToken))).
		Msg("Tokens received from provider")

	// Store tokens in session
	sessionData.AccessToken = accessToken
	sessionData.IDToken = idToken
	sessionData.ExpiresAt = time.Now().Add(time.Hour) // Approximate expiry
	s.Sessions[state] = sessionData

	// Store the code for token exchange
	s.Sessions[code] = sessionData

	log.Debug().Str("state", state).Str("code", code).Msg("Stored tokens in session")

	// Redirect back to the client with the authorization code
	redirectURL, err := url.Parse(sessionData.RedirectURI)
	if err != nil {
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	q := redirectURL.Query()
	q.Set("code", code)
	q.Set("state", state)
	redirectURL.RawQuery = q.Encode()

	log.Debug().Str("redirect_url", redirectURL.String()).Msg("Redirecting to client")

	c.Redirect(http.StatusTemporaryRedirect, redirectURL.String())
}

// tokenHandler processes token requests
func (s *Server) tokenHandler(c *gin.Context) {
	log.Info().Str("path", c.Request.URL.Path).Msg("Received token request")

	// Get form parameters
	grantType := c.PostForm("grant_type")
	code := c.PostForm("code")
	redirectURI := c.PostForm("redirect_uri")
	clientID := c.PostForm("client_id")
	// clientSecret is unused but we'll keep it for future use
	_ = c.PostForm("client_secret")

	log.Debug().
		Str("grant_type", grantType).
		Str("code", code).
		Str("redirect_uri", redirectURI).
		Str("client_id", clientID).
		Msg("Token request parameters")

	// Validate grant type
	if grantType != "authorization_code" {
		log.Error().Str("grant_type", grantType).Msg("Unsupported grant type")
		c.JSON(400, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": "Only authorization_code grant type is supported",
		})
		return
	}

	// Validate client credentials - check if it's a registered client
	_, clientExists := s.Clients[clientID]
	if !clientExists {
		log.Error().Str("client_id", clientID).Msg("Unknown client")
		c.JSON(400, gin.H{
			"error":             "invalid_client",
			"error_description": "Unknown client",
		})
		return
	}

	// Find the session with this code
	sessionData, found := s.Sessions[code]
	if !found {
		log.Error().Str("code", code).Msg("Invalid authorization code")
		c.JSON(400, gin.H{
			"error":             "invalid_grant",
			"error_description": "Invalid authorization code",
		})
		return
	}

	// Validate that the client ID in the token request matches the one in the session
	if sessionData.ClientID != clientID {
		log.Error().
			Str("provided_client_id", clientID).
			Str("expected_client_id", sessionData.ClientID).
			Msg("Client ID mismatch")
		c.JSON(400, gin.H{
			"error":             "invalid_grant",
			"error_description": "Client ID mismatch",
		})
		return
	}

	// Validate that the redirect URI matches
	if sessionData.RedirectURI != redirectURI {
		log.Error().
			Str("provided_redirect_uri", redirectURI).
			Str("expected_redirect_uri", sessionData.RedirectURI).
			Msg("Redirect URI mismatch")
		c.JSON(400, gin.H{
			"error":             "invalid_grant",
			"error_description": "Redirect URI mismatch",
		})
		return
	}

	log.Debug().
		Str("code", code).
		Bool("access_token_empty", sessionData.AccessToken == "").
		Bool("id_token_empty", sessionData.IDToken == "").
		Time("expires_at", sessionData.ExpiresAt).
		Msg("Session data for token request")

	// Return the tokens
	c.JSON(200, gin.H{
		"access_token": sessionData.AccessToken,
		"token_type":   "Bearer",
		"expires_in":   int(time.Until(sessionData.ExpiresAt).Seconds()),
		"id_token":     sessionData.IDToken,
	})

	// Clean up sessions after use
	delete(s.Sessions, code)
}

// sseHandler handles Server-Sent Events connections authentication only
func (s *Server) sseHandler(c *gin.Context) {
	log.Info().Str("path", c.Request.URL.Path).Msg("Received SSE auth request")

	// Get the authorization header or query parameter
	authHeader := c.GetHeader("Authorization")
	tokenParam := c.Query("access_token")

	log.Debug().
		Str("auth_header", authHeader).
		Str("token_param", tokenParam).
		Msg("Authorization received")

	var token string

	// Check if the authorization header is present and has the correct format
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
		log.Debug().Str("token_source", "header").Msg("Using token from Authorization header")
	} else if tokenParam != "" {
		token = tokenParam
		log.Debug().Str("token_source", "query").Msg("Using token from query parameter")
	} else {
		log.Warn().Msg("Missing or invalid authorization")
		c.Header("WWW-Authenticate", "Bearer realm=\"mcpauth\"")
		c.JSON(401, gin.H{
			"error":             "unauthorized",
			"error_description": "Missing or invalid authorization",
		})
		return
	}

	// Validate the token (simple check for now - just see if it exists in any session)
	var validToken bool
	var matchedSession string

	// Log all sessions for debugging
	log.Debug().Int("session_count", len(s.Sessions)).Msg("Checking sessions")
	for key, session := range s.Sessions {
		// Only log part of the token for security
		tokenPrefix := ""
		if session.AccessToken != "" && len(session.AccessToken) > 10 {
			tokenPrefix = session.AccessToken[:10] + "..."
		}
		log.Debug().Str("session_key", key).Str("session_token_prefix", tokenPrefix).Msg("Session details")

		if session.AccessToken == token {
			validToken = true
			matchedSession = key
			break
		}
	}

	if !validToken {
		log.Warn().Str("token_prefix", token[:min(10, len(token))]+"...").Msg("Invalid token - not found in any session")
		c.Header("WWW-Authenticate", "Bearer realm=\"mcpauth\"")
		c.JSON(401, gin.H{
			"error":             "unauthorized",
			"error_description": "Invalid token",
		})
		return
	}

	log.Info().Str("session_key", matchedSession).Msg("Token validated successfully")

	// For forward auth, just return 200 OK if authentication is successful
	c.Status(http.StatusOK)
}

// messageHandler processes messages sent from the client and forwards them to the remote server
func (s *Server) messageHandler(c *gin.Context) {
	log.Info().Str("path", c.Request.URL.Path).Msg("Received message from client")

	// Set CORS headers
	origin := c.Request.Header.Get("Origin")
	if origin == "" {
		origin = "*"
	}
	c.Header("Access-Control-Allow-Origin", origin)
	c.Header("Access-Control-Allow-Methods", "POST, OPTIONS")
	c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")
	c.Header("Access-Control-Allow-Credentials", "true")

	// Get the authorization header
	authHeader := c.GetHeader("Authorization")
	var token string

	// Check if the authorization header is present and has the correct format
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	} else {
		log.Warn().Msg("Missing or invalid authorization")
		c.Header("WWW-Authenticate", "Bearer realm=\"mcpauth\"")
		c.JSON(401, gin.H{
			"error":             "unauthorized",
			"error_description": "Missing or invalid authorization",
		})
		return
	}

	// Validate the token (simple check for now - just see if it exists in any session)
	var validToken bool

	for _, session := range s.Sessions {
		if session.AccessToken == token {
			validToken = true
			break
		}
	}

	if !validToken {
		log.Warn().Str("token_prefix", token[:min(10, len(token))]+"...").Msg("Invalid token")
		c.Header("WWW-Authenticate", "Bearer realm=\"mcpauth\"")
		c.JSON(401, gin.H{
			"error":             "unauthorized",
			"error_description": "Invalid token",
		})
		return
	}

	// Parse the message from the request body
	var messageRequest struct {
		Message string `json:"message"`
	}

	if err := c.ShouldBindJSON(&messageRequest); err != nil {
		log.Error().Err(err).Msg("Failed to parse message request")
		c.JSON(400, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid message format",
		})
		return
	}

	log.Info().Str("message", messageRequest.Message).Msg("Received message")

	// Forward the message to the remote server
	remoteURL := "https://test-sse.vercel.app/api/message"
	log.Info().Str("remote_url", remoteURL).Msg("Forwarding message to remote server")

	// Create the request body
	requestBody := strings.NewReader(fmt.Sprintf(`{"message":"%s"}`, messageRequest.Message))

	// Create the request
	req, err := http.NewRequest("POST", remoteURL, requestBody)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create request to remote server")
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	// Send the request
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Error().Err(err).Msg("Failed to send message to remote server")
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}
	defer resp.Body.Close()

	// Check if the response is successful
	if resp.StatusCode != http.StatusOK {
		log.Error().Int("status_code", resp.StatusCode).Msg("Remote server returned error")
		c.JSON(resp.StatusCode, gin.H{"error": "server_error"})
		return
	}

	// Read the response body
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error().Err(err).Msg("Failed to read response from remote server")
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	log.Info().Str("response", string(responseBody)).Msg("Message forwarded successfully")

	// Return the response from the remote server
	c.Header("Content-Type", "application/json")
	c.Writer.Write(responseBody)
}

// Helper function to get minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
