package server

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	
	"mcpauth/server/providers/google"
)

// Server represents the HTTP server
type Server struct {
	Router     *gin.Engine
	Path       string
	BaseDomain string // Base domain for OAuth endpoints
	DevMode    bool   // Development mode flag
	
	// OAuth providers
	GoogleProvider *google.Provider
	
	// Session storage (simple in-memory for now)
	Sessions map[string]SessionData
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
func NewServer(path string, baseDomain string, devMode bool) *Server {
	// Disable gin debug logs
	gin.SetMode(gin.ReleaseMode)

	// Create router
	router := gin.New()
	router.Use(gin.Recovery())

	// Create server
	server := &Server{
		Router:     router,
		Path:       path,
		BaseDomain: baseDomain,
		DevMode:    devMode,
		Sessions:   make(map[string]SessionData),
	}

	// Setup routes
	server.setupRoutes()

	return server
}

// SetGoogleOAuthConfig sets the Google OAuth configuration
func (s *Server) SetGoogleOAuthConfig(clientID, clientSecret, redirectURI string, scopes []string) {
	s.GoogleProvider = google.NewProvider(clientID, clientSecret, redirectURI, scopes)
}

// setupRoutes configures the server routes
func (s *Server) setupRoutes() {
	// Only add the unauthorized handler if the path is not one of our special endpoints
	if s.Path != "/sse" {
		// Add the route for the specified path
		s.Router.GET(s.Path, s.unauthorizedHandler)
	}
	
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

// oauthAuthorizationServerHandler returns OAuth authorization server metadata
func (s *Server) oauthAuthorizationServerHandler(c *gin.Context) {
	log.Info().Str("path", c.Request.URL.Path).Msg("Received request for OAuth authorization server metadata")
	
	// Get the Origin header from the request
	origin := c.Request.Header.Get("Origin")
	if origin == "" {
		origin = "*"
	}
	
	// Set CORS headers to match the working example
	c.Header("Access-Control-Allow-Origin", origin)
	c.Header("Access-Control-Allow-Methods", "*")
	c.Header("Access-Control-Allow-Headers", "Authorization, *")
	c.Header("Access-Control-Max-Age", "86400") // 24 hours
	
	// Determine protocol based on development mode
	protocol := "https"
	if s.DevMode {
		protocol = "http"
	}
	
	c.JSON(200, gin.H{
		"issuer": fmt.Sprintf("%s://%s", protocol, s.BaseDomain),
		"authorization_endpoint": fmt.Sprintf("%s://%s/authorize", protocol, s.BaseDomain),
		"token_endpoint": fmt.Sprintf("%s://%s/token", protocol, s.BaseDomain),
		"registration_endpoint": fmt.Sprintf("%s://%s/register", protocol, s.BaseDomain),
		"response_types_supported": []string{"code"},
		"response_modes_supported": []string{"query"},
		"grant_types_supported": []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post", "none"},
		"revocation_endpoint": fmt.Sprintf("%s://%s/token", protocol, s.BaseDomain),
		"code_challenge_methods_supported": []string{"plain", "S256"},
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
	c.Header("Access-Control-Allow-Methods", "*")
	c.Header("Access-Control-Allow-Headers", "Authorization, *")
	c.Header("Access-Control-Max-Age", "86400") // 24 hours
	
	// Respond with 204 No Content
	c.Status(204)
}

// registerHandler handles OAuth client registration
func (s *Server) registerHandler(c *gin.Context) {
	log.Info().Str("path", c.Request.URL.Path).Msg("Received client registration request")
	
	// Set CORS headers
	origin := c.Request.Header.Get("Origin")
	if origin == "" {
		origin = "*"
	}
	c.Header("Access-Control-Allow-Origin", origin)
	c.Header("Access-Control-Allow-Methods", "*")
	c.Header("Access-Control-Allow-Headers", "Authorization, *")
	
	// Parse the registration request
	var registrationRequest struct {
		RedirectURIs            []string `json:"redirect_uris"`
		ResponseTypes           []string `json:"response_types"`
		GrantTypes              []string `json:"grant_types"`
		ApplicationType         string   `json:"application_type"`
		ClientName              string   `json:"client_name"`
		TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	}
	
	if err := c.ShouldBindJSON(&registrationRequest); err != nil {
		log.Error().Err(err).Msg("Failed to parse registration request")
		c.JSON(400, gin.H{
			"error": "invalid_request",
			"error_description": "Invalid registration request",
		})
		return
	}
	
	// Generate a client ID and client secret
	clientID := fmt.Sprintf("client-%s", generateRandomString(16))
	clientSecret := generateRandomString(32)
	
	// Log the registration details
	log.Info().
		Str("client_id", clientID).
		Str("client_name", registrationRequest.ClientName).
		Strs("redirect_uris", registrationRequest.RedirectURIs).
		Msg("Registered new client")
	
	// Return the client credentials
	c.JSON(201, gin.H{
		"client_id": clientID,
		"client_secret": clientSecret,
		"client_id_issued_at": time.Now().Unix(),
		"client_secret_expires_at": 0, // Never expires
		"redirect_uris": registrationRequest.RedirectURIs,
		"grant_types": registrationRequest.GrantTypes,
		"response_types": registrationRequest.ResponseTypes,
		"token_endpoint_auth_method": registrationRequest.TokenEndpointAuthMethod,
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
			"error": "unsupported_response_type",
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
			"error": "invalid_request",
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

// tokenHandler exchanges an authorization code for tokens
func (s *Server) tokenHandler(c *gin.Context) {
	log.Info().Str("path", c.Request.URL.Path).Msg("Received token request")
	
	// Set CORS headers
	origin := c.Request.Header.Get("Origin")
	if origin == "" {
		origin = "*"
	}
	c.Header("Access-Control-Allow-Origin", origin)
	c.Header("Access-Control-Allow-Methods", "POST, OPTIONS")
	c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")
	c.Header("Access-Control-Allow-Credentials", "true")
	
	// Parse the token request
	grantType := c.PostForm("grant_type")
	code := c.PostForm("code")
	redirectURI := c.PostForm("redirect_uri")
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")
	
	log.Debug().
		Str("grant_type", grantType).
		Str("code", code).
		Str("redirect_uri", redirectURI).
		Str("client_id", clientID).
		Msg("Token request parameters")
	
	// Check if Google provider is configured
	if s.GoogleProvider == nil {
		log.Error().Msg("Google provider not configured")
		c.JSON(500, gin.H{
			"error": "server_error",
			"error_description": "OAuth provider not configured",
		})
		return
	}
	
	// In development mode, skip client validation
	if !s.DevMode {
		// Validate client credentials
		if clientID != s.GoogleProvider.ClientID || clientSecret != s.GoogleProvider.ClientSecret {
			log.Error().
				Str("provided_client_id", clientID).
				Str("expected_client_id", s.GoogleProvider.ClientID).
				Msg("Invalid client credentials")
			
			c.JSON(401, gin.H{
				"error": "invalid_client",
				"error_description": "Invalid client credentials",
			})
			return
		}
	}
	
	// Find the session with this code
	sessionData, found := s.Sessions[code]
	if !found {
		log.Error().Str("code", code).Msg("Invalid authorization code")
		c.JSON(400, gin.H{
			"error": "invalid_grant",
			"error_description": "Invalid authorization code",
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
		"token_type": "Bearer",
		"expires_in": int(time.Until(sessionData.ExpiresAt).Seconds()),
		"id_token": sessionData.IDToken,
	})
	
	// Clean up sessions after use
	delete(s.Sessions, code)
}

// sseHandler handles Server-Sent Events connections and proxies events from the remote server
func (s *Server) sseHandler(c *gin.Context) {
	log.Info().Str("path", c.Request.URL.Path).Msg("Received SSE request")
	
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
			"error": "unauthorized",
			"error_description": "Missing or invalid authorization",
		})
		return
	}
	
	log.Debug().Str("token", token[:min(10, len(token))]+"...").Msg("Extracted token")
	
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
			"error": "unauthorized",
			"error_description": "Invalid token",
		})
		return
	}
	
	log.Info().Str("session_key", matchedSession).Msg("Token validated successfully")
	
	// Set headers for SSE
	c.Writer.Header().Set("Content-Type", "text/event-stream")
	c.Writer.Header().Set("Cache-Control", "no-cache")
	c.Writer.Header().Set("Connection", "keep-alive")
	c.Writer.Header().Set("X-Accel-Buffering", "no")
	log.Debug().Interface("response_headers", c.Writer.Header()).Msg("Set SSE headers on response")
	
	// Create a channel for client disconnection
	clientGone := c.Writer.CloseNotify()
	
	// Connect to the remote SSE server
	remoteURL := "https://test-sse.vercel.app/api/sse"
	log.Info().Str("remote_url", remoteURL).Msg("Connecting to remote SSE server")
	
	req, err := http.NewRequest("GET", remoteURL, nil)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create request to remote SSE server")
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}
	
	// Create a client with a longer timeout
	client := &http.Client{
		Timeout: 0, // No timeout for SSE connections
	}
	
	resp, err := client.Do(req)
	if err != nil {
		log.Error().Err(err).Msg("Failed to connect to remote SSE server")
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}
	defer resp.Body.Close()
	
	// Check if the response is successful
	if resp.StatusCode != http.StatusOK {
		log.Error().Int("status_code", resp.StatusCode).Msg("Remote SSE server returned error")
		c.JSON(resp.StatusCode, gin.H{"error": "server_error"})
		return
	}
	
	log.Info().Msg("Connected to remote SSE server, proxying events")
	
	// Send a welcome message
	c.Writer.Write([]byte("data: {\"type\":\"connection\",\"message\":\"Connected to SSE server via proxy\"}\n\n"))
	c.Writer.Flush()
	
	// Create a buffer for reading from the remote server
	reader := bufio.NewReader(resp.Body)
	
	// Proxy events from the remote server to the client
	for {
		select {
		case <-clientGone:
			log.Debug().Msg("Client disconnected from SSE")
			return
		default:
			// Read a line from the remote server
			line, err := reader.ReadString('\n')
			if err != nil {
				if err == io.EOF {
					log.Info().Msg("Remote SSE server closed connection")
				} else {
					log.Error().Err(err).Msg("Error reading from remote SSE server")
				}
				return
			}
			
			// Write the line to the client
			_, err = c.Writer.Write([]byte(line))
			if err != nil {
				log.Error().Err(err).Msg("Error writing to client")
				return
			}
			
			// If the line is empty (end of event), flush the response
			if line == "\n" {
				c.Writer.Flush()
			}
		}
	}
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
			"error": "unauthorized",
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
			"error": "unauthorized",
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
			"error": "invalid_request",
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
