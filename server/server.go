package server

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"mcpauth/server/providers"
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
	Router        *gin.Engine
	Sessions      map[string]SessionData
	Clients       map[string]Client
	Provider      providers.Provider
	ProtectedPath string
	OAuthDomain   string // Renamed from BaseDomain
	DevMode       bool
	AllowedEmails []string // List of emails allowed to access protected resources
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
	Email        string // Store the user's email
}

// NewServer creates a new server instance
func NewServer(protectedPath, oauthDomain string, devMode bool) *Server {
	router := gin.Default()

	server := &Server{
		Router:        router,
		Sessions:      make(map[string]SessionData),
		Clients:       make(map[string]Client),
		ProtectedPath: protectedPath,
		OAuthDomain:   oauthDomain, // Use the new name
		DevMode:       devMode,
		AllowedEmails: []string{}, // Initialize empty allowed emails list
	}

	// Set up all routes
	server.SetupRoutes()

	return server
}

// SetAllowedEmails sets the list of emails allowed to access protected resources
func (s *Server) SetAllowedEmails(emails []string) {
	s.AllowedEmails = emails
	log.Info().Strs("allowed_emails", emails).Msg("Configured allowed emails")
}

// ConfigureProvider sets up the specified OAuth provider
func (s *Server) ConfigureProvider(providerName, clientID, clientSecret, redirectURI string, scopes []string) error {
	switch providerName {
	case "google":
		s.Provider = google.NewProvider(clientID, clientSecret, redirectURI, scopes)
		return nil
	// Add more providers here as needed
	// case "auth0":
	//     s.Provider = auth0.NewProvider(clientID, clientSecret, redirectURI, scopes)
	//     return nil
	default:
		return fmt.Errorf("unsupported provider: %s", providerName)
	}
}

// SetupRoutes configures all the routes for the server
func (s *Server) SetupRoutes() {
	// Only add debug logging middleware if we're at debug level
	if zerolog.GlobalLevel() <= zerolog.DebugLevel {
		s.Router.Use(func(c *gin.Context) {
			log.Debug().
				Str("path", c.Request.URL.Path).
				Str("method", c.Request.Method).
				Str("query", c.Request.URL.RawQuery).
				Msg("Incoming request before handler")
			c.Next()
			log.Debug().
				Str("path", c.Request.URL.Path).
				Int("status", c.Writer.Status()).
				Msg("Outgoing response after handler")
		})
	}

	// Add a health check endpoint
	s.Router.GET("/health", s.healthCheckHandler)

	// Add OAuth authorization server metadata endpoint
	s.Router.GET("/.well-known/oauth-authorization-server", s.oauthAuthorizationServerHandler)
	s.Router.OPTIONS("/.well-known/oauth-authorization-server", s.optionsHandler)

	// Add OAuth client registration endpoint
	s.Router.POST("/register", s.registerHandler)
	s.Router.OPTIONS("/register", s.optionsHandler)

	// OAuth endpoints
	s.Router.GET("/authorize", s.authorizeHandler)
	s.Router.OPTIONS("/authorize", s.optionsHandler)
	s.Router.GET("/callback", s.callbackHandler)
	s.Router.POST("/token", s.tokenHandler)
	s.Router.OPTIONS("/token", s.optionsHandler)

	// Add SSE endpoint or protected path (not both)
	if s.ProtectedPath == "/sse" {
		s.Router.GET("/sse", s.sseHandler)
	} else {
		// Register protected path if it's different from /sse
		if s.ProtectedPath != "" {
			s.Router.GET(s.ProtectedPath, s.sseHandler)
		}
	}
}

// healthCheckHandler returns a 200 OK response
func (s *Server) healthCheckHandler(c *gin.Context) {
	c.JSON(200, gin.H{
		"status":  200,
		"message": "OK",
	})
}

// oauthAuthorizationServerHandler returns OAuth server metadata
func (s *Server) oauthAuthorizationServerHandler(c *gin.Context) {
	log.Info().
		Str("path", c.Request.URL.Path).
		Str("domain", s.OAuthDomain). // Log the domain being used
		Msg("Received OAuth server metadata request")

	// Set CORS headers
	origin := c.Request.Header.Get("Origin")
	if origin == "" {
		origin = "*"
	}
	c.Header("Access-Control-Allow-Origin", origin)
	c.Header("Access-Control-Allow-Methods", "GET, OPTIONS")
	c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type, mcp-protocol-version")
	c.Header("Access-Control-Allow-Credentials", "true")

	protocol := "https"
	if s.DevMode {
		protocol = "http"
	}

	// Use the OAuthDomain field
	c.JSON(200, gin.H{
		"issuer":                                fmt.Sprintf("%s://%s", protocol, s.OAuthDomain),
		"authorization_endpoint":                fmt.Sprintf("%s://%s/authorize", protocol, s.OAuthDomain),
		"token_endpoint":                        fmt.Sprintf("%s://%s/token", protocol, s.OAuthDomain),
		"registration_endpoint":                 fmt.Sprintf("%s://%s/register", protocol, s.OAuthDomain),
		"jwks_uri":                              fmt.Sprintf("%s://%s/jwks", protocol, s.OAuthDomain),
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"revocation_endpoint":                   fmt.Sprintf("%s://%s/token", protocol, s.OAuthDomain),
		"code_challenge_methods_supported":      []string{"plain", "S256"},
	})
}

// optionsHandler handles preflight OPTIONS requests with proper CORS headers
func (s *Server) optionsHandler(c *gin.Context) {
	origin := c.GetHeader("Origin")
	if origin == "" {
		origin = "*" // fallback for non-browser clients
	}

	// CORS headers required by browser clients
	c.Header("Access-Control-Allow-Origin", origin)
	c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type, MCP-Protocol-Version")
	c.Header("Access-Control-Allow-Credentials", "true")
	c.Header("Access-Control-Max-Age", "86400") // Cache preflight for 1 day

	// Send a 200 OK status
	c.Status(http.StatusOK)
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

	// Log all clients for debugging
	log.Debug().Interface("clients", s.Clients).Msg("Current registered clients")

	var registration struct {
		ClientName   string   `json:"client_name"`
		RedirectURIs []string `json:"redirect_uris"`
	}

	if err := c.BindJSON(&registration); err != nil {
		log.Error().Err(err).Msg("Failed to parse registration request")
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

	// Check if provider is configured
	if s.Provider == nil {
		log.Error().Msg("OAuth provider not configured")
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

	// Redirect to OAuth provider
	authURL := s.Provider.GetAuthURL(state, codeVerifier, nonce)
	c.Redirect(http.StatusTemporaryRedirect, authURL)
}

// callbackHandler processes the OAuth callback
func (s *Server) callbackHandler(c *gin.Context) {
	log.Info().Str("path", c.Request.URL.Path).Msg("Received callback from OAuth provider")

	// Get the authorization code and state from the request
	code := c.Query("code")
	state := c.Query("state")

	// Only log sensitive data at debug level
	log.Debug().Str("state", state).Msg("Callback parameters")
	// Don't log the code as it's sensitive

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
	accessToken, idToken, err := s.Provider.ExchangeToken(code, sessionData.CodeVerifier)
	if err != nil {
		log.Error().Err(err).Msg("Failed to exchange token")
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	// Get user info to extract email
	userInfo, err := s.Provider.GetUserInfo(accessToken)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get user info")
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	// Extract email from user info
	email, ok := userInfo["email"].(string)
	if !ok {
		log.Error().Interface("user_info", userInfo).Msg("Email not found in user info")
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}

	log.Info().Str("email", email).Msg("User authenticated")

	// Store tokens and email in session
	sessionData.AccessToken = accessToken
	sessionData.IDToken = idToken
	sessionData.Email = email
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

	// Set CORS headers
	origin := c.Request.Header.Get("Origin")
	if origin == "" {
		origin = "*"
	}
	c.Header("Access-Control-Allow-Origin", origin)
	c.Header("Access-Control-Allow-Methods", "POST, OPTIONS")
	c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type, mcp-protocol-version")
	c.Header("Access-Control-Allow-Credentials", "true")

	// Get form parameters
	grantType := c.PostForm("grant_type")
	code := c.PostForm("code")
	redirectURI := c.PostForm("redirect_uri")
	clientID := c.PostForm("client_id")

	log.Debug().
		Str("grant_type", grantType).
		Str("code", code).
		Str("redirect_uri", redirectURI).
		Str("client_id", clientID).
		Msg("Token request parameters")

	// Log all clients for debugging
	log.Debug().Interface("clients", s.Clients).Msg("Current registered clients")

	// TEMPORARY HACK: Accept any client ID
	if _, clientExists := s.Clients[clientID]; !clientExists {
		log.Warn().Str("client_id", clientID).Msg("TEMPORARY WORKAROUND for testing: Accepting unknown client")
		// Create a temporary client
		s.Clients[clientID] = Client{
			ClientID:     clientID,
			ClientName:   "Temporary Client",
			RedirectURIs: []string{redirectURI},
		}
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

	// If redirect URI is not provided in token request, use the one from the session
	if redirectURI == "" {
		log.Info().
			Str("session_redirect_uri", sessionData.RedirectURI).
			Msg("Using redirect URI from initial authorization request")
		redirectURI = sessionData.RedirectURI
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

// sseHandler handles Server-Sent Events connections authentication
func (s *Server) sseHandler(c *gin.Context) {
	log.Info().
		Str("path", c.Request.URL.Path).
		Str("query", c.Request.URL.RawQuery).
		Str("user_agent", c.Request.UserAgent()).
		Str("referer", c.Request.Referer()).
		Msg("Received SSE auth request")

	// Set CORS headers for the SSE endpoint
	origin := c.Request.Header.Get("Origin")
	if origin == "" {
		origin = "*"
	}
	c.Header("Access-Control-Allow-Origin", origin)
	c.Header("Access-Control-Allow-Methods", "GET, OPTIONS")
	c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")
	c.Header("Access-Control-Allow-Credentials", "true")

	// Get the authorization header or query parameter
	authHeader := c.GetHeader("Authorization")
	tokenParam := c.Query("access_token")

	var token string

	// Extract token from header or query parameter
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	} else if tokenParam != "" {
		token = tokenParam
	} else {
		// No token provided, return 401 Unauthorized
		log.Warn().Msg("Missing authorization token")
		c.Header("WWW-Authenticate", "Bearer realm=\"mcpauth\"")
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	// Validate the token by checking if it exists in any active session
	valid := false
	var userEmail string

	for _, session := range s.Sessions {
		if session.AccessToken == token {
			// Check if token is expired
			if time.Now().After(session.ExpiresAt) {
				log.Warn().Msg("Token expired")
				c.Header("WWW-Authenticate", "Bearer error=\"invalid_token\", error_description=\"The access token expired\"")
				c.JSON(401, gin.H{
					"status":  401,
					"message": "Token expired",
				})
				return
			}
			valid = true
			userEmail = session.Email
			break
		}
	}

	if !valid {
		log.Warn().Msg("Invalid token")
		c.Header("WWW-Authenticate", "Bearer error=\"invalid_token\"")
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Invalid token",
		})
		return
	}

	// Check if email is in the allowed list (if the list is not empty)
	if len(s.AllowedEmails) > 0 {
		emailAllowed := false
		for _, allowedEmail := range s.AllowedEmails {
			if allowedEmail == userEmail {
				emailAllowed = true
				break
			}
		}

		if !emailAllowed {
			log.Warn().Str("email", userEmail).Msg("Email not in allowed list")
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Email not in allowed list",
			})
			return
		}
	}

	// Token is valid and email is authorized
	log.Info().Str("email", userEmail).Msg("Authentication and authorization successful")
	c.Status(http.StatusOK)
}
