package server

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"

	"mcpauth/server/database"
	"mcpauth/server/providers"
	"mcpauth/server/providers/google"
	"mcpauth/server/providers/local"
	"mcpauth/server/services"
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
	Router           *gin.Engine
	Sessions         *SessionStore
	Clients          map[string]Client // Legacy in-memory clients for backward compatibility
	Provider         providers.Provider
	InternalProvider *local.Provider
	DB               *database.DB
	UserService      *services.UserService
	ClientService    *services.ClientService
	LicenseService   *services.LicenseService
	OAuthDomain      string // Renamed from BaseDomain
	DevMode          bool
	AllowedEmails    []string // List of emails allowed to access protected resources
	AllowedScopes    []string // list of scopes middleware is allowed to request
	RequiredScopes   []string // list of scopes that must be present in tokens
	UseInternalAuth  bool     // Whether to use internal authentication
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
	Scopes       []string
}

// NewServer creates a new server instance
func NewServer(oauthDomain string, devMode bool, dataDir string) (*Server, error) {
	router := gin.Default()

	// Initialize database
	db, err := database.NewDB(dataDir)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize database: %w", err)
	}

	// Initialize repositories
	userRepo := database.NewUserRepository(db)
	clientRepo := database.NewClientRepository(db)
	scopeRepo := database.NewScopeRepository(db)
	authCodeRepo := database.NewAuthCodeRepository(db)
	tokenRepo := database.NewTokenRepository(db)
	licenseRepo := database.NewRSLLicenseRepository(db)

	// Initialize services
	userService := services.NewUserService(userRepo)
	clientService := services.NewClientService(clientRepo, scopeRepo)
	licenseService := services.NewLicenseService(licenseRepo, clientRepo)

	// Initialize internal provider
	internalProvider := local.NewProvider(
		fmt.Sprintf("http%s://%s", map[bool]string{true: "s", false: ""}[!devMode], oauthDomain),
		userRepo, clientRepo, authCodeRepo, tokenRepo,
	)

	server := &Server{
		Router:           router,
		Sessions:         NewSessionStore(),
		Clients:          make(map[string]Client), // Legacy support
		DB:               db,
		UserService:      userService,
		ClientService:    clientService,
		LicenseService:   licenseService,
		InternalProvider: internalProvider,
		OAuthDomain:      oauthDomain,
		DevMode:          devMode,
		AllowedEmails:    []string{},
		UseInternalAuth:  false, // Default to external auth for backward compatibility
	}

	// Start background cleanup of expired sessions
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			log.Debug().Msg("Running cleanup of expired sessions")
			server.Sessions.CleanupExpired()
		}
	}()

	// Set up all routes
	server.SetupRoutes()

	return server, nil
}

// SetAllowedEmails sets the list of emails allowed to access protected resources
func (s *Server) SetAllowedEmails(emails []string) {
	s.AllowedEmails = emails
	log.Info().Strs("allowed_emails", emails).Msg("Configured allowed emails")
}

// SetScopes sets the allowed and required scopes for the server
func (s *Server) SetScopes(allowed, required []string) {
	s.AllowedScopes = allowed
	s.RequiredScopes = required
	log.Info().
		Strs("allowed_scopes", allowed).
		Strs("required_scopes", required).
		Msg("Configured OAuth scopes")
}

// ConfigureProvider sets up the specified OAuth provider
func (s *Server) ConfigureProvider(providerName, clientID, clientSecret, redirectURI string, scopes []string) error {
	switch providerName {
	case "google":
		s.Provider = google.NewProvider(clientID, clientSecret, redirectURI, scopes)
		s.UseInternalAuth = false
		return nil
	case "internal":
		s.UseInternalAuth = true
		log.Info().Msg("Configured to use internal authentication")
		return nil
	// Add more providers here as needed
	// case "auth0":
	//     s.Provider = auth0.NewProvider(clientID, clientSecret, redirectURI, scopes)
	//     return nil
	default:
		return fmt.Errorf("unsupported provider: %s", providerName)
	}
}

// CreateDefaultAdminUser creates a default admin user if no users exist
func (s *Server) CreateDefaultAdminUser(username, email, password string) error {
	// Check if any users exist
	users, err := s.UserService.ListUsers()
	if err != nil {
		return fmt.Errorf("failed to check existing users: %w", err)
	}

	if len(users) > 0 {
		log.Info().Msg("Users already exist, skipping default admin creation")
		return nil
	}

	// Create default admin user
	user, err := s.UserService.CreateUser(username, email, password, "Admin", "User")
	if err != nil {
		return fmt.Errorf("failed to create default admin user: %w", err)
	}

	log.Info().
		Str("username", user.Username).
		Str("email", user.Email).
		Msg("Created default admin user")

	return nil
}

// SetupRoutes configures all the routes for the server
func (s *Server) SetupRoutes() {
	// Middleware to log all incoming requests
	s.Router.Use(func(c *gin.Context) {
		log.Info().
			Str("path", c.Request.URL.Path).
			Str("method", c.Request.Method).
			Str("query", c.Request.URL.RawQuery).
			Msg("Incoming request")
		c.Next()
		log.Info().
			Str("path", c.Request.URL.Path).
			Int("status", c.Writer.Status()).
			Msg("Outgoing response")
	})

	// Add a health check endpoint
	s.Router.GET("/health", s.healthCheckHandler)

	// Add OAuth authorization server metadata endpoint
	s.Router.GET("/.well-known/oauth-authorization-server", s.oauthAuthorizationServerHandler)
	s.Router.OPTIONS("/.well-known/oauth-authorization-server", s.optionsHandler)

	// Add OAuth protected resource metadata endpoint
	s.Router.GET("/.well-known/oauth-protected-resource", s.oauthProtectedResourceHandler)
	s.Router.OPTIONS("/.well-known/oauth-protected-resource", s.optionsHandler)

	// Add OAuth client registration endpoint
	s.Router.POST("/register", s.registerHandler)
	s.Router.OPTIONS("/register", s.optionsHandler)

	// OAuth endpoints
	s.Router.GET("/authorize", s.authorizeHandler)
	s.Router.OPTIONS("/authorize", s.optionsHandler)
	s.Router.GET("/callback", s.callbackHandler)
	s.Router.POST("/token", s.tokenHandler)
	s.Router.OPTIONS("/token", s.optionsHandler)

	// Internal authentication endpoints
	s.Router.GET("/internal/authorize", s.internalAuthorizeHandler)
	s.Router.POST("/internal/authorize", s.internalAuthorizeHandler)
	s.Router.GET("/internal/login", s.internalLoginHandler)
	s.Router.POST("/internal/login", s.internalLoginHandler)

	// User management endpoints
	s.Router.POST("/users", s.createUserHandler)
	s.Router.GET("/users", s.listUsersHandler)
	s.Router.GET("/users/:id", s.getUserHandler)
	s.Router.DELETE("/users/:id", s.deleteUserHandler)

	// Client management endpoints
	s.Router.POST("/clients", s.createClientHandler)
	s.Router.GET("/clients", s.listClientsHandler)
	s.Router.GET("/clients/:id", s.getClientHandler)
	s.Router.DELETE("/clients/:id", s.deleteClientHandler)

	// Scope management endpoints
	s.Router.GET("/scopes", s.listScopesHandler)

	// Open Licensing Protocol (OLP) endpoints
	s.Router.POST("/introspect", s.introspectHandler)
	s.Router.POST("/key", s.keyHandler)

	// Admin web interface
	s.Router.GET("/admin", s.adminDashboardHandler)
	s.Router.Static("/static", "./static")

	// Generic auth handler for forwardAuth
	s.Router.Any("/auth", s.authHandler)
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

// oauthProtectedResourceHandler returns OAuth protected resource metadata
func (s *Server) oauthProtectedResourceHandler(c *gin.Context) {
	log.Info().
		Str("path", c.Request.URL.Path).
		Str("domain", s.OAuthDomain).
		Msg("Received OAuth protected resource metadata request")

	// Set CORS headers
	origin := c.Request.Header.Get("Origin")
	if origin == "" {
		origin = "*"
	}
	c.Header("Access-Control-Allow-Origin", origin)
	c.Header("Access-Control-Allow-Methods", "GET, OPTIONS")
	c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type, mcp-protocol-version")
	c.Header("Access-Control-Allow-Credentials", "true")

	// Detect protocol (prefer headers when behind proxy/load balancer)
	protocol := "https"
	if s.DevMode {
		protocol = "http"
	} else if forwardedProto := c.Request.Header.Get("X-Forwarded-Proto"); forwardedProto != "" {
		protocol = forwardedProto
	}

	// Determine host (fall back to configured domain if unavailable)
	host := c.Request.Host
	if host == "" {
		host = s.OAuthDomain
	}

	// ✅ Always point to the canonical resource root (/mcp)
	resourceURL := fmt.Sprintf("%s://%s", protocol, host)

	// Return the protected resource metadata
	c.JSON(200, gin.H{
		"resource":              resourceURL,
		"authorization_servers": []string{fmt.Sprintf("%s://%s/", protocol, s.OAuthDomain)},
		"scopes_supported":      s.RequiredScopes,
		"resource_name":         resourceURL,
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

	// If using internal auth, redirect to internal authorize handler
	if s.UseInternalAuth {
		// Forward all query parameters to internal handler
		internalURL := "/internal/authorize?" + c.Request.URL.RawQuery
		c.Redirect(http.StatusTemporaryRedirect, internalURL)
		return
	}

	// Check if external provider is configured
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
	s.Sessions.SaveState(state, SessionData{
		State:        state,
		CodeVerifier: codeVerifier,
		ClientID:     clientID,
		RedirectURI:  redirectURI,
		Nonce:        nonce,
	})

	log.Debug().Str("state", state).Msg("Stored session data")

	// Redirect to OAuth provider
	var requestedScopes []string
	if scope != "" {
		requestedScopes = strings.Split(scope, " ")
	}
	authURL := s.Provider.GetAuthURL(state, codeVerifier, nonce, requestedScopes)
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
	sessionData, exists := s.Sessions.GetByState(state)
	if !exists {
		log.Error().Str("state", state).Msg("Invalid state parameter")
		c.JSON(400, gin.H{
			"error":             "invalid_request",
			"error_description": "Invalid state parameter",
		})
		return
	}

	// Exchange the authorization code for tokens
	accessToken, idToken, scopes, err := s.Provider.ExchangeToken(code, sessionData.CodeVerifier)
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
	sessionData.Scopes = scopes
	sessionData.ExpiresAt = time.Now().Add(time.Hour) // Approximate expiry

	// The code from the provider is passed to our client, which will exchange it for a token.
	// We store the session data by this code.
	s.Sessions.SaveCode(code, sessionData)

	// The state has served its purpose and can be deleted.
	s.Sessions.DeleteState(state)

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

	// Handle RSL grant type for Open Licensing Protocol
	if grantType == "rsl" {
		log.Info().Msg("Handling RSL token request")
		if s.LicenseService == nil {
			log.Error().Msg("LicenseService is nil")
			c.JSON(500, gin.H{
				"error":             "server_error",
				"error_description": "License service not available",
			})
			return
		}
		s.handleRSLTokenRequest(c)
		return
	}

	// Handle internal authentication token exchange
	if s.UseInternalAuth {
		s.handleInternalTokenExchange(c, grantType, code, redirectURI, clientID)
		return
	}

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
	sessionData, found := s.Sessions.GetByCode(code)
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

	// The token is now being given to the client.
	// Store it for efficient lookup by the sseHandler.
	s.Sessions.SaveToken(sessionData.AccessToken, sessionData)

	// Return the tokens
	c.JSON(200, gin.H{
		"access_token": sessionData.AccessToken,
		"token_type":   "Bearer",
		"expires_in":   int(time.Until(sessionData.ExpiresAt).Seconds()),
		"id_token":     sessionData.IDToken,
	})

	// Clean up the one-time authorization code
	s.Sessions.DeleteCode(code)
}

// internalAuthorizeHandler handles internal authorization requests
func (s *Server) internalAuthorizeHandler(c *gin.Context) {
	if c.Request.Method == "GET" {
		// Show login form
		s.showInternalLoginForm(c)
		return
	}

	// Handle POST - process login
	s.processInternalLogin(c)
}

// internalLoginHandler handles internal login form display and processing
func (s *Server) internalLoginHandler(c *gin.Context) {
	if c.Request.Method == "GET" {
		s.showInternalLoginForm(c)
		return
	}
	s.processInternalLogin(c)
}

// showInternalLoginForm displays the login form
func (s *Server) showInternalLoginForm(c *gin.Context) {
	// Get parameters from query string
	state := c.Query("state")
	scope := c.Query("scope")

	// Store these in session for later use
	if state != "" {
		c.SetCookie("auth_state", state, 600, "/", "", false, true)
	}

	if scope != "" {
		c.SetCookie("auth_scope", scope, 600, "/", "", false, true)
	}

	// Simple HTML login form
	html := `
<!DOCTYPE html>
<html>
<head>
    <title>MCPAuth Login</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 400px; margin: 100px auto; padding: 20px; }
        .form-group { margin-bottom: 15px; }
        label { display: block; margin-bottom: 5px; }
        input[type="text"], input[type="password"] { width: 100%; padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
        button { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .error { color: red; margin-bottom: 15px; }
    </style>
</head>
<body>
    <h2>MCPAuth Login</h2>
    ` + func() string {
		if errMsg := c.Query("error"); errMsg != "" {
			return `<div class="error">` + errMsg + `</div>`
		}
		return ""
	}() + `
    <form method="POST">
        <div class="form-group">
            <label for="username">Username or Email:</label>
            <input type="text" id="username" name="username" required>
        </div>
        <div class="form-group">
            <label for="password">Password:</label>
            <input type="password" id="password" name="password" required>
        </div>
        <button type="submit">Login</button>
    </form>
</body>
</html>`

	c.Header("Content-Type", "text/html")
	c.String(200, html)
}

// processInternalLogin processes the login form submission
func (s *Server) processInternalLogin(c *gin.Context) {
	username := c.PostForm("username")
	password := c.PostForm("password")

	// Get stored parameters from cookies or query parameters
	state, _ := c.Cookie("auth_state")
	scope, _ := c.Cookie("auth_scope")

	// If scope is not in cookies, try to get it from query parameters
	if scope == "" {
		scope = c.Query("scope")
	}

	if username == "" || password == "" {
		c.Redirect(302, "/internal/login?error=Username and password are required")
		return
	}

	// Authenticate user
	user, err := s.InternalProvider.AuthenticateUser(username, password)
	if err != nil {
		log.Warn().Str("username", username).Msg("Failed authentication attempt")
		c.Redirect(302, "/internal/login?error=Invalid username or password")
		return
	}

	log.Info().Str("username", user.Username).Msg("User authenticated successfully")

	// Get client ID and redirect URI from the original authorization request
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")

	// If not in query, try to get from the session data stored by state
	if clientID == "" && state != "" {
		if sessionData, exists := s.Sessions.GetByState(state); exists {
			clientID = sessionData.ClientID
			redirectURI = sessionData.RedirectURI
		}
	}

	if clientID == "" || redirectURI == "" {
		c.String(400, "Missing client_id or redirect_uri")
		return
	}

	log.Info().Str("clientID", clientID).Msg(" - Client ID")
	log.Info().Str("redirectURI", redirectURI).Msg(" - redirectURI")

	// Validate redirect URI
	if err := s.InternalProvider.ValidateRedirectURI(clientID, redirectURI); err != nil {
		c.String(400, "Invalid redirect URI")
		return
	}

	// Parse scopes
	var requestedScopes []string
	if scope != "" {
		requestedScopes = strings.Split(scope, " ")
	}

	// Create authorization code (scope validation is handled inside CreateAuthorizationCode)
	authCode, err := s.InternalProvider.CreateAuthorizationCode(clientID, user.ID, redirectURI, requestedScopes)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create authorization code")
		// Check if it's a scope validation error
		if strings.Contains(err.Error(), "scope validation failed") || strings.Contains(err.Error(), "not allowed") {
			c.String(400, err.Error())
		} else {
			c.String(500, "Internal server error")
		}
		return
	}

	// Clear cookies
	c.SetCookie("auth_state", "", -1, "/", "", false, true)
	c.SetCookie("auth_scope", "", -1, "/", "", false, true)

	// Redirect back to client with authorization code
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		c.String(500, "Invalid redirect URI")
		return
	}

	q := redirectURL.Query()
	q.Set("code", authCode.Code)
	if state != "" {
		q.Set("state", state)
	}
	redirectURL.RawQuery = q.Encode()

	log.Info().
		Str("client_id", clientID).
		Str("user", user.Username).
		Str("redirect_url", redirectURL.String()).
		Msg("Redirecting with authorization code")

	c.Redirect(302, redirectURL.String())
}

// handleInternalTokenExchange handles token exchange for internal authentication
func (s *Server) handleInternalTokenExchange(c *gin.Context, grantType, code, redirectURI, clientID string) {
	// Validate grant type
	if grantType != "authorization_code" {
		c.JSON(400, gin.H{
			"error":             "unsupported_grant_type",
			"error_description": "Only authorization_code grant type is supported",
		})
		return
	}

	// Validate required parameters
	if code == "" || redirectURI == "" || clientID == "" {
		c.JSON(400, gin.H{
			"error":             "invalid_request",
			"error_description": "Missing required parameters",
		})
		return
	}

	// Exchange authorization code for access token
	accessToken, idTokenClaims, err := s.InternalProvider.ExchangeAuthorizationCode(code, clientID, redirectURI)
	if err != nil {
		log.Error().Err(err).Msg("Failed to exchange authorization code")
		c.JSON(400, gin.H{
			"error":             "invalid_grant",
			"error_description": "Invalid authorization code",
		})
		return
	}

	// Prepare response
	response := gin.H{
		"access_token": accessToken.Token,
		"token_type":   "Bearer",
		"expires_in":   int(time.Until(accessToken.ExpiresAt).Seconds()),
	}

	// Add ID token if present (for OpenID Connect)
	if idTokenClaims != nil {
		idToken, err := local.CreateIDTokenJWT(idTokenClaims)
		if err != nil {
			log.Error().Err(err).Msg("Failed to create ID token")
		} else {
			response["id_token"] = idToken
		}
	}

	log.Info().
		Str("client_id", clientID).
		Str("token_id", accessToken.Token[:8]+"...").
		Msg("Issued access token")

	c.JSON(200, response)
}

// User management handlers

// createUserHandler creates a new user
func (s *Server) createUserHandler(c *gin.Context) {
	var req struct {
		Username  string `json:"username" binding:"required"`
		Email     string `json:"email" binding:"required"`
		Password  string `json:"password" binding:"required"`
		FirstName string `json:"first_name" binding:"required"`
		LastName  string `json:"last_name" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	user, err := s.UserService.CreateUser(req.Username, req.Email, req.Password, req.FirstName, req.LastName)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	c.JSON(201, user)
}

// AdminUser represents a user with sensitive data for admin interface
type AdminUser struct {
	ID           int       `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"password_hash"` // Include password hash for admin
	FirstName    string    `json:"first_name"`
	LastName     string    `json:"last_name"`
	Active       bool      `json:"active"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// listUsersHandler lists all users
func (s *Server) listUsersHandler(c *gin.Context) {
	users, err := s.UserService.ListUsers()
	if err != nil {
		c.JSON(500, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	// Convert to admin users to include password hashes
	adminUsers := make([]AdminUser, len(users))
	for i, user := range users {
		adminUsers[i] = AdminUser{
			ID:           user.ID,
			Username:     user.Username,
			Email:        user.Email,
			PasswordHash: user.PasswordHash,
			FirstName:    user.FirstName,
			LastName:     user.LastName,
			Active:       user.Active,
			CreatedAt:    user.CreatedAt,
			UpdatedAt:    user.UpdatedAt,
		}
	}

	c.JSON(200, gin.H{"users": adminUsers})
}

// getUserHandler gets a specific user
func (s *Server) getUserHandler(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": "Invalid user ID"})
		return
	}

	user, err := s.UserService.GetUser(id)
	if err != nil {
		c.JSON(404, gin.H{"error": "not_found", "error_description": "User not found"})
		return
	}

	c.JSON(200, user)
}

// deleteUserHandler deletes a user by ID
func (s *Server) deleteUserHandler(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid user ID"})
		return
	}

	err = s.UserService.DeleteUser(id)
	if err != nil {
		log.Error().Err(err).Int("user_id", id).Msg("Failed to delete user")
		c.JSON(500, gin.H{"error": "Failed to delete user"})
		return
	}

	log.Info().Int("user_id", id).Msg("User deleted successfully")
	c.JSON(200, gin.H{"message": "User deleted successfully"})
}

// Client management handlers

// createClientHandler creates a new OAuth client
func (s *Server) createClientHandler(c *gin.Context) {
	var req struct {
		ClientName   string   `json:"client_name" binding:"required"`
		RedirectURIs []string `json:"redirect_uris" binding:"required"`
		Scopes       []string `json:"scopes" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	client, err := s.ClientService.CreateClient(req.ClientName, req.RedirectURIs, req.Scopes)
	if err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	c.JSON(201, client)
}

// listClientsHandler lists all OAuth clients
func (s *Server) listClientsHandler(c *gin.Context) {
	clients, err := s.ClientService.ListClients()
	if err != nil {
		c.JSON(500, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	c.JSON(200, gin.H{"clients": clients})
}

// getClientHandler gets a specific OAuth client
func (s *Server) getClientHandler(c *gin.Context) {
	clientID := c.Param("id")

	client, err := s.ClientService.GetClient(clientID)
	if err != nil {
		c.JSON(404, gin.H{"error": "not_found", "error_description": "Client not found"})
		return
	}

	// For admin interface, include client secret
	c.JSON(200, client)
}

// deleteClientHandler deletes an OAuth client by ID
func (s *Server) deleteClientHandler(c *gin.Context) {
	clientID := c.Param("id")

	err := s.ClientService.DeleteClient(clientID)
	if err != nil {
		log.Error().Err(err).Str("client_id", clientID).Msg("Failed to delete client")
		c.JSON(500, gin.H{"error": "Failed to delete client"})
		return
	}

	log.Info().Str("client_id", clientID).Msg("Client deleted successfully")
	c.JSON(200, gin.H{"message": "Client deleted successfully"})
}

// listScopesHandler lists all available scopes
func (s *Server) listScopesHandler(c *gin.Context) {
	scopes, err := s.ClientService.GetAvailableScopes()
	if err != nil {
		c.JSON(500, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	c.JSON(200, gin.H{"scopes": scopes})
}

// adminDashboardHandler serves the admin dashboard
func (s *Server) adminDashboardHandler(c *gin.Context) {
	html := `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MCPAuth Admin Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f5f5f5; }
        .header { background: #2c3e50; color: white; padding: 1rem 2rem; }
        .header h1 { font-size: 1.5rem; }
        .container { max-width: 1200px; margin: 2rem auto; padding: 0 2rem; }
        .card { background: white; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); margin-bottom: 2rem; }
        .card-header { padding: 1rem 1.5rem; border-bottom: 1px solid #eee; font-weight: 600; }
        .card-body { padding: 1.5rem; }
        .btn { background: #3498db; color: white; border: none; padding: 0.5rem 1rem; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }
        .btn:hover { background: #2980b9; }
        .btn-success { background: #27ae60; }
        .btn-success:hover { background: #229954; }
        .btn-danger { background: #e74c3c; }
        .btn-danger:hover { background: #c0392b; }
        .form-group { margin-bottom: 1rem; }
        .form-group label { display: block; margin-bottom: 0.5rem; font-weight: 500; }
        .form-group input, .form-group select, .form-group textarea { width: 100%; padding: 0.5rem; border: 1px solid #ddd; border-radius: 4px; }
        .table { width: 100%; border-collapse: collapse; }
        .table th, .table td { padding: 0.75rem; text-align: left; border-bottom: 1px solid #eee; }
        .table th { background: #f8f9fa; font-weight: 600; }
        .tabs { display: flex; border-bottom: 1px solid #ddd; }
        .tab { padding: 1rem 1.5rem; cursor: pointer; border-bottom: 2px solid transparent; }
        .tab.active { border-bottom-color: #3498db; color: #3498db; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .status { padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.875rem; }
        .status.active { background: #d4edda; color: #155724; }
        .status.inactive { background: #f8d7da; color: #721c24; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1rem; }
        .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.5); z-index: 1000; }
        .modal-content { background: white; margin: 5% auto; padding: 2rem; width: 90%; max-width: 500px; border-radius: 8px; }
        .close { float: right; font-size: 1.5rem; cursor: pointer; }
    </style>
</head>
<body>
    <div class="header">
        <h1>MCPAuth Admin Dashboard</h1>
    </div>

    <div class="container">
        <div class="card">
            <div class="card-header">
                <div class="tabs">
                    <div class="tab active" onclick="showTab('overview')">Overview</div>
                    <div class="tab" onclick="showTab('users')">Users</div>
                    <div class="tab" onclick="showTab('clients')">OAuth Clients</div>
                    <div class="tab" onclick="showTab('scopes')">Scopes</div>
                </div>
            </div>
            <div class="card-body">
                <div id="overview" class="tab-content active">
                    <h3>System Overview</h3>
                    <div class="grid">
                        <div class="card">
                            <div class="card-header">Users</div>
                            <div class="card-body">
                                <div id="user-count">Loading...</div>
                            </div>
                        </div>
                        <div class="card">
                            <div class="card-header">OAuth Clients</div>
                            <div class="card-body">
                                <div id="client-count">Loading...</div>
                            </div>
                        </div>
                        <div class="card">
                            <div class="card-header">Available Scopes</div>
                            <div class="card-body">
                                <div id="scope-count">Loading...</div>
                            </div>
                        </div>
                    </div>
                </div>

                <div id="users" class="tab-content">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                        <h3>Users</h3>
                        <button class="btn btn-success" onclick="showCreateUserModal()">Create User</button>
                    </div>
                    <div id="users-table">Loading...</div>
                </div>

                <div id="clients" class="tab-content">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 1rem;">
                        <h3>OAuth Clients</h3>
                        <button class="btn btn-success" onclick="showCreateClientModal()">Create Client</button>
                    </div>
                    <div id="clients-table">Loading...</div>
                </div>

                <div id="scopes" class="tab-content">
                    <h3>Available Scopes</h3>
                    <div id="scopes-table">Loading...</div>
                </div>
            </div>
        </div>
    </div>

    <!-- Create User Modal -->
    <div id="createUserModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('createUserModal')">&times;</span>
            <h3>Create New User</h3>
            <form id="createUserForm">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" required>
                </div>
                <div class="form-group">
                    <label for="email">Email:</label>
                    <input type="email" id="email" name="email" required>
                </div>
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required>
                </div>
                <div class="form-group">
                    <label for="firstName">First Name:</label>
                    <input type="text" id="firstName" name="first_name" required>
                </div>
                <div class="form-group">
                    <label for="lastName">Last Name:</label>
                    <input type="text" id="lastName" name="last_name" required>
                </div>
                <button type="submit" class="btn btn-success">Create User</button>
            </form>
        </div>
    </div>

    <!-- Create Client Modal -->
    <div id="createClientModal" class="modal">
        <div class="modal-content">
            <span class="close" onclick="closeModal('createClientModal')">&times;</span>
            <h3>Create New OAuth Client</h3>
            <form id="createClientForm">
                <div class="form-group">
                    <label for="clientName">Client Name:</label>
                    <input type="text" id="clientName" name="client_name" required>
                </div>
                <div class="form-group">
                    <label for="redirectUris">Redirect URIs (one per line):</label>
                    <textarea id="redirectUris" name="redirect_uris" rows="3" required placeholder="http://localhost:3000/callback"></textarea>
                </div>
                <div class="form-group">
                    <label for="clientScopes">Scopes:</label>
                    <div id="scope-checkboxes">Loading...</div>
                </div>
                <button type="submit" class="btn btn-success">Create Client</button>
            </form>
        </div>
    </div>

    <script>
        // Tab functionality
        function showTab(tabName) {
            document.querySelectorAll('.tab').forEach(tab => tab.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(content => content.classList.remove('active'));

            event.target.classList.add('active');
            document.getElementById(tabName).classList.add('active');

            // Load data for the active tab
            if (tabName === 'overview') loadOverview();
            else if (tabName === 'users') loadUsers();
            else if (tabName === 'clients') loadClients();
            else if (tabName === 'scopes') loadScopes();
        }

        // Modal functionality
        function showCreateUserModal() {
            document.getElementById('createUserModal').style.display = 'block';
        }

        function showCreateClientModal() {
            loadScopesForForm();
            document.getElementById('createClientModal').style.display = 'block';
        }

        function closeModal(modalId) {
            document.getElementById(modalId).style.display = 'none';
        }

        // API calls
        async function apiCall(url, options = {}) {
            try {
                const response = await fetch(url, options);
                if (!response.ok) throw new Error('Network response was not ok');
                return await response.json();
            } catch (error) {
                console.error('API call failed:', error);
                return null;
            }
        }

		async function loadOverview() {
			const [users, clients, scopes] = await Promise.all([
				apiCall('/users'),
				apiCall('/clients'),
				apiCall('/scopes')
			]);

			const userCount = users?.users?.length ?? 0;
			const clientCount = clients?.clients?.length ?? 0;
			const scopeCount = scopes?.scopes?.length ?? 0;

			document.getElementById('user-count').textContent = userCount;
			document.getElementById('client-count').textContent = clientCount;
			document.getElementById('scope-count').textContent = scopeCount;
		}
			
        async function loadUsers() {
            const data = await apiCall('/users');
            if (!data) {
                document.getElementById('users-table').innerHTML = '<p>Error loading users</p>';
                return;
            }

            const table = ` + "`" + `
                <table class="table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Username</th>
                            <th>Email</th>
                            <th>Name</th>
                            <th>Password Hash</th>
                            <th>Status</th>
                            <th>Created</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${data.users.map(user => ` + "`" + `
                            <tr>
                                <td>${user.id}</td>
                                <td>${user.username}</td>
                                <td>${user.email}</td>
                                <td>${user.first_name} ${user.last_name}</td>
                                <td><code style="font-size: 0.8em; word-break: break-all;">${user.password_hash ? user.password_hash.substring(0, 20) + '...' : 'N/A'}</code></td>
                                <td><span class="status ${user.active ? 'active' : 'inactive'}">${user.active ? 'Active' : 'Inactive'}</span></td>
                                <td>${new Date(user.created_at).toLocaleDateString()}</td>
                                <td>
                                    <button class="btn btn-danger" onclick="deleteUser(${user.id})" style="font-size: 0.8em; padding: 0.25rem 0.5rem;">Delete</button>
                                </td>
                            </tr>
                        ` + "`" + `).join('')}
                    </tbody>
                </table>
            ` + "`" + `;
            document.getElementById('users-table').innerHTML = table;
        }

        async function loadClients() {
            const data = await apiCall('/clients');
            if (!data) {
                document.getElementById('clients-table').innerHTML = '<p>Error loading clients</p>';
                return;
            }

			const table = ` + "`" + `
				<table class="table">
					<thead>
						<tr>
							<th>Client ID</th>
							<th>Client Secret</th>
							<th>Name</th>
							<th>Redirect URIs</th>
							<th>Scopes</th>
							<th>Status</th>
							<th>Created</th>
							<th>Actions</th>
						</tr>
					</thead>
					<tbody>
						${
							// Start of the conditional logic
							data.clients && data.clients.length > 0
								? data.clients.map(client => ` + "`" + `
									<tr>
										<td><code style="font-size: 0.8em;">${client.client_id}</code></td>
										<td><code style="font-size: 0.8em; word-break: break-all;">${client.client_secret || 'Hidden'}</code></td>
										<td>${client.client_name}</td>
										<td style="font-size: 0.9em;">${JSON.parse(client.redirect_uris).join(', ')}</td>
										<td>${JSON.parse(client.scopes).join(', ')}</td>
										<td><span class="status ${client.active ? 'active' : 'inactive'}">${client.active ? 'Active' : 'Inactive'}</span></td>
										<td>${new Date(client.created_at).toLocaleDateString()}</td>
										<td>
											<button class="btn btn-danger" onclick="deleteClient('${client.client_id}')" style="font-size: 0.8em; padding: 0.25rem 0.5rem;">Delete</button>
										</td>
									</tr>
								` + "`" + `).join('')
								: // Else (No Clients): Insert the empty table row
								` + "`" + `
								<tr>
									<td colspan="8" style="text-align: center; color: #6c757d;">No clients configured.</td>
								</tr>
								` + "`" + `
						}
					</tbody>
				</table>
			` + "`" + `;
			document.getElementById('clients-table').innerHTML = table;
		}

        async function loadScopes() {
            const data = await apiCall('/scopes');
            if (!data) {
                document.getElementById('scopes-table').innerHTML = '<p>Error loading scopes</p>';
                return;
            }

            const table = ` + "`" + `
                <table class="table">
                    <thead>
                        <tr>
                            <th>Name</th>
                            <th>Description</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                        ${data.scopes.map(scope => ` + "`" + `
                            <tr>
                                <td><code>${scope.name}</code></td>
                                <td>${scope.description}</td>
                                <td><span class="status ${scope.active ? 'active' : 'inactive'}">${scope.active ? 'Active' : 'Inactive'}</span></td>
                            </tr>
                        ` + "`" + `).join('')}
                    </tbody>
                </table>
            ` + "`" + `;
            document.getElementById('scopes-table').innerHTML = table;
        }

		async function loadScopesForForm() {
			const data = await apiCall('/scopes');
			if (!data) return;

			const checkboxes = data.scopes.map(scope => ` + "`" + `
				<label style="display: inline-flex; align-items: flex-start; margin-bottom: 0.5rem; cursor: pointer;">
					<span style="display: inline-block; width: 1.5rem; text-align: center;">
						<input type="checkbox" name="scopes" value="${scope.name}">
					</span>
					<span>${scope.name} - ${scope.description}</span>
				</label>
			` + "`" + `).join('');

			document.getElementById('scope-checkboxes').innerHTML = checkboxes;
		}


        // Form submissions
        document.getElementById('createUserForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);
            const data = Object.fromEntries(formData);

            const result = await apiCall('/users', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });

            if (result) {
                closeModal('createUserModal');
                loadUsers();
                e.target.reset();
            }
        });

        document.getElementById('createClientForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const formData = new FormData(e.target);

            const data = {
                client_name: formData.get('client_name'),
                redirect_uris: formData.get('redirect_uris').split('\n').map(uri => uri.trim()).filter(uri => uri),
                scopes: Array.from(formData.getAll('scopes'))
            };

            const result = await apiCall('/clients', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(data)
            });

            if (result) {
                closeModal('createClientModal');
                loadClients();
                e.target.reset();
            }
        });

        // Delete functions
        async function deleteUser(userId) {
            if (!confirm('Are you sure you want to delete this user? This action cannot be undone.')) {
                return;
            }

            const result = await apiCall(` + "`" + `/users/${userId}` + "`" + `, {
                method: 'DELETE'
            });

            if (result) {
                loadUsers();
                loadOverview();
                alert('User deleted successfully');
            } else {
                alert('Failed to delete user');
            }
        }

        async function deleteClient(clientId) {
            if (!confirm('Are you sure you want to delete this OAuth client? This action cannot be undone.')) {
                return;
            }

            const result = await apiCall(` + "`" + `/clients/${clientId}` + "`" + `, {
                method: 'DELETE'
            });

            if (result) {
                loadClients();
                loadOverview();
                alert('Client deleted successfully');
            } else {
                alert('Failed to delete client');
            }
        }

        // Load initial data
        loadOverview();
    </script>
</body>
</html>
	`

	c.Header("Content-Type", "text/html")
	c.String(200, html)
}

// Open Licensing Protocol (OLP) handlers

// handleRSLTokenRequest handles RSL license token requests
func (s *Server) handleRSLTokenRequest(c *gin.Context) {
	log.Info().Msg("RSL token request received")

	// Get form parameters
	licenseXML := c.PostForm("license")
	resource := c.PostForm("resource")

	log.Info().
		Str("resource", resource).
		Int("license_length", len(licenseXML)).
		Msg("RSL request parameters")

	// Get client credentials from Authorization header
	clientID, clientSecret, err := s.extractClientCredentials(c)
	if err != nil {
		log.Error().Err(err).Msg("Failed to extract client credentials")
		c.JSON(401, gin.H{
			"error":             "invalid_client",
			"error_description": "Invalid client credentials",
		})
		return
	}

	log.Info().Str("client_id", clientID).Msg("Extracted client credentials")

	// Validate client credentials
	client, err := s.ClientService.ValidateClientCredentials(clientID, clientSecret)
	if err != nil {
		c.JSON(401, gin.H{
			"error":             "invalid_client",
			"error_description": "Invalid client credentials",
		})
		return
	}

	// Validate required parameters
	if licenseXML == "" {
		c.JSON(400, gin.H{
			"error":             "invalid_request",
			"error_description": "Missing license parameter",
		})
		return
	}

	if resource == "" {
		c.JSON(400, gin.H{
			"error":             "invalid_request",
			"error_description": "Missing resource parameter",
		})
		return
	}

	// Create RSL license
	license, err := s.LicenseService.CreateLicense(client.ClientID, resource, licenseXML, nil)
	if err != nil {
		log.Error().Err(err).Msg("Failed to create RSL license")
		c.JSON(400, gin.H{
			"error":             "invalid_license",
			"error_description": err.Error(),
		})
		return
	}

	log.Info().
		Str("client_id", client.ClientID).
		Str("resource", resource).
		Str("license_id", license.LicenseID).
		Msg("Created RSL license")

	// Return RSL license token
	c.JSON(200, gin.H{
		"access_token": license.AccessToken,
		"token_type":   "rsl",
		"expires_in":   0, // Non-expiring by default
	})
}

// introspectHandler handles token introspection requests
func (s *Server) introspectHandler(c *gin.Context) {
	// Get client credentials
	clientID, clientSecret, err := s.extractClientCredentials(c)
	if err != nil {
		c.JSON(401, gin.H{
			"error":             "unauthorized_client",
			"error_description": "Invalid client credentials",
		})
		return
	}

	// Validate client credentials
	_, err = s.ClientService.ValidateClientCredentials(clientID, clientSecret)
	if err != nil {
		c.JSON(401, gin.H{
			"error":             "unauthorized_client",
			"error_description": "Invalid client credentials",
		})
		return
	}

	// Get parameters
	token := c.PostForm("token")
	resource := c.PostForm("resource")

	if token == "" {
		c.JSON(400, gin.H{
			"error":             "invalid_request",
			"error_description": "Missing token parameter",
		})
		return
	}

	if resource == "" {
		c.JSON(400, gin.H{
			"error":             "invalid_request",
			"error_description": "Missing resource parameter",
		})
		return
	}

	// Validate license access
	license, permitted, reason, err := s.LicenseService.ValidateLicenseAccess(token, resource)
	if err != nil {
		// Token not found or invalid
		c.JSON(200, gin.H{
			"active": false,
		})
		return
	}

	// Return introspection response
	response := gin.H{
		"active":     true,
		"token_type": "rsl",
		"license":    license.LicenseXML,
		"resource":   license.Resource,
		"permitted":  permitted,
	}

	if !permitted {
		response["reason"] = reason
	}

	c.JSON(200, response)
}

// keyHandler handles encryption key retrieval requests
func (s *Server) keyHandler(c *gin.Context) {
	// Get client credentials
	clientID, clientSecret, err := s.extractClientCredentials(c)
	if err != nil {
		c.JSON(401, gin.H{
			"error":             "unauthorized_client",
			"error_description": "Invalid client credentials",
		})
		return
	}

	// Validate client credentials
	_, err = s.ClientService.ValidateClientCredentials(clientID, clientSecret)
	if err != nil {
		c.JSON(401, gin.H{
			"error":             "unauthorized_client",
			"error_description": "Invalid client credentials",
		})
		return
	}

	// Get parameters
	token := c.PostForm("token")
	resource := c.PostForm("resource")

	if token == "" {
		c.JSON(400, gin.H{
			"error":             "invalid_request",
			"error_description": "Missing token parameter",
		})
		return
	}

	if resource == "" {
		c.JSON(400, gin.H{
			"error":             "invalid_request",
			"error_description": "Missing resource parameter",
		})
		return
	}

	// Get encryption key
	key, err := s.LicenseService.GetEncryptionKey(token, resource)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get encryption key")
		c.JSON(403, gin.H{
			"error":             "access_denied",
			"error_description": err.Error(),
		})
		return
	}

	// Return encryption key
	c.JSON(200, gin.H{
		"key":      key,
		"resource": resource,
	})
}

// extractClientCredentials extracts client credentials from Authorization header
func (s *Server) extractClientCredentials(c *gin.Context) (string, string, error) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		return "", "", fmt.Errorf("missing authorization header")
	}

	if !strings.HasPrefix(authHeader, "Basic ") {
		return "", "", fmt.Errorf("invalid authorization header format")
	}

	// Decode base64 credentials
	encoded := strings.TrimPrefix(authHeader, "Basic ")
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", "", fmt.Errorf("invalid base64 encoding")
	}

	// Split client_id:client_secret
	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid credentials format")
	}

	return parts[0], parts[1], nil
}

// buildWWWAuthenticateHeader creates the WWW-Authenticate header with resource metadata URL
func (s *Server) buildWWWAuthenticateHeader() string {
	protocol := "https"
	if s.DevMode {
		protocol = "http"
	}

	resourceMetadataURL := fmt.Sprintf("%s://%s/.well-known/oauth-protected-resource", protocol, s.OAuthDomain)
	return fmt.Sprintf("Bearer resource_metadata=\"%%s\", scope=\"mcp:read mcp:write\"", resourceMetadataURL)
}

func normalizeScope(scope string) string {
	switch scope {
	case "https://www.googleapis.com/auth/userinfo.email":
		return "email"
	case "https://www.googleapis.com/auth/userinfo.profile":
		return "profile"
	default:
		return scope
	}
}

// hasRequiredScopes checks if the session has all the required scopes
func (s *Server) hasRequiredScopes(session SessionData) bool {
	if len(s.RequiredScopes) == 0 {
		return true
	}
	granted := make(map[string]struct{})
	for _, sc := range session.Scopes {
		granted[normalizeScope(sc)] = struct{}{}
	}
	for _, req := range s.RequiredScopes {
		if _, ok := granted[normalizeScope(req)]; !ok {
			return false
		}
	}
	return true
}

// authHandler handles Server-Sent Events connections authentication
func (s *Server) authHandler(c *gin.Context) {
	log.Info().
		Str("path", c.Request.URL.Path).
		Str("query", c.Request.URL.RawQuery).
		Str("user_agent", c.Request.UserAgent()).
		Str("referer", c.Request.Referer()).
		Msg("Received MCP auth request")

    // Get the authorization header or query parameter
    authHeader := c.GetHeader("Authorization")
    tokenParam := c.Query("access_token")
	
	// Set CORS headers for the MCP endpoint
	origin := c.Request.Header.Get("Origin")
	if origin == "" {
		origin = "*"
	}
	c.Header("Access-Control-Allow-Origin", origin)
	c.Header("Access-Control-Allow-Methods", "GET, OPTIONS")
	c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")
	c.Header("Access-Control-Allow-Credentials", "true")

	var token string

	// Extract token from header or query parameter
	if authHeader != "" && strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	} else if tokenParam != "" {
		token = tokenParam
	} else {
		// No token provided, return 401 Unauthorized with WWW-Authenticate header
		log.Warn().Msg("Missing authorization token")
		c.Header("WWW-Authenticate", s.buildWWWAuthenticateHeader())
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Unauthorized",
		})
		return
	}

	// Validate the token by checking if it exists in the session store.
	// This is now an efficient O(1) lookup.
	sessionData, ok := s.Sessions.GetByToken(token)

	if !ok {
		// Token not found or expired
		log.Warn().Msg("Invalid or expired token")
		c.Header("WWW-Authenticate", s.buildWWWAuthenticateHeader()+" error=\"invalid_token\"")
		c.JSON(401, gin.H{
			"status":  401,
			"message": "Invalid or expired token",
		})
		return
	}

	// Check if the session has the required scopes
	log.Info().Strs("granted_scopes", sessionData.Scopes).Strs("required_scopes", s.RequiredScopes).Msg("Scopes")
	if !s.hasRequiredScopes(sessionData) {
		log.Warn().Strs("granted_scopes", sessionData.Scopes).Strs("required_scopes", s.RequiredScopes).Msg("Missing required scopes")
		c.Header("WWW-Authenticate", s.buildWWWAuthenticateHeader()+" error=\"insufficient_scope\"")
		c.JSON(403, gin.H{"status": 403, "message": "Insufficient scope"})
		return
	}

	userEmail := sessionData.Email

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
			c.Header("WWW-Authenticate", s.buildWWWAuthenticateHeader())
			c.JSON(401, gin.H{
				"status":  401,
				"message": "Email not in allowed list",
			})
			return
		}
	}

	// Token is valid and email is authorized
	log.Info().Str("email", userEmail).Msg("Authentication and authorization successful")

	// Add X-Forwarded-User header with the authenticated user's email
	c.Header("X-Forwarded-User", userEmail)
	if len(sessionData.Scopes) > 0 {
		c.Header("X-Forwarded-Scopes", strings.Join(sessionData.Scopes, " "))
	}	
	c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(`You're authenticated as '`+userEmail+`'`))

	//Removed this code
	//c.Header("X-Forwarded-User", userEmail)
	//c.Status(http.StatusOK)

}
