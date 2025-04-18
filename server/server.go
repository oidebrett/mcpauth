package server

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Server represents the HTTP server
// This comment was added to verify file path
type Server struct {
	Router     *gin.Engine
	Path       string
	BaseDomain string // Base domain for OAuth endpoints
	DevMode    bool   // Development mode flag
	
	// Google OAuth configuration
	GoogleOAuth GoogleOAuthConfig
	
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

// GoogleOAuthConfig holds the configuration for Google OAuth
type GoogleOAuthConfig struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scopes       []string
}

// GoogleUserInfo represents the user info returned by Google
type GoogleUserInfo struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	VerifiedEmail bool   `json:"verified_email"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Locale        string `json:"locale"`
	HD            string `json:"hd"` // Hosted domain (for Google Workspace accounts)
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
	s.GoogleOAuth = GoogleOAuthConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURI:  redirectURI,
		Scopes:       scopes,
	}
}

// setupRoutes configures the server routes
func (s *Server) setupRoutes() {
	// Add the route for the specified path
	s.Router.GET(s.Path, s.unauthorizedHandler)
	
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

// authorizeHandler initiates the OAuth2 flow with Google
func (s *Server) authorizeHandler(c *gin.Context) {
	log.Info().Str("path", c.Request.URL.Path).Msg("Received authorization request")
	
	// Parse the incoming request
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	responseType := c.Query("response_type")
	scope := c.Query("scope")
	if scope == "" {
		scope = "openid email profile"
	}
	
	// Validate required parameters
	if clientID == "" || redirectURI == "" || responseType != "code" {
		c.JSON(400, gin.H{
			"error": "invalid_request",
			"error_description": "Missing required parameters",
		})
		return
	}
	
	// Initialize sessions map if needed
	if s.Sessions == nil {
		s.Sessions = make(map[string]SessionData)
	}
	
	// Generate state and nonce
	state := generateRandomString(32)
	nonce := generateRandomString(32)
	
	// Store the session data
	s.Sessions[state] = SessionData{
		State:        state,
		ClientID:     clientID,
		RedirectURI:  redirectURI,
		Nonce:        nonce,
	}
	
	// Build the Google authorization URL
	authURL, err := url.Parse("https://accounts.google.com/o/oauth2/v2/auth")
	if err != nil {
		log.Error().Err(err).Msg("Failed to parse Google authorize URL")
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}
	
	q := authURL.Query()
	q.Set("client_id", s.GoogleOAuth.ClientID)
	q.Set("redirect_uri", s.GoogleOAuth.RedirectURI)
	q.Set("response_type", "code")
	q.Set("scope", scope)
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("access_type", "offline") // Request a refresh token
	q.Set("prompt", "consent")      // Force consent screen to ensure refresh token
	
	authURL.RawQuery = q.Encode()
	
	log.Info().Str("auth_url", authURL.String()).Msg("Redirecting to Google OAuth")
	
	// Redirect to Google's authorization endpoint
	c.Redirect(http.StatusTemporaryRedirect, authURL.String())
}

// callbackHandler processes the OAuth callback from Google
func (s *Server) callbackHandler(c *gin.Context) {
	log.Info().Str("path", c.Request.URL.Path).Msg("Received callback from Google")
	
	// Get the authorization code and state from the request
	code := c.Query("code")
	state := c.Query("state")
	
	// Validate state parameter to prevent CSRF
	sessionData, exists := s.Sessions[state]
	if !exists {
		c.JSON(400, gin.H{
			"error": "invalid_request",
			"error_description": "Invalid state parameter",
		})
		return
	}
	
	// Exchange the authorization code for tokens
	tokenURL := "https://oauth2.googleapis.com/token"
	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", s.GoogleOAuth.ClientID)
	data.Set("client_secret", s.GoogleOAuth.ClientSecret)
	data.Set("redirect_uri", s.GoogleOAuth.RedirectURI)
	data.Set("grant_type", "authorization_code")
	
	req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		log.Error().Err(err).Msg("Failed to create token request")
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}
	
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Error().Err(err).Msg("Failed to exchange code for token")
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error().Err(err).Msg("Failed to read token response")
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}
	
	var tokenResponse struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		TokenType    string `json:"token_type"`
	}
	
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		log.Error().Err(err).Msg("Failed to parse token response")
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}
	
	// Store tokens in session
	sessionData.AccessToken = tokenResponse.AccessToken
	sessionData.IDToken = tokenResponse.IDToken
	sessionData.ExpiresAt = time.Now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second)
	s.Sessions[state] = sessionData
	
	// Get user info
	userInfo, err := s.getUserInfo(tokenResponse.AccessToken)
	if err != nil {
		log.Error().Err(err).Msg("Failed to get user info")
		c.JSON(500, gin.H{"error": "server_error"})
		return
	}
	
	log.Info().Str("email", userInfo.Email).Msg("User authenticated")
	
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
	
	c.Redirect(http.StatusTemporaryRedirect, redirectURL.String())
}

// getUserInfo fetches the user's profile from Google
func (s *Server) getUserInfo(accessToken string) (*GoogleUserInfo, error) {
	userInfoURL := "https://www.googleapis.com/oauth2/v1/userinfo"
	
	req, err := http.NewRequest("GET", userInfoURL, nil)
	if err != nil {
		return nil, err
	}
	
	req.Header.Add("Authorization", "Bearer "+accessToken)
	
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	
	var userInfo GoogleUserInfo
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, err
	}
	
	return &userInfo, nil
}

// tokenHandler exchanges an authorization code for tokens
func (s *Server) tokenHandler(c *gin.Context) {
	log.Info().Str("path", c.Request.URL.Path).Msg("Received token request")
	
	// Parse the token request
	grantType := c.PostForm("grant_type")
	code := c.PostForm("code")
	redirectURI := c.PostForm("redirect_uri")
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")
	
	// Validate client credentials
	if clientID != s.GoogleOAuth.ClientID || clientSecret != s.GoogleOAuth.ClientSecret {
		c.JSON(401, gin.H{
			"error": "invalid_client",
			"error_description": "Invalid client credentials",
		})
		return
	}
	
	// Validate required parameters
	if grantType != "authorization_code" || code == "" || redirectURI == "" {
		c.JSON(400, gin.H{
			"error": "invalid_request",
			"error_description": "Missing required parameters",
		})
		return
	}
	
	// Find the session with this code
	var sessionData SessionData
	var sessionKey string
	found := false
	
	for key, session := range s.Sessions {
		if session.ClientID == clientID && session.RedirectURI == redirectURI {
			sessionData = session
			sessionKey = key
			found = true
			break
		}
	}
	
	if !found {
		c.JSON(400, gin.H{
			"error": "invalid_grant",
			"error_description": "Invalid authorization code",
		})
		return
	}
	
	// Return the tokens
	c.JSON(200, gin.H{
		"access_token": sessionData.AccessToken,
		"token_type": "Bearer",
		"expires_in": int(time.Until(sessionData.ExpiresAt).Seconds()),
		"id_token": sessionData.IDToken,
	})
	
	// Remove the session after use
	delete(s.Sessions, sessionKey)
}
