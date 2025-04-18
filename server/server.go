package server

import (
    "fmt"
    "github.com/gin-gonic/gin"
    "github.com/rs/zerolog/log"
    "math/rand"
    "time"
)

func init() {
    // Seed the random number generator
    rand.Seed(time.Now().UnixNano())
}

// Server represents the HTTP server
// This comment was added to verify file path
type Server struct {
    Router     *gin.Engine
    Path       string
    BaseDomain string // Base domain for OAuth endpoints
    DevMode    bool   // Development mode flag
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
    }

    // Setup routes
    server.setupRoutes()

    return server
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

// generateRandomString creates a random string of the specified length
func generateRandomString(length int) string {
    const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    b := make([]byte, length)
    for i := range b {
        b[i] = charset[rand.Intn(len(charset))]
    }
    return string(b)
}
