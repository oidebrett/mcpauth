package server

import (
    "net/http"

    "github.com/gin-gonic/gin"
    "github.com/rs/zerolog/log"
)

// Server represents the HTTP server
type Server struct {
    Router *gin.Engine
    Path   string
}

// NewServer creates a new server instance
func NewServer(path string) *Server {
    // Disable gin debug logs
    gin.SetMode(gin.ReleaseMode)

    // Create router
    router := gin.New()
    router.Use(gin.Recovery())

    // Create server
    server := &Server{
        Router: router,
        Path:   path,
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