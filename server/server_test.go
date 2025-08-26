package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestOAuthProtectedResourceHandler(t *testing.T) {
	// Set Gin to test mode
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name               string
		path               string
		host               string
		xForwardedHost     string
		devMode            bool
		oauthDomain        string
		expectedResource   string
		expectedAuthServer string
		expectedProtocol   string
	}{
		{
			name:               "Root path without forwarded host",
			path:               "/.well-known/oauth-protected-resource",
			host:               "localhost:11000",
			xForwardedHost:     "",
			devMode:            true,
			oauthDomain:        "oauth.example.com",
			expectedResource:   "http://localhost:11000",
			expectedAuthServer: "http://oauth.example.com/",
			expectedProtocol:   "http",
		},
		{
			name:               "Root path with forwarded host",
			path:               "/.well-known/oauth-protected-resource",
			host:               "localhost:11000",
			xForwardedHost:     "internal.mcpgateway.online",
			devMode:            true,
			oauthDomain:        "oauth.mcpgateway.online",
			expectedResource:   "http://internal.mcpgateway.online",
			expectedAuthServer: "http://oauth.mcpgateway.online/",
			expectedProtocol:   "http",
		},
		{
			name:               "Path-based resource without forwarded host",
			path:               "/.well-known/oauth-protected-resource/mcp",
			host:               "localhost:11000",
			xForwardedHost:     "",
			devMode:            true,
			oauthDomain:        "oauth.example.com",
			expectedResource:   "http://localhost:11000/mcp",
			expectedAuthServer: "http://oauth.example.com/",
			expectedProtocol:   "http",
		},
		{
			name:               "Path-based resource with forwarded host",
			path:               "/.well-known/oauth-protected-resource/mcp",
			host:               "localhost:11000",
			xForwardedHost:     "internal.mcpgateway.online",
			devMode:            true,
			oauthDomain:        "oauth.mcpgateway.online",
			expectedResource:   "http://internal.mcpgateway.online/mcp",
			expectedAuthServer: "http://oauth.mcpgateway.online/",
			expectedProtocol:   "http",
		},
		{
			name:               "Complex path with forwarded host",
			path:               "/.well-known/oauth-protected-resource/v1/users",
			host:               "localhost:11000",
			xForwardedHost:     "api.example.com",
			devMode:            true,
			oauthDomain:        "oauth.example.com",
			expectedResource:   "http://api.example.com/v1/users",
			expectedAuthServer: "http://oauth.example.com/",
			expectedProtocol:   "http",
		},
		{
			name:               "HTTPS production mode",
			path:               "/.well-known/oauth-protected-resource/mcp",
			host:               "localhost:11000",
			xForwardedHost:     "internal.mcpgateway.online",
			devMode:            false,
			oauthDomain:        "oauth.mcpgateway.online",
			expectedResource:   "https://internal.mcpgateway.online/mcp",
			expectedAuthServer: "https://oauth.mcpgateway.online/",
			expectedProtocol:   "https",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create server instance
			server := NewServer(tt.oauthDomain, tt.devMode)

			// Create request
			req, err := http.NewRequest("GET", tt.path, nil)
			assert.NoError(t, err)
			req.Host = tt.host
			if tt.xForwardedHost != "" {
				req.Header.Set("X-Forwarded-Host", tt.xForwardedHost)
			}

			// Create response recorder
			w := httptest.NewRecorder()

			// Create Gin context
			c, _ := gin.CreateTestContext(w)
			c.Request = req

			// Call the handler
			server.oauthProtectedResourceHandler(c)

			// Check response status
			assert.Equal(t, http.StatusOK, w.Code)

			// Parse response body
			var response map[string]interface{}
			err = json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)

			// Verify response structure
			assert.Contains(t, response, "resource")
			assert.Contains(t, response, "authorization_servers")
			assert.Contains(t, response, "scopes_supported")
			assert.Contains(t, response, "resource_name")

			// Verify resource URL
			assert.Equal(t, tt.expectedResource, response["resource"])
			assert.Equal(t, tt.expectedResource, response["resource_name"])

			// Verify authorization servers
			authServers, ok := response["authorization_servers"].([]interface{})
			assert.True(t, ok)
			assert.Len(t, authServers, 1)
			assert.Equal(t, tt.expectedAuthServer, authServers[0])

			// Verify scopes
			scopes, ok := response["scopes_supported"].([]interface{})
			assert.True(t, ok)
			assert.Contains(t, scopes, "read")
			assert.Contains(t, scopes, "write")

			// Verify CORS headers
			assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
			assert.Equal(t, "GET, OPTIONS", w.Header().Get("Access-Control-Allow-Methods"))
			assert.Equal(t, "Authorization, Content-Type, mcp-protocol-version", w.Header().Get("Access-Control-Allow-Headers"))
			assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
		})
	}
}

func TestOAuthProtectedResourceHandlerCORS(t *testing.T) {
	gin.SetMode(gin.TestMode)
	server := NewServer("oauth.example.com", true)

	// Test with specific Origin header
	req, err := http.NewRequest("GET", "/.well-known/oauth-protected-resource", nil)
	assert.NoError(t, err)
	req.Header.Set("Origin", "https://client.example.com")

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = req

	server.oauthProtectedResourceHandler(c)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "https://client.example.com", w.Header().Get("Access-Control-Allow-Origin"))
}
