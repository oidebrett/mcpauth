package keycloak

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// Provider implements the OAuth provider interface for Keycloak
type Provider struct {
	ClientID         string
	ClientSecret     string
	RedirectURI      string
	Scopes           []string
	AuthHost         string
	AuthPort         int
	AuthProtocol     string // http or https
	Realm            string
	MCPServerURL     string // The MCP server URL for audience validation
}

// TokenInfo represents introspected token information
type TokenInfo struct {
	Active    bool     `json:"active"`
	ClientID  string   `json:"client_id"`
	Email     string   `json:"email"`
	Scopes    []string `json:"scopes"`
	ExpiresAt int64    `json:"exp"`
	Audience  interface{} `json:"aud"` // Can be string or []string
}

// NewProvider creates a new Keycloak OAuth provider
func NewProvider(clientID, clientSecret, redirectURI string, scopes []string, authHost string, authPort int, authProtocol string, realm string, mcpServerURL string) *Provider {
	if scopes == nil || len(scopes) == 0 {
		// Default scopes if none provided
		scopes = []string{"openid", "email", "profile"}
	}

	// Default to https if not specified
	if authProtocol == "" {
		authProtocol = "https"
	}

	return &Provider{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURI:  redirectURI,
		Scopes:       scopes,
		AuthHost:     authHost,
		AuthPort:     authPort,
		AuthProtocol: authProtocol,
		Realm:        realm,
		MCPServerURL: mcpServerURL,
	}
}

// getBaseURL returns the Keycloak base URL
func (p *Provider) getBaseURL() string {
	// Omit port if it's the default for the protocol
	if (p.AuthProtocol == "https" && p.AuthPort == 443) || (p.AuthProtocol == "http" && p.AuthPort == 80) {
		return fmt.Sprintf("%s://%s/realms/%s/", p.AuthProtocol, p.AuthHost, p.Realm)
	}
	return fmt.Sprintf("%s://%s:%d/realms/%s/", p.AuthProtocol, p.AuthHost, p.AuthPort, p.Realm)
}

// GetBaseURL returns the Keycloak base URL (public method)
func (p *Provider) GetBaseURL() string {
	return p.getBaseURL()
}

// GetAuthURL returns the Keycloak OAuth authorization URL
func (p *Provider) GetAuthURL(state string, codeVerifier string, nonce string, scopes []string) string {
	baseURL := p.getBaseURL()
	authURL, err := url.Parse(baseURL + "protocol/openid-connect/auth")
	if err != nil {
		log.Error().Err(err).Msg("Failed to parse Keycloak auth URL")
		return ""
	}

	// Generate code challenge from code verifier (PKCE)
	// S256 method: BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
	h := sha256.New()
	h.Write([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	if len(scopes) == 0 {
		scopes = p.Scopes // fallback to provider defaults
	}

	// Add query parameters
	q := authURL.Query()
	q.Set("client_id", p.ClientID)
	q.Set("redirect_uri", p.RedirectURI)
	q.Set("response_type", "code")
	q.Set("scope", strings.Join(scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")

	authURL.RawQuery = q.Encode()

	return authURL.String()
}

// ExchangeToken exchanges an authorization code for access and ID tokens
func (p *Provider) ExchangeToken(code string, codeVerifier string) (string, string, []string, error) {
	// Create the token exchange request
	baseURL := p.getBaseURL()
	tokenURL := baseURL + "protocol/openid-connect/token"

	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", p.ClientID)
	data.Set("client_secret", p.ClientSecret)
	data.Set("redirect_uri", p.RedirectURI)
	data.Set("grant_type", "authorization_code")
	data.Set("code_verifier", codeVerifier)

	// Make the request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.PostForm(tokenURL, data)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to make token exchange request: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", nil, fmt.Errorf("failed to read token exchange response: %w", err)
	}

	// Check for error response
	if resp.StatusCode != http.StatusOK {
		return "", "", nil, fmt.Errorf("token exchange failed: %s - %s", resp.Status, string(body))
	}

	// Parse the response
	var tokenResponse struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
	}

	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return "", "", nil, fmt.Errorf("failed to parse token exchange response: %w", err)
	}

	// Validate the response
	if tokenResponse.AccessToken == "" {
		return "", "", nil, fmt.Errorf("no access token in response")
	}

	scopes := strings.Split(tokenResponse.Scope, " ")
	return tokenResponse.AccessToken, tokenResponse.IDToken, scopes, nil
}

// GetUserInfo retrieves the user's profile information using the access token
func (p *Provider) GetUserInfo(accessToken string) (map[string]interface{}, error) {
	// Create the user info request
	baseURL := p.getBaseURL()
	userInfoURL := baseURL + "protocol/openid-connect/userinfo"

	req, err := http.NewRequest("GET", userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create user info request: %w", err)
	}

	// Add the access token to the request
	req.Header.Add("Authorization", "Bearer "+accessToken)

	// Make the request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make user info request: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read user info response: %w", err)
	}

	// Check for error response
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("user info request failed: %s - %s", resp.Status, string(body))
	}

	// Parse the response
	var userInfo map[string]interface{}
	if err := json.Unmarshal(body, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to parse user info response: %w", err)
	}

	return userInfo, nil
}

// IntrospectToken validates a token using Keycloak's introspection endpoint
// This is used for MCP authentication (Bearer token validation)
func (p *Provider) IntrospectToken(token string) (*TokenInfo, error) {
	baseURL := p.getBaseURL()
	introspectionURL := baseURL + "protocol/openid-connect/token/introspect"

	// Prepare introspection request
	data := url.Values{}
	data.Set("token", token)
	data.Set("client_id", p.ClientID)
	if p.ClientSecret != "" {
		data.Set("client_secret", p.ClientSecret)
	}

	// Make the request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.PostForm(introspectionURL, data)
	if err != nil {
		log.Error().Err(err).Msg("[Keycloak] Introspection request failed")
		return nil, fmt.Errorf("introspection request failed: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Error().Err(err).Msg("[Keycloak] Failed to read introspection response")
		return nil, fmt.Errorf("failed to read introspection response: %w", err)
	}

	// Check for error response
	if resp.StatusCode != http.StatusOK {
		log.Error().
			Int("status", resp.StatusCode).
			Str("body", string(body)).
			Msg("[Keycloak] Introspection failed")
		return nil, fmt.Errorf("introspection failed: %s - %s", resp.Status, string(body))
	}

	// Parse the response
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		log.Error().Err(err).Msg("[Keycloak] Failed to parse introspection response")
		return nil, fmt.Errorf("failed to parse introspection response: %w", err)
	}

	// Check if token is active
	active, ok := result["active"].(bool)
	if !ok || !active {
		log.Warn().Msg("[Keycloak] Token is inactive")
		return nil, fmt.Errorf("inactive token")
	}

	// Validate audience if MCP server URL is configured
	if p.MCPServerURL != "" {
		if aud, exists := result["aud"]; exists {
			if !p.checkResourceAllowed(aud) {
				audiences := p.formatAudience(aud)
				log.Warn().
					Str("expected", p.MCPServerURL).
					Str("got", audiences).
					Msg("[Keycloak] Audience validation failed")
				return nil, fmt.Errorf("none of the provided audiences are allowed. Expected %s, got: %s", p.MCPServerURL, audiences)
			}
		} else {
			log.Warn().Msg("[Keycloak] Resource indicator (aud) missing")
			return nil, fmt.Errorf("resource indicator (aud) missing")
		}
	}

	// Extract token information
	tokenInfo := &TokenInfo{
		Active: true,
	}

	if clientID, ok := result["client_id"].(string); ok {
		tokenInfo.ClientID = clientID
	}

	if email, ok := result["email"].(string); ok {
		tokenInfo.Email = email
	}

	if scope, ok := result["scope"].(string); ok {
		tokenInfo.Scopes = strings.Split(scope, " ")
	}

	if exp, ok := result["exp"].(float64); ok {
		tokenInfo.ExpiresAt = int64(exp)
	}

	tokenInfo.Audience = result["aud"]

	return tokenInfo, nil
}

// checkResourceAllowed validates if the audience matches the configured MCP server URL
func (p *Provider) checkResourceAllowed(aud interface{}) bool {
	var audiences []string

	switch v := aud.(type) {
	case string:
		audiences = []string{v}
	case []interface{}:
		for _, a := range v {
			if s, ok := a.(string); ok {
				audiences = append(audiences, s)
			}
		}
	case []string:
		audiences = v
	default:
		return false
	}

	// Check if any audience matches the MCP server URL
	for _, audience := range audiences {
		if p.resourceMatches(audience, p.MCPServerURL) {
			return true
		}
	}

	return false
}

// resourceMatches checks if the requested resource matches the configured resource
// This implements the same logic as checkResourceAllowed from the MCP SDK
func (p *Provider) resourceMatches(requested, configured string) bool {
	// Parse both URLs
	requestedURL, err := url.Parse(requested)
	if err != nil {
		return false
	}

	configuredURL, err := url.Parse(configured)
	if err != nil {
		return false
	}

	// Compare scheme, host, and path prefix
	if requestedURL.Scheme != configuredURL.Scheme {
		return false
	}

	if requestedURL.Host != configuredURL.Host {
		return false
	}

	// Check if requested path starts with configured path
	return strings.HasPrefix(requestedURL.Path, configuredURL.Path)
}

// formatAudience converts the audience to a readable string
func (p *Provider) formatAudience(aud interface{}) string {
	switch v := aud.(type) {
	case string:
		return v
	case []interface{}:
		var audiences []string
		for _, a := range v {
			if s, ok := a.(string); ok {
				audiences = append(audiences, s)
			}
		}
		return strings.Join(audiences, ", ")
	case []string:
		return strings.Join(v, ", ")
	default:
		return fmt.Sprintf("%v", aud)
	}
}
