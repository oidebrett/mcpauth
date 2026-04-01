package keycloak

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// Helper functions
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

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
	jwksCache        *jwksCache
}

// JWKS represents a JSON Web Key Set
type jwks struct {
	Keys []jwk `json:"keys"`
}

// JWK represents a JSON Web Key
type jwk struct {
	Kid string `json:"kid"` // Key ID
	Kty string `json:"kty"` // Key type
	Alg string `json:"alg"` // Algorithm
	Use string `json:"use"` // Usage
	N   string `json:"n"`   // Modulus (RSA)
	E   string `json:"e"`   // Exponent (RSA)
}

// jwksCache caches JWKS public keys
type jwksCache struct {
	mu          sync.RWMutex
	keys        map[string]*rsa.PublicKey
	lastFetched time.Time
	ttl         time.Duration
	jwksURL     string
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

	// Construct JWKS URL
	var jwksURL string
	if (authProtocol == "https" && authPort == 443) || (authProtocol == "http" && authPort == 80) {
		jwksURL = fmt.Sprintf("%s://%s/realms/%s/protocol/openid-connect/certs", authProtocol, authHost, realm)
	} else {
		jwksURL = fmt.Sprintf("%s://%s:%d/realms/%s/protocol/openid-connect/certs", authProtocol, authHost, authPort, realm)
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
		jwksCache: &jwksCache{
			keys:    make(map[string]*rsa.PublicKey),
			ttl:     10 * time.Minute, // Cache public keys for 10 minutes
			jwksURL: jwksURL,
		},
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
		log.Error().
			Str("token_url", tokenURL).
			Str("client_id", p.ClientID).
			Str("redirect_uri", p.RedirectURI).
			Int("status", resp.StatusCode).
			Str("response", string(body)).
			Msg("Keycloak token exchange failed")
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

	// Log the introspection request details
	log.Info().
		Str("url", introspectionURL).
		Str("client_id", p.ClientID).
		Str("token_prefix", token[:min(20, len(token))]).
		Str("token_suffix", token[max(0, len(token)-10):]).
		Int("token_length", len(token)).
		Msg("[Keycloak] Starting token introspection")

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

	// Log the full introspection response
	log.Info().
		Interface("response", result).
		Msg("[Keycloak] Introspection response received")

	// Check if token is active
	active, ok := result["active"].(bool)
	if !ok || !active {
		log.Warn().
			Interface("full_response", result).
			Bool("active_field_present", ok).
			Bool("active_value", active).
			Msg("[Keycloak] Token is inactive - full details")
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

// ValidateJWT validates a JWT token locally without introspection
// This is the RECOMMENDED approach for token validation
func (p *Provider) ValidateJWT(token string) (*TokenInfo, error) {
	log.Info().Msg("[Keycloak] Starting JWT validation (local, no introspection)")

	// Parse JWT header to get kid
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	// Decode header
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT header: %w", err)
	}

	var header struct {
		Kid string `json:"kid"`
		Alg string `json:"alg"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, fmt.Errorf("failed to parse JWT header: %w", err)
	}

	log.Info().
		Str("kid", header.Kid).
		Str("alg", header.Alg).
		Msg("[Keycloak] JWT header parsed")

	// Get public key for this kid
	publicKey, err := p.getPublicKey(header.Kid)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Verify signature
	message := parts[0] + "." + parts[1]
	signatureBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	// Hash the message
	hashed := sha256.Sum256([]byte(message))

	// Verify RSA signature (using SHA256 hash algorithm)
	if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signatureBytes); err != nil {
		log.Warn().Err(err).Msg("[Keycloak] JWT signature verification failed")
		return nil, fmt.Errorf("invalid JWT signature: %w", err)
	}

	log.Info().Msg("[Keycloak] JWT signature verified successfully")

	// Decode and parse claims
	claimsBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("failed to decode JWT claims: %w", err)
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, fmt.Errorf("failed to parse JWT claims: %w", err)
	}

	// Validate expiration
	if exp, ok := claims["exp"].(float64); ok {
		if time.Now().Unix() > int64(exp) {
			log.Warn().Int64("exp", int64(exp)).Msg("[Keycloak] JWT token expired")
			return nil, fmt.Errorf("token expired")
		}
	} else {
		return nil, fmt.Errorf("missing exp claim")
	}

	// Validate issuer
	baseURL := p.getBaseURL()
	if iss, ok := claims["iss"].(string); ok {
		if !strings.HasPrefix(iss, baseURL) && iss != strings.TrimSuffix(baseURL, "/") {
			log.Warn().
				Str("expected", baseURL).
				Str("got", iss).
				Msg("[Keycloak] JWT issuer mismatch")
			return nil, fmt.Errorf("invalid issuer")
		}
	}

	// Validate audience if configured
	if p.MCPServerURL != "" {
		if aud, exists := claims["aud"]; exists {
			if !p.checkResourceAllowed(aud) {
				audiences := p.formatAudience(aud)
				log.Warn().
					Str("expected", p.MCPServerURL).
					Str("got", audiences).
					Msg("[Keycloak] JWT audience validation failed")
				return nil, fmt.Errorf("audience validation failed. Expected %s, got: %s", p.MCPServerURL, audiences)
			}
		} else {
			log.Warn().Msg("[Keycloak] JWT missing audience claim")
			return nil, fmt.Errorf("missing audience claim")
		}
	}

	// Extract token info
	tokenInfo := &TokenInfo{
		Active: true,
	}

	if email, ok := claims["email"].(string); ok {
		tokenInfo.Email = email
	}
	if preferredUsername, ok := claims["preferred_username"].(string); ok && tokenInfo.Email == "" {
		tokenInfo.Email = preferredUsername
	}

	if scope, ok := claims["scope"].(string); ok {
		tokenInfo.Scopes = strings.Split(scope, " ")
	}

	if exp, ok := claims["exp"].(float64); ok {
		tokenInfo.ExpiresAt = int64(exp)
	}

	if azp, ok := claims["azp"].(string); ok {
		tokenInfo.ClientID = azp
	}

	tokenInfo.Audience = claims["aud"]

	log.Info().
		Str("email", tokenInfo.Email).
		Strs("scopes", tokenInfo.Scopes).
		Str("client_id", tokenInfo.ClientID).
		Int64("expires_at", tokenInfo.ExpiresAt).
		Msg("[Keycloak] JWT validation successful")

	return tokenInfo, nil
}

// getPublicKey retrieves the public key for a given kid, using cache
func (p *Provider) getPublicKey(kid string) (*rsa.PublicKey, error) {
	cache := p.jwksCache

	cache.mu.RLock()
	// Check if we have a cached key and it's not expired
	if key, exists := cache.keys[kid]; exists && time.Since(cache.lastFetched) < cache.ttl {
		cache.mu.RUnlock()
		log.Debug().Str("kid", kid).Msg("[Keycloak] Using cached public key")
		return key, nil
	}
	cache.mu.RUnlock()

	// Fetch JWKS
	cache.mu.Lock()
	defer cache.mu.Unlock()

	// Double-check after acquiring write lock
	if key, exists := cache.keys[kid]; exists && time.Since(cache.lastFetched) < cache.ttl {
		log.Debug().Str("kid", kid).Msg("[Keycloak] Using cached public key (race check)")
		return key, nil
	}

	log.Info().Str("jwks_url", cache.jwksURL).Msg("[Keycloak] Fetching JWKS")

	resp, err := http.Get(cache.jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWKS response: %w", err)
	}

	var keySet jwks
	if err := json.Unmarshal(body, &keySet); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS: %w", err)
	}

	log.Info().Int("key_count", len(keySet.Keys)).Msg("[Keycloak] JWKS fetched successfully")

	// Parse all keys and cache them
	cache.keys = make(map[string]*rsa.PublicKey)
	for _, key := range keySet.Keys {
		if key.Kty != "RSA" {
			continue
		}

		// Decode modulus (n)
		nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
		if err != nil {
			log.Warn().Str("kid", key.Kid).Err(err).Msg("[Keycloak] Failed to decode key modulus")
			continue
		}

		// Decode exponent (e)
		eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
		if err != nil {
			log.Warn().Str("kid", key.Kid).Err(err).Msg("[Keycloak] Failed to decode key exponent")
			continue
		}

		// Convert exponent bytes to int
		var eInt int
		for _, b := range eBytes {
			eInt = eInt<<8 + int(b)
		}

		// Create RSA public key
		pubKey := &rsa.PublicKey{
			N: new(big.Int).SetBytes(nBytes),
			E: eInt,
		}

		cache.keys[key.Kid] = pubKey
		log.Debug().Str("kid", key.Kid).Msg("[Keycloak] Cached public key")
	}

	cache.lastFetched = time.Now()

	// Return the requested key
	if key, exists := cache.keys[kid]; exists {
		return key, nil
	}

	return nil, fmt.Errorf("key with kid '%s' not found in JWKS", kid)
}
