package google

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

// Provider implements the OAuth provider interface for Google
type Provider struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scopes       []string
}

// UserInfo represents the user info returned by Google
type UserInfo struct {
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

// NewProvider creates a new Google OAuth provider
func NewProvider(clientID, clientSecret, redirectURI string, scopes []string) *Provider {
	if scopes == nil || len(scopes) == 0 {
		// Default scopes if none provided
		scopes = []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
			"openid",
		}
	}
	
	return &Provider{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURI:  redirectURI,
		Scopes:       scopes,
	}
}

// GetAuthURL returns the Google OAuth authorization URL
func (p *Provider) GetAuthURL(state string, codeVerifier string, nonce string) string {
	// Create the authorization URL
	authURL, err := url.Parse("https://accounts.google.com/o/oauth2/v2/auth")
	if err != nil {
		log.Error().Err(err).Msg("Failed to parse auth URL")
		return ""
	}
	
	// Generate code challenge from code verifier (PKCE)
	// S256 method: BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
	h := sha256.New()
	h.Write([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h.Sum(nil))
	
	// Add query parameters
	q := authURL.Query()
	q.Set("client_id", p.ClientID)
	q.Set("redirect_uri", p.RedirectURI)
	q.Set("response_type", "code")
	q.Set("scope", strings.Join(p.Scopes, " "))
	q.Set("state", state)
	q.Set("nonce", nonce)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	q.Set("access_type", "offline")
	q.Set("prompt", "consent")
	
	authURL.RawQuery = q.Encode()
	
	return authURL.String()
}

// ExchangeToken exchanges an authorization code for access and ID tokens
func (p *Provider) ExchangeToken(code string, codeVerifier string) (string, string, error) {
	// Create the token exchange request
	tokenURL := "https://oauth2.googleapis.com/token"
	
	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", p.ClientID)
	data.Set("client_secret", p.ClientSecret)
	data.Set("redirect_uri", p.RedirectURI)
	data.Set("grant_type", "authorization_code")
	data.Set("code_verifier", codeVerifier) // Add the code verifier
	
	// Make the request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.PostForm(tokenURL, data)
	if err != nil {
		return "", "", fmt.Errorf("failed to make token exchange request: %w", err)
	}
	defer resp.Body.Close()
	
	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("failed to read token exchange response: %w", err)
	}
	
	// Check for error response
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("token exchange failed: %s - %s", resp.Status, string(body))
	}
	
	// Parse the response
	var tokenResponse struct {
		AccessToken  string `json:"access_token"`
		IDToken      string `json:"id_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
	}
	
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return "", "", fmt.Errorf("failed to parse token exchange response: %w", err)
	}
	
	// Validate the response
	if tokenResponse.AccessToken == "" {
		return "", "", fmt.Errorf("no access token in response")
	}
	
	return tokenResponse.AccessToken, tokenResponse.IDToken, nil
}

// GetUserInfo retrieves the user's profile information using the access token
func (p *Provider) GetUserInfo(accessToken string) (map[string]interface{}, error) {
	// Create the user info request
	userInfoURL := "https://www.googleapis.com/oauth2/v3/userinfo"
	
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
