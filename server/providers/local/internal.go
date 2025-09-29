package local

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog/log"

	"mcpauth/server/database"
)

// Provider implements the OAuth provider interface for internal authentication
type Provider struct {
	BaseURL      string
	UserRepo     *database.UserRepository
	ClientRepo   *database.ClientRepository
	AuthCodeRepo *database.AuthCodeRepository
	TokenRepo    *database.TokenRepository
}

// NewProvider creates a new internal OAuth provider
func NewProvider(baseURL string, userRepo *database.UserRepository, clientRepo *database.ClientRepository, authCodeRepo *database.AuthCodeRepository, tokenRepo *database.TokenRepository) *Provider {
	return &Provider{
		BaseURL:      baseURL,
		UserRepo:     userRepo,
		ClientRepo:   clientRepo,
		AuthCodeRepo: authCodeRepo,
		TokenRepo:    tokenRepo,
	}
}

// GetAuthURL returns the internal authorization URL
func (p *Provider) GetAuthURL(state string, codeVerifier string, nonce string, scopes []string) string {
	authURL, err := url.Parse(p.BaseURL + "/internal/authorize")
	if err != nil {
		log.Error().Err(err).Msg("Failed to parse auth URL")
		return ""
	}

	// Generate code challenge from code verifier (PKCE)
	h := sha256.New()
	h.Write([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h.Sum(nil))

	params := url.Values{}
	params.Set("state", state)
	params.Set("nonce", nonce)
	params.Set("code_challenge", codeChallenge)
	params.Set("code_challenge_method", "S256")
	if len(scopes) > 0 {
		params.Set("scope", strings.Join(scopes, " "))
	}

	authURL.RawQuery = params.Encode()
	return authURL.String()
}

// ExchangeToken exchanges an authorization code for tokens (not used for internal provider)
func (p *Provider) ExchangeToken(code string, codeVerifier string) (string, string, []string, error) {
	// For internal provider, token exchange is handled directly by the server
	return "", "", nil, fmt.Errorf("internal provider does not support external token exchange")
}

// GetUserInfo retrieves user information from an access token
func (p *Provider) GetUserInfo(accessToken string) (map[string]interface{}, error) {
	token, err := p.TokenRepo.GetAccessToken(accessToken)
	if err != nil {
		return nil, fmt.Errorf("invalid access token: %w", err)
	}

	user, err := p.UserRepo.GetUserByID(token.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	scopes, err := token.GetScopes()
	if err != nil {
		return nil, fmt.Errorf("failed to parse token scopes: %w", err)
	}

	userInfo := map[string]interface{}{
		"sub": fmt.Sprintf("%d", user.ID),
	}

	// Add user info based on scopes
	for _, scope := range scopes {
		switch scope {
		case "profile":
			userInfo["name"] = user.FirstName + " " + user.LastName
			userInfo["given_name"] = user.FirstName
			userInfo["family_name"] = user.LastName
			userInfo["preferred_username"] = user.Username
		case "email":
			userInfo["email"] = user.Email
			userInfo["email_verified"] = true
		}
	}

	return userInfo, nil
}

// AuthenticateUser authenticates a user with username/password
func (p *Provider) AuthenticateUser(username, password string) (*database.User, error) {
	user, err := p.UserRepo.GetUserByUsername(username)
	if err != nil {
		// Try email as well
		user, err = p.UserRepo.GetUserByEmail(username)
		if err != nil {
			return nil, fmt.Errorf("user not found")
		}
	}

	if !p.UserRepo.ValidatePassword(user, password) {
		return nil, fmt.Errorf("invalid password")
	}

	return user, nil
}

// CreateAuthorizationCode creates an authorization code for a user
func (p *Provider) CreateAuthorizationCode(clientID string, userID int, redirectURI string, scopes []string) (*database.AuthorizationCode, error) {
	// Authorization codes expire in 10 minutes
	expiresAt := time.Now().Add(10 * time.Minute)
	
	return p.AuthCodeRepo.CreateAuthCode(clientID, userID, redirectURI, scopes, expiresAt)
}

// ExchangeAuthorizationCode exchanges an authorization code for an access token
func (p *Provider) ExchangeAuthorizationCode(code, clientID, redirectURI string) (*database.AccessToken, map[string]interface{}, error) {
	// Get and validate authorization code
	authCode, err := p.AuthCodeRepo.GetAuthCode(code)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid authorization code")
	}

	// Validate client ID and redirect URI
	if authCode.ClientID != clientID || authCode.RedirectURI != redirectURI {
		return nil, nil, fmt.Errorf("invalid client or redirect URI")
	}

	// Mark code as used
	if err := p.AuthCodeRepo.UseAuthCode(code); err != nil {
		return nil, nil, fmt.Errorf("failed to use authorization code: %w", err)
	}

	// Get scopes from authorization code
	scopes, err := authCode.GetScopes()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse scopes: %w", err)
	}

	// Create access token (expires in 1 hour)
	expiresAt := time.Now().Add(1 * time.Hour)
	accessToken, err := p.TokenRepo.CreateAccessToken(clientID, authCode.UserID, scopes, expiresAt)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create access token: %w", err)
	}

	// Create ID token if openid scope is present
	var idToken map[string]interface{}
	for _, scope := range scopes {
		if scope == "openid" {
			user, err := p.UserRepo.GetUserByID(authCode.UserID)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to get user: %w", err)
			}

			idToken = map[string]interface{}{
				"iss": p.BaseURL,
				"sub": fmt.Sprintf("%d", user.ID),
				"aud": clientID,
				"exp": expiresAt.Unix(),
				"iat": time.Now().Unix(),
				"nonce": uuid.New().String(), // Should match the nonce from the original request
			}

			// Add claims based on scopes
			for _, s := range scopes {
				switch s {
				case "profile":
					idToken["name"] = user.FirstName + " " + user.LastName
					idToken["given_name"] = user.FirstName
					idToken["family_name"] = user.LastName
					idToken["preferred_username"] = user.Username
				case "email":
					idToken["email"] = user.Email
					idToken["email_verified"] = true
				}
			}
			break
		}
	}

	return accessToken, idToken, nil
}

// ValidateRedirectURI checks if a redirect URI is valid for a client
func (p *Provider) ValidateRedirectURI(clientID, redirectURI string) error {
	client, err := p.ClientRepo.GetClientByID(clientID)
	if err != nil {
		return fmt.Errorf("client not found")
	}

	redirectURIs, err := client.GetRedirectURIs()
	if err != nil {
		return fmt.Errorf("failed to parse redirect URIs")
	}

	for _, uri := range redirectURIs {
		if uri == redirectURI {
			return nil
		}
	}

	return fmt.Errorf("invalid redirect URI")
}

// GenerateRandomString generates a random string for various purposes
func GenerateRandomString(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(b)[:length]
}

// CreateIDTokenJWT creates a simple JWT-like ID token (for demo purposes)
// In production, you should use a proper JWT library with proper signing
func CreateIDTokenJWT(claims map[string]interface{}) (string, error) {
	header := map[string]interface{}{
		"alg": "none",
		"typ": "JWT",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	claimsB64 := base64.RawURLEncoding.EncodeToString(claimsJSON)

	// For demo purposes, we're not signing the token (alg: none)
	return headerB64 + "." + claimsB64 + ".", nil
}
