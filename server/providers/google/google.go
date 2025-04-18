package google

import (
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "strings"
    "time"
)

// Provider implements the Google OAuth provider
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
    return &Provider{
        ClientID:     clientID,
        ClientSecret: clientSecret,
        RedirectURI:  redirectURI,
        Scopes:       scopes,
    }
}

// GetAuthURL returns the Google authorization URL
func (p *Provider) GetAuthURL(state string, codeVerifier string, nonce string) string {
    authURL, _ := url.Parse("https://accounts.google.com/o/oauth2/v2/auth")
    
    q := authURL.Query()
    q.Set("client_id", p.ClientID)
    q.Set("redirect_uri", p.RedirectURI)
    q.Set("response_type", "code")
    q.Set("scope", strings.Join(p.Scopes, " "))
    q.Set("state", state)
    q.Set("nonce", nonce)
    q.Set("access_type", "offline")
    q.Set("prompt", "consent")
    
    // Add code challenge for PKCE if code verifier is provided
    if codeVerifier != "" {
        q.Set("code_challenge", codeVerifier)
        q.Set("code_challenge_method", "plain")
    }
    
    authURL.RawQuery = q.Encode()
    
    return authURL.String()
}

// ExchangeToken exchanges an authorization code for tokens
func (p *Provider) ExchangeToken(code string) (string, string, error) {
    tokenURL := "https://oauth2.googleapis.com/token"
    data := url.Values{}
    data.Set("code", code)
    data.Set("client_id", p.ClientID)
    data.Set("client_secret", p.ClientSecret)
    data.Set("redirect_uri", p.RedirectURI)
    data.Set("grant_type", "authorization_code")
    
    req, err := http.NewRequest("POST", tokenURL, strings.NewReader(data.Encode()))
    if err != nil {
        return "", "", err
    }
    
    req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
    
    client := &http.Client{Timeout: 10 * time.Second}
    resp, err := client.Do(req)
    if err != nil {
        return "", "", err
    }
    defer resp.Body.Close()
    
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return "", "", err
    }
    
    var tokenResponse struct {
        AccessToken  string `json:"access_token"`
        IDToken      string `json:"id_token"`
        RefreshToken string `json:"refresh_token"`
        ExpiresIn    int    `json:"expires_in"`
        TokenType    string `json:"token_type"`
    }
    
    if err := json.Unmarshal(body, &tokenResponse); err != nil {
        return "", "", err
    }
    
    return tokenResponse.AccessToken, tokenResponse.IDToken, nil
}

// GetUserInfo retrieves user information using the access token
func (p *Provider) GetUserInfo(accessToken string) (*UserInfo, error) {
    userInfoURL := "https://www.googleapis.com/oauth2/v2/userinfo"
    
    req, err := http.NewRequest("GET", userInfoURL, nil)
    if err != nil {
        return nil, err
    }
    
    req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", accessToken))
    
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
    
    var userInfo UserInfo
    if err := json.Unmarshal(body, &userInfo); err != nil {
        return nil, err
    }
    
    return &userInfo, nil
}
