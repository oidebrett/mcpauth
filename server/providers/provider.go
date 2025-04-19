package providers

// Provider defines the interface that all OAuth providers must implement
type Provider interface {
	GetAuthURL(state string, codeVerifier string, nonce string) string
	ExchangeToken(code string, codeVerifier string) (string, string, error)
	GetUserInfo(accessToken string) (map[string]interface{}, error)
}

// BaseProvider contains common functionality for OAuth providers
type BaseProvider struct {
	ClientID     string
	ClientSecret string
	RedirectURI  string
	Scopes       []string
}
