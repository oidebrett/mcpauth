package providers

import (
    "encoding/json"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "strings"
    "time"
)

// Provider defines the interface that all OAuth providers must implement
type Provider interface {
    GetAuthURL(state string, nonce string) string
    ExchangeToken(code string) (string, string, error)
    GetUserInfo(accessToken string) (map[string]interface{}, error)
}

// BaseProvider contains common functionality for OAuth providers
type BaseProvider struct {
    ClientID     string
    ClientSecret string
    RedirectURI  string
    Scopes       []string
}