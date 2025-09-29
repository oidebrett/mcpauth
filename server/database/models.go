package database

import (
	"time"
)

// User represents a user in the system
type User struct {
	ID           int       `json:"id" db:"id"`
	Username     string    `json:"username" db:"username"`
	Email        string    `json:"email" db:"email"`
	PasswordHash string    `json:"-" db:"password_hash"` // Never expose password hash in JSON
	FirstName    string    `json:"first_name" db:"first_name"`
	LastName     string    `json:"last_name" db:"last_name"`
	Active       bool      `json:"active" db:"active"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}

// OAuthClient represents an OAuth client application
type OAuthClient struct {
	ID           int       `json:"id" db:"id"`
	ClientID     string    `json:"client_id" db:"client_id"`
	ClientSecret string    `json:"client_secret,omitempty" db:"client_secret"` // Only show when creating
	ClientName   string    `json:"client_name" db:"client_name"`
	RedirectURIs string    `json:"redirect_uris" db:"redirect_uris"` // JSON array as string
	Scopes       string    `json:"scopes" db:"scopes"`               // JSON array as string
	Active       bool      `json:"active" db:"active"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}

// Scope represents an OAuth scope
type Scope struct {
	ID          int       `json:"id" db:"id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description" db:"description"`
	Active      bool      `json:"active" db:"active"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// RSLLicense represents an RSL license for the Open Licensing Protocol
type RSLLicense struct {
	ID          int       `json:"id" db:"id"`
	LicenseID   string    `json:"license_id" db:"license_id"`     // Unique identifier for the license
	ClientID    string    `json:"client_id" db:"client_id"`       // OAuth client that owns this license
	Resource    string    `json:"resource" db:"resource"`         // URL of the digital asset
	LicenseXML  string    `json:"license_xml" db:"license_xml"`   // Complete RSL <license> XML element
	AccessToken string    `json:"access_token" db:"access_token"` // RSL license token
	EncryptionKey *string `json:"encryption_key,omitempty" db:"encryption_key"` // JWK for encrypted assets
	ExpiresAt   *time.Time `json:"expires_at" db:"expires_at"`    // License expiration (nullable)
	Active      bool      `json:"active" db:"active"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// AuthorizationCode represents a temporary authorization code
type AuthorizationCode struct {
	ID          int       `json:"id" db:"id"`
	Code        string    `json:"code" db:"code"`
	ClientID    string    `json:"client_id" db:"client_id"`
	UserID      int       `json:"user_id" db:"user_id"`
	RedirectURI string    `json:"redirect_uri" db:"redirect_uri"`
	Scopes      string    `json:"scopes" db:"scopes"` // JSON array as string
	ExpiresAt   time.Time `json:"expires_at" db:"expires_at"`
	Used        bool      `json:"used" db:"used"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
}

// AccessToken represents an issued access token
type AccessToken struct {
	ID        int       `json:"id" db:"id"`
	Token     string    `json:"token" db:"token"`
	ClientID  string    `json:"client_id" db:"client_id"`
	UserID    int       `json:"user_id" db:"user_id"`
	Scopes    string    `json:"scopes" db:"scopes"` // JSON array as string
	ExpiresAt time.Time `json:"expires_at" db:"expires_at"`
	Active    bool      `json:"active" db:"active"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}
