
package database

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"
	"github.com/google/uuid"
	"github.com/golang-jwt/jwt/v5"
)

var jwtSecret = []byte("my-secret-key") // ⚠️ move to config/env

// UserRepository handles user database operations
type UserRepository struct {
	db *DB
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *DB) *UserRepository {
	return &UserRepository{db: db}
}

// CreateUser creates a new user with hashed password
func (r *UserRepository) CreateUser(username, email, password, firstName, lastName string) (*User, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	query := `
		INSERT INTO users (username, email, password_hash, first_name, last_name)
		VALUES (?, ?, ?, ?, ?)
	`
	result, err := r.db.Exec(query, username, email, string(hashedPassword), firstName, lastName)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("failed to get user ID: %w", err)
	}

	return r.GetUserByID(int(id))
}

// GetUserByID retrieves a user by ID
func (r *UserRepository) GetUserByID(id int) (*User, error) {
	user := &User{}
	query := `
		SELECT id, username, email, password_hash, first_name, last_name, active, created_at, updated_at
		FROM users WHERE id = ?
	`
	err := r.db.QueryRow(query, id).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash,
		&user.FirstName, &user.LastName, &user.Active, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// GetUserByUsername retrieves a user by username
func (r *UserRepository) GetUserByUsername(username string) (*User, error) {
	user := &User{}
	query := `
		SELECT id, username, email, password_hash, first_name, last_name, active, created_at, updated_at
		FROM users WHERE username = ? AND active = 1
	`
	err := r.db.QueryRow(query, username).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash,
		&user.FirstName, &user.LastName, &user.Active, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// GetUserByEmail retrieves a user by email
func (r *UserRepository) GetUserByEmail(email string) (*User, error) {
	user := &User{}
	query := `
		SELECT id, username, email, password_hash, first_name, last_name, active, created_at, updated_at
		FROM users WHERE email = ? AND active = 1
	`
	err := r.db.QueryRow(query, email).Scan(
		&user.ID, &user.Username, &user.Email, &user.PasswordHash,
		&user.FirstName, &user.LastName, &user.Active, &user.CreatedAt, &user.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// ValidatePassword checks if the provided password matches the user's hashed password
func (r *UserRepository) ValidatePassword(user *User, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
	return err == nil
}

// ListUsers retrieves all active users
func (r *UserRepository) ListUsers() ([]*User, error) {
	query := `
		SELECT id, username, email, password_hash, first_name, last_name, active, created_at, updated_at
		FROM users WHERE active = 1 ORDER BY username
	`
	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []*User
	for rows.Next() {
		user := &User{}
		err := rows.Scan(
			&user.ID, &user.Username, &user.Email, &user.PasswordHash,
			&user.FirstName, &user.LastName, &user.Active, &user.CreatedAt, &user.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

// DeleteUser deletes a user by ID
func (r *UserRepository) DeleteUser(id int) error {
	query := `DELETE FROM users WHERE id = ?`
	_, err := r.db.Exec(query, id)
	return err
}

// ClientRepository handles OAuth client database operations
type ClientRepository struct {
	db *DB
}

// NewClientRepository creates a new client repository
func NewClientRepository(db *DB) *ClientRepository {
	return &ClientRepository{db: db}
}

// CreateClient creates a new OAuth client
func (r *ClientRepository) CreateClient(clientName string, redirectURIs []string, scopes []string) (*OAuthClient, error) {
	clientID := "client_" + uuid.New().String()
	clientSecret := uuid.New().String()

	redirectURIsJSON, err := json.Marshal(redirectURIs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal redirect URIs: %w", err)
	}

	scopesJSON, err := json.Marshal(scopes)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal scopes: %w", err)
	}

	query := `
		INSERT INTO oauth_clients (client_id, client_secret, client_name, redirect_uris, scopes)
		VALUES (?, ?, ?, ?, ?)
	`
	_, err = r.db.Exec(query, clientID, clientSecret, clientName, string(redirectURIsJSON), string(scopesJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	return r.GetClientByID(clientID)
}

// CreateClientWithID creates a new OAuth client with a specific client ID.
func (r *ClientRepository) CreateClientWithID(clientID, clientName string, redirectURIs []string, scopes []string) (*OAuthClient, error) {
	clientSecret := uuid.New().String()

	redirectURIsJSON, err := json.Marshal(redirectURIs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal redirect URIs: %w", err)
	}

	scopesJSON, err := json.Marshal(scopes)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal scopes: %w", err)
	}

	query := `
		INSERT INTO oauth_clients (client_id, client_secret, client_name, redirect_uris, scopes)
		VALUES (?, ?, ?, ?, ?)
	`
	_, err = r.db.Exec(query, clientID, clientSecret, clientName, string(redirectURIsJSON), string(scopesJSON))
	if err != nil {
		return nil, fmt.Errorf("failed to create client: %w", err)
	}

	return r.GetClientByID(clientID)
}

// GetClientByID retrieves a client by client ID
func (r *ClientRepository) GetClientByID(clientID string) (*OAuthClient, error) {
	client := &OAuthClient{}
	query := `
		SELECT id, client_id, client_secret, client_name, redirect_uris, scopes, active, created_at, updated_at
		FROM oauth_clients WHERE client_id = ?
	`
	err := r.db.QueryRow(query, clientID).Scan(
		&client.ID, &client.ClientID, &client.ClientSecret, &client.ClientName,
		&client.RedirectURIs, &client.Scopes, &client.Active, &client.CreatedAt, &client.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return client, nil
}

// ListClients retrieves all active clients
func (r *ClientRepository) ListClients() ([]*OAuthClient, error) {
	query := `
		SELECT id, client_id, client_secret, client_name, redirect_uris, scopes, active, created_at, updated_at
		FROM oauth_clients WHERE active = 1 ORDER BY client_name
	`
	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var clients []*OAuthClient
	for rows.Next() {
		client := &OAuthClient{}
		err := rows.Scan(
			&client.ID, &client.ClientID, &client.ClientSecret, &client.ClientName,
			&client.RedirectURIs, &client.Scopes, &client.Active, &client.CreatedAt, &client.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		// Include client secret for admin interface
		clients = append(clients, client)
	}
	return clients, nil
}

// ValidateClientCredentials checks if client ID and secret are valid
func (r *ClientRepository) ValidateClientCredentials(clientID, clientSecret string) (*OAuthClient, error) {
	client := &OAuthClient{}
	query := `
		SELECT id, client_id, client_secret, client_name, redirect_uris, scopes, active, created_at, updated_at
		FROM oauth_clients WHERE client_id = ? AND client_secret = ? AND active = 1
	`
	err := r.db.QueryRow(query, clientID, clientSecret).Scan(
		&client.ID, &client.ClientID, &client.ClientSecret, &client.ClientName,
		&client.RedirectURIs, &client.Scopes, &client.Active, &client.CreatedAt, &client.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return client, nil
}

// GetRedirectURIs parses and returns the redirect URIs for a client
func (c *OAuthClient) GetRedirectURIs() ([]string, error) {
	var uris []string
	err := json.Unmarshal([]byte(c.RedirectURIs), &uris)
	return uris, err
}

// GetScopes parses and returns the scopes for a client
func (c *OAuthClient) GetScopes() ([]string, error) {
	var scopes []string
	err := json.Unmarshal([]byte(c.Scopes), &scopes)
	return scopes, err
}

// DeleteClient deletes a client by client ID
func (r *ClientRepository) DeleteClient(clientID string) error {
	query := `DELETE FROM oauth_clients WHERE client_id = ?`
	_, err := r.db.Exec(query, clientID)
	return err
}

// ScopeRepository handles scope database operations
type ScopeRepository struct {
	db *DB
}

// NewScopeRepository creates a new scope repository
func NewScopeRepository(db *DB) *ScopeRepository {
	return &ScopeRepository{db: db}
}

// ListScopes retrieves all active scopes
func (r *ScopeRepository) ListScopes() ([]*Scope, error) {
	query := `
		SELECT id, name, description, active, created_at, updated_at
		FROM scopes WHERE active = 1 ORDER BY name
	`
	rows, err := r.db.Query(query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scopes []*Scope
	for rows.Next() {
		scope := &Scope{}
		err := rows.Scan(
			&scope.ID, &scope.Name, &scope.Description, &scope.Active, &scope.CreatedAt, &scope.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		scopes = append(scopes, scope)
	}
	return scopes, nil
}

// RSLLicenseRepository handles RSL license database operations
type RSLLicenseRepository struct {
	db *DB
}

// NewRSLLicenseRepository creates a new RSL license repository
func NewRSLLicenseRepository(db *DB) *RSLLicenseRepository {
	return &RSLLicenseRepository{db: db}
}

// CreateLicense creates a new RSL license
func (r *RSLLicenseRepository) CreateLicense(clientID, resource, licenseXML string, expiresAt *time.Time) (*RSLLicense, error) {
	licenseID := "rsl_" + uuid.New().String()
	accessToken := "rsl_" + uuid.New().String()

	query := `
		INSERT INTO rsl_licenses (license_id, client_id, resource, license_xml, access_token, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`
	_, err := r.db.Exec(query, licenseID, clientID, resource, licenseXML, accessToken, expiresAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create license: %w", err)
	}

	return r.GetLicenseByToken(accessToken)
}

// GetLicenseByToken retrieves a license by access token
func (r *RSLLicenseRepository) GetLicenseByToken(token string) (*RSLLicense, error) {
	license := &RSLLicense{}
	query := `
		SELECT id, license_id, client_id, resource, license_xml, access_token, encryption_key, expires_at, active, created_at, updated_at
		FROM rsl_licenses WHERE access_token = ? AND active = 1
	`
	err := r.db.QueryRow(query, token).Scan(
		&license.ID, &license.LicenseID, &license.ClientID, &license.Resource,
		&license.LicenseXML, &license.AccessToken, &license.EncryptionKey,
		&license.ExpiresAt, &license.Active, &license.CreatedAt, &license.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}

	// Check if license is expired
	if license.ExpiresAt != nil && time.Now().After(*license.ExpiresAt) {
		return nil, sql.ErrNoRows // Treat expired licenses as not found
	}

	return license, nil
}

// GetLicenseByID retrieves a license by license ID
func (r *RSLLicenseRepository) GetLicenseByID(licenseID string) (*RSLLicense, error) {
	license := &RSLLicense{}
	query := `
		SELECT id, license_id, client_id, resource, license_xml, access_token, encryption_key, expires_at, active, created_at, updated_at
		FROM rsl_licenses WHERE license_id = ? AND active = 1
	`
	err := r.db.QueryRow(query, licenseID).Scan(
		&license.ID, &license.LicenseID, &license.ClientID, &license.Resource,
		&license.LicenseXML, &license.AccessToken, &license.EncryptionKey,
		&license.ExpiresAt, &license.Active, &license.CreatedAt, &license.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return license, nil
}

// ListLicensesByClient retrieves all licenses for a client
func (r *RSLLicenseRepository) ListLicensesByClient(clientID string) ([]*RSLLicense, error) {
	query := `
		SELECT id, license_id, client_id, resource, license_xml, access_token, encryption_key, expires_at, active, created_at, updated_at
		FROM rsl_licenses WHERE client_id = ? AND active = 1 ORDER BY created_at DESC
	`
	rows, err := r.db.Query(query, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var licenses []*RSLLicense
	for rows.Next() {
		license := &RSLLicense{}
		err := rows.Scan(
			&license.ID, &license.LicenseID, &license.ClientID, &license.Resource,
			&license.LicenseXML, &license.AccessToken, &license.EncryptionKey,
			&license.ExpiresAt, &license.Active, &license.CreatedAt, &license.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		licenses = append(licenses, license)
	}
	return licenses, nil
}

// SetEncryptionKey sets the encryption key for a license
func (r *RSLLicenseRepository) SetEncryptionKey(licenseID, encryptionKey string) error {
	query := `UPDATE rsl_licenses SET encryption_key = ?, updated_at = CURRENT_TIMESTAMP WHERE license_id = ?`
	_, err := r.db.Exec(query, encryptionKey, licenseID)
	return err
}

// AuthCodeRepository handles authorization code database operations
type AuthCodeRepository struct {
	db *DB
}

// NewAuthCodeRepository creates a new authorization code repository
func NewAuthCodeRepository(db *DB) *AuthCodeRepository {
	return &AuthCodeRepository{db: db}
}

// CreateAuthCode creates a new authorization code
func (r *AuthCodeRepository) CreateAuthCode(clientID string, userID int, redirectURI string, scopes []string, expiresAt time.Time) (*AuthorizationCode, error) {
	code := uuid.New().String()

	scopesJSON, err := json.Marshal(scopes)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal scopes: %w", err)
	}

	query := `
		INSERT INTO authorization_codes (code, client_id, user_id, redirect_uri, scopes, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`
	_, err = r.db.Exec(query, code, clientID, userID, redirectURI, string(scopesJSON), expiresAt)
	if err != nil {
		return nil, fmt.Errorf("failed to create authorization code: %w", err)
	}

	return r.GetAuthCode(code)
}

// GetAuthCode retrieves an authorization code
func (r *AuthCodeRepository) GetAuthCode(code string) (*AuthorizationCode, error) {
	authCode := &AuthorizationCode{}
	query := `
		SELECT id, code, client_id, user_id, redirect_uri, scopes, expires_at, used, created_at
		FROM authorization_codes WHERE code = ?
	`
	err := r.db.QueryRow(query, code).Scan(
		&authCode.ID, &authCode.Code, &authCode.ClientID, &authCode.UserID,
		&authCode.RedirectURI, &authCode.Scopes, &authCode.ExpiresAt, &authCode.Used, &authCode.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	// Check if code is expired or used
	if time.Now().After(authCode.ExpiresAt) || authCode.Used {
		return nil, sql.ErrNoRows
	}

	return authCode, nil
}

// UseAuthCode marks an authorization code as used
func (r *AuthCodeRepository) UseAuthCode(code string) error {
	query := `UPDATE authorization_codes SET used = 1 WHERE code = ?`
	_, err := r.db.Exec(query, code)
	return err
}

// GetScopes parses and returns the scopes for an authorization code
func (ac *AuthorizationCode) GetScopes() ([]string, error) {
	var scopes []string
	err := json.Unmarshal([]byte(ac.Scopes), &scopes)
	return scopes, err
}

// TokenRepository handles access token database operations
type TokenRepository struct {
	db *DB
}

// NewTokenRepository creates a new token repository
func NewTokenRepository(db *DB) *TokenRepository {
	return &TokenRepository{db: db}
}

// CreateAccessToken creates a new access token
func (r *TokenRepository) CreateAccessToken(clientID string, userID int, scopes []string, expiresAt time.Time) (*AccessToken, error) {
	claims := jwt.MapClaims{
		"sub": userID,
		"aud": clientID,
		"scopes": scopes,
		"exp": expiresAt.Unix(),
		"iat": time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(jwtSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to sign JWT: %w", err)
	}

	// (Optional) still persist to DB for revocation
	query := `
		INSERT INTO access_tokens (token, client_id, user_id, scopes, expires_at)
		VALUES (?, ?, ?, ?, ?)
	`

	scopesJSON, err := json.Marshal(scopes)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal scopes: %w", err)
	}

	_, err = r.db.Exec(query, signedToken, clientID, userID, string(scopesJSON), expiresAt)

	if err != nil {
		return nil, fmt.Errorf("failed to store access token: %w", err)
	}

	// 🔹 Add logging here
	fmt.Printf("[DEBUG] Generated JWT: %s\n", signedToken)

	return r.GetAccessToken(signedToken)
}

// GetAccessToken retrieves an access token
func (r *TokenRepository) GetAccessToken(token string) (*AccessToken, error) {
	accessToken := &AccessToken{}
	query := `
		SELECT id, token, client_id, user_id, scopes, expires_at, active, created_at
		FROM access_tokens WHERE token = ? AND active = 1
	`
	err := r.db.QueryRow(query, token).Scan(
		&accessToken.ID, &accessToken.Token, &accessToken.ClientID, &accessToken.UserID,
		&accessToken.Scopes, &accessToken.ExpiresAt, &accessToken.Active, &accessToken.CreatedAt,
	)
	if err != nil {
		return nil, err
	}

	// Check if token is expired
	if time.Now().After(accessToken.ExpiresAt) {
		return nil, sql.ErrNoRows
	}

	return accessToken, nil
}

// RevokeAccessToken revokes an access token
func (r *TokenRepository) RevokeAccessToken(token string) error {
	query := `UPDATE access_tokens SET active = 0 WHERE token = ?`
	_, err := r.db.Exec(query, token)
	return err
}

// GetScopes parses and returns the scopes for an access token
func (at *AccessToken) GetScopes() ([]string, error) {
	var scopes []string
	err := json.Unmarshal([]byte(at.Scopes), &scopes)
	return scopes, err
}
