package database

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "github.com/mattn/go-sqlite3"
	"github.com/rs/zerolog/log"
)

// DB wraps the database connection
type DB struct {
	*sql.DB
}

// NewDB creates a new database connection
func NewDB(dataDir string) (*DB, error) {
	// Ensure data directory exists
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	dbPath := filepath.Join(dataDir, "mcpauth.db")
	log.Info().Str("path", dbPath).Msg("Opening database")

	sqlDB, err := sql.Open("sqlite3", dbPath+"?_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	db := &DB{sqlDB}

	// Test connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Run migrations
	if err := db.migrate(); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	log.Info().Msg("Database initialized successfully")
	return db, nil
}

// migrate runs database migrations
func (db *DB) migrate() error {
	log.Info().Msg("Running database migrations")

	migrations := []string{
		createUsersTable,
		createOAuthClientsTable,
		createScopesTable,
		createRSLLicensesTable,
		createAuthorizationCodesTable,
		createAccessTokensTable,
		insertDefaultScopes,
	}

	for i, migration := range migrations {
		log.Debug().Int("migration", i+1).Msg("Running migration")
		if _, err := db.Exec(migration); err != nil {
			return fmt.Errorf("migration %d failed: %w", i+1, err)
		}
	}

	log.Info().Msg("Database migrations completed")
	return nil
}

const createUsersTable = `
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    first_name TEXT NOT NULL DEFAULT '',
    last_name TEXT NOT NULL DEFAULT '',
    active BOOLEAN NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_users_active ON users(active);
`

const createOAuthClientsTable = `
CREATE TABLE IF NOT EXISTS oauth_clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id TEXT UNIQUE NOT NULL,
    client_secret TEXT NOT NULL,
    client_name TEXT NOT NULL,
    redirect_uris TEXT NOT NULL, -- JSON array
    scopes TEXT NOT NULL DEFAULT '[]', -- JSON array
    active BOOLEAN NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_oauth_clients_client_id ON oauth_clients(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_clients_active ON oauth_clients(active);
`

const createScopesTable = `
CREATE TABLE IF NOT EXISTS scopes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    description TEXT NOT NULL,
    active BOOLEAN NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scopes_name ON scopes(name);
CREATE INDEX IF NOT EXISTS idx_scopes_active ON scopes(active);
`

const createRSLLicensesTable = `
CREATE TABLE IF NOT EXISTS rsl_licenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    license_id TEXT UNIQUE NOT NULL,
    client_id TEXT NOT NULL,
    resource TEXT NOT NULL,
    license_xml TEXT NOT NULL,
    access_token TEXT UNIQUE NOT NULL,
    encryption_key TEXT, -- JWK for encrypted assets
    expires_at DATETIME, -- NULL for non-expiring licenses
    active BOOLEAN NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id)
);

CREATE INDEX IF NOT EXISTS idx_rsl_licenses_license_id ON rsl_licenses(license_id);
CREATE INDEX IF NOT EXISTS idx_rsl_licenses_access_token ON rsl_licenses(access_token);
CREATE INDEX IF NOT EXISTS idx_rsl_licenses_client_id ON rsl_licenses(client_id);
CREATE INDEX IF NOT EXISTS idx_rsl_licenses_resource ON rsl_licenses(resource);
CREATE INDEX IF NOT EXISTS idx_rsl_licenses_active ON rsl_licenses(active);
`

const createAuthorizationCodesTable = `
CREATE TABLE IF NOT EXISTS authorization_codes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT UNIQUE NOT NULL,
    client_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    redirect_uri TEXT NOT NULL,
    scopes TEXT NOT NULL DEFAULT '[]', -- JSON array
    expires_at DATETIME NOT NULL,
    used BOOLEAN NOT NULL DEFAULT 0,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_authorization_codes_code ON authorization_codes(code);
CREATE INDEX IF NOT EXISTS idx_authorization_codes_expires_at ON authorization_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_authorization_codes_used ON authorization_codes(used);
`

const createAccessTokensTable = `
CREATE TABLE IF NOT EXISTS access_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    client_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    scopes TEXT NOT NULL DEFAULT '[]', -- JSON array
    expires_at DATETIME NOT NULL,
    active BOOLEAN NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (client_id) REFERENCES oauth_clients(client_id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_access_tokens_token ON access_tokens(token);
CREATE INDEX IF NOT EXISTS idx_access_tokens_expires_at ON access_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_access_tokens_active ON access_tokens(active);
`

const insertDefaultScopes = `
INSERT OR IGNORE INTO scopes (name, description) VALUES
    ('openid', 'OpenID Connect authentication'),
    ('profile', 'Access to user profile information'),
    ('email', 'Access to user email address'),
    ('read', 'Read access to resources'),
    ('write', 'Write access to resources'),
    ('admin', 'Administrative access');
`
