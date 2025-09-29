package services

import (
	"fmt"
	"regexp"
	"strings"

	"mcpauth/server/database"
)

// UserService handles user management operations
type UserService struct {
	userRepo *database.UserRepository
}

// NewUserService creates a new user service
func NewUserService(userRepo *database.UserRepository) *UserService {
	return &UserService{
		userRepo: userRepo,
	}
}

// CreateUser creates a new user with validation
func (s *UserService) CreateUser(username, email, password, firstName, lastName string) (*database.User, error) {
	// Validate input
	if err := s.validateUserInput(username, email, password, firstName, lastName); err != nil {
		return nil, err
	}

	// Check if username already exists
	if _, err := s.userRepo.GetUserByUsername(username); err == nil {
		return nil, fmt.Errorf("username already exists")
	}

	// Check if email already exists
	if _, err := s.userRepo.GetUserByEmail(email); err == nil {
		return nil, fmt.Errorf("email already exists")
	}

	// Create user
	return s.userRepo.CreateUser(username, email, password, firstName, lastName)
}

// GetUser retrieves a user by ID
func (s *UserService) GetUser(id int) (*database.User, error) {
	return s.userRepo.GetUserByID(id)
}

// DeleteUser deletes a user by ID
func (s *UserService) DeleteUser(id int) error {
	return s.userRepo.DeleteUser(id)
}

// GetUserByUsername retrieves a user by username
func (s *UserService) GetUserByUsername(username string) (*database.User, error) {
	return s.userRepo.GetUserByUsername(username)
}

// GetUserByEmail retrieves a user by email
func (s *UserService) GetUserByEmail(email string) (*database.User, error) {
	return s.userRepo.GetUserByEmail(email)
}

// ListUsers retrieves all users
func (s *UserService) ListUsers() ([]*database.User, error) {
	return s.userRepo.ListUsers()
}

// AuthenticateUser authenticates a user with username/email and password
func (s *UserService) AuthenticateUser(usernameOrEmail, password string) (*database.User, error) {
	// Try username first
	user, err := s.userRepo.GetUserByUsername(usernameOrEmail)
	if err != nil {
		// Try email
		user, err = s.userRepo.GetUserByEmail(usernameOrEmail)
		if err != nil {
			return nil, fmt.Errorf("user not found")
		}
	}

	if !s.userRepo.ValidatePassword(user, password) {
		return nil, fmt.Errorf("invalid password")
	}

	return user, nil
}

// validateUserInput validates user input fields
func (s *UserService) validateUserInput(username, email, password, firstName, lastName string) error {
	// Username validation
	if len(username) < 3 || len(username) > 50 {
		return fmt.Errorf("username must be between 3 and 50 characters")
	}
	if !regexp.MustCompile(`^[a-zA-Z0-9_-]+$`).MatchString(username) {
		return fmt.Errorf("username can only contain letters, numbers, underscores, and hyphens")
	}

	// Email validation
	if !isValidEmail(email) {
		return fmt.Errorf("invalid email format")
	}

	// Password validation
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}

	// Name validation
	if len(strings.TrimSpace(firstName)) == 0 {
		return fmt.Errorf("first name is required")
	}
	if len(strings.TrimSpace(lastName)) == 0 {
		return fmt.Errorf("last name is required")
	}

	return nil
}

// isValidEmail validates email format
func isValidEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

// ClientService handles OAuth client management operations
type ClientService struct {
	clientRepo *database.ClientRepository
	scopeRepo  *database.ScopeRepository
}

// NewClientService creates a new client service
func NewClientService(clientRepo *database.ClientRepository, scopeRepo *database.ScopeRepository) *ClientService {
	return &ClientService{
		clientRepo: clientRepo,
		scopeRepo:  scopeRepo,
	}
}

// CreateClient creates a new OAuth client with validation
func (s *ClientService) CreateClient(clientName string, redirectURIs []string, scopes []string) (*database.OAuthClient, error) {
	// Validate input
	if err := s.validateClientInput(clientName, redirectURIs, scopes); err != nil {
		return nil, err
	}

	// Create client
	return s.clientRepo.CreateClient(clientName, redirectURIs, scopes)
}

// GetClient retrieves a client by client ID
func (s *ClientService) GetClient(clientID string) (*database.OAuthClient, error) {
	return s.clientRepo.GetClientByID(clientID)
}

// DeleteClient deletes a client by ID
func (s *ClientService) DeleteClient(clientID string) error {
	return s.clientRepo.DeleteClient(clientID)
}

// ListClients retrieves all clients
func (s *ClientService) ListClients() ([]*database.OAuthClient, error) {
	return s.clientRepo.ListClients()
}

// ValidateClientCredentials validates client credentials
func (s *ClientService) ValidateClientCredentials(clientID, clientSecret string) (*database.OAuthClient, error) {
	return s.clientRepo.ValidateClientCredentials(clientID, clientSecret)
}

// GetAvailableScopes retrieves all available scopes
func (s *ClientService) GetAvailableScopes() ([]*database.Scope, error) {
	return s.scopeRepo.ListScopes()
}

// validateClientInput validates client input fields
func (s *ClientService) validateClientInput(clientName string, redirectURIs []string, scopes []string) error {
	// Client name validation
	if len(strings.TrimSpace(clientName)) == 0 {
		return fmt.Errorf("client name is required")
	}
	if len(clientName) > 100 {
		return fmt.Errorf("client name must be less than 100 characters")
	}

	// Redirect URIs validation
	if len(redirectURIs) == 0 {
		return fmt.Errorf("at least one redirect URI is required")
	}
	for _, uri := range redirectURIs {
		if !isValidURL(uri) {
			return fmt.Errorf("invalid redirect URI: %s", uri)
		}
	}

	// Scopes validation
	if len(scopes) == 0 {
		return fmt.Errorf("at least one scope is required")
	}

	// Validate that all requested scopes exist
	availableScopes, err := s.scopeRepo.ListScopes()
	if err != nil {
		return fmt.Errorf("failed to validate scopes: %w", err)
	}

	availableScopeNames := make(map[string]bool)
	for _, scope := range availableScopes {
		availableScopeNames[scope.Name] = true
	}

	for _, scope := range scopes {
		if !availableScopeNames[scope] {
			return fmt.Errorf("invalid scope: %s", scope)
		}
	}

	return nil
}

// isValidURL validates URL format
func isValidURL(urlStr string) bool {
	// Basic URL validation - in production you might want more sophisticated validation
	return strings.HasPrefix(urlStr, "http://") || strings.HasPrefix(urlStr, "https://")
}
