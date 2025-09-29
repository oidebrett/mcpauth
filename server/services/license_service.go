package services

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"mcpauth/server/database"
)

// LicenseService handles RSL license management operations
type LicenseService struct {
	licenseRepo *database.RSLLicenseRepository
	clientRepo  *database.ClientRepository
}

// NewLicenseService creates a new license service
func NewLicenseService(licenseRepo *database.RSLLicenseRepository, clientRepo *database.ClientRepository) *LicenseService {
	return &LicenseService{
		licenseRepo: licenseRepo,
		clientRepo:  clientRepo,
	}
}

// CreateLicense creates a new RSL license
func (s *LicenseService) CreateLicense(clientID, resource, licenseXML string, expiresAt *time.Time) (*database.RSLLicense, error) {
	// Validate client exists
	_, err := s.clientRepo.GetClientByID(clientID)
	if err != nil {
		return nil, fmt.Errorf("invalid client: %w", err)
	}

	// Validate license XML (basic validation)
	if err := s.validateLicenseXML(licenseXML); err != nil {
		return nil, fmt.Errorf("invalid license: %w", err)
	}

	// Validate resource URL
	if !isValidURLString(resource) {
		return nil, fmt.Errorf("invalid resource URL")
	}

	// Create license
	return s.licenseRepo.CreateLicense(clientID, resource, licenseXML, expiresAt)
}

// GetLicenseByToken retrieves a license by access token
func (s *LicenseService) GetLicenseByToken(token string) (*database.RSLLicense, error) {
	return s.licenseRepo.GetLicenseByToken(token)
}

// ValidateLicenseAccess checks if a license permits access to a resource
func (s *LicenseService) ValidateLicenseAccess(token, resource string) (*database.RSLLicense, bool, string, error) {
	license, err := s.licenseRepo.GetLicenseByToken(token)
	if err != nil {
		return nil, false, "License not found or expired", err
	}

	// Check if the license covers the requested resource
	permitted, reason := s.checkResourcePermission(license, resource)
	
	return license, permitted, reason, nil
}

// GenerateEncryptionKey generates and stores an encryption key for a license
func (s *LicenseService) GenerateEncryptionKey(licenseID string) (map[string]interface{}, error) {
	// Generate a 128-bit AES key
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}

	// Create JWK
	jwk := map[string]interface{}{
		"kty": "oct",                                           // Key type: octet sequence (symmetric)
		"kid": uuid.New().String(),                            // Key ID
		"k":   base64.RawURLEncoding.EncodeToString(keyBytes), // Base64url-encoded key
		"alg": "A128CTR",                                      // Algorithm: AES-128 in CTR mode
	}

	// Store the JWK as JSON
	jwkJSON, err := json.Marshal(jwk)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JWK: %w", err)
	}

	// Store in database
	if err := s.licenseRepo.SetEncryptionKey(licenseID, string(jwkJSON)); err != nil {
		return nil, fmt.Errorf("failed to store encryption key: %w", err)
	}

	return jwk, nil
}

// GetEncryptionKey retrieves the encryption key for a license
func (s *LicenseService) GetEncryptionKey(token, resource string) (map[string]interface{}, error) {
	license, permitted, reason, err := s.ValidateLicenseAccess(token, resource)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	if !permitted {
		return nil, fmt.Errorf("access denied: %s", reason)
	}

	if license.EncryptionKey == nil || *license.EncryptionKey == "" {
		// Generate key if it doesn't exist
		return s.GenerateEncryptionKey(license.LicenseID)
	}

	// Parse existing key
	var jwk map[string]interface{}
	if err := json.Unmarshal([]byte(*license.EncryptionKey), &jwk); err != nil {
		return nil, fmt.Errorf("failed to parse encryption key: %w", err)
	}

	return jwk, nil
}


// ListLicensesByClient retrieves all licenses for a client
func (s *LicenseService) ListLicensesByClient(clientID string) ([]*database.RSLLicense, error) {
	return s.licenseRepo.ListLicensesByClient(clientID)
}

// validateLicenseXML performs basic validation of RSL license XML
func (s *LicenseService) validateLicenseXML(licenseXML string) error {
	// Basic validation - check if it contains license tags
	if !strings.Contains(licenseXML, "<license") || !strings.Contains(licenseXML, "</license>") {
		return fmt.Errorf("invalid license XML format")
	}

	// In a production system, you would want to:
	// 1. Parse the XML to ensure it's well-formed
	// 2. Validate against RSL schema
	// 3. Check license terms and conditions
	// 4. Verify digital signatures if present

	return nil
}

// checkResourcePermission checks if a license permits access to a specific resource
func (s *LicenseService) checkResourcePermission(license *database.RSLLicense, resource string) (bool, string) {
	// Simple implementation: check if the resource matches exactly or is a sub-path
	if license.Resource == resource {
		return true, ""
	}

	// Check if the requested resource is under the licensed resource path
	if strings.HasPrefix(resource, license.Resource) {
		return true, ""
	}

	// In a production system, you would want to:
	// 1. Parse the license XML to extract permitted resources
	// 2. Check resource patterns and wildcards
	// 3. Validate usage constraints (time, geography, etc.)
	// 4. Check license terms and conditions

	return false, "License does not cover this resource"
}

// ParseLicenseXML extracts information from RSL license XML (simplified)
func (s *LicenseService) ParseLicenseXML(licenseXML string) (map[string]interface{}, error) {
	// This is a simplified parser for demo purposes
	// In production, you would use a proper XML parser and RSL schema
	
	info := map[string]interface{}{
		"format": "RSL",
		"raw":    licenseXML,
	}

	// Extract basic information (very simplified)
	if strings.Contains(licenseXML, "commercial") {
		info["type"] = "commercial"
	} else if strings.Contains(licenseXML, "non-commercial") {
		info["type"] = "non-commercial"
	} else {
		info["type"] = "unknown"
	}

	return info, nil
}

// isValidURLString validates if a string is a valid URL
func isValidURLString(urlStr string) bool {
	if urlStr == "" {
		return false
	}

	// Parse the URL
	u, err := url.Parse(urlStr)
	if err != nil {
		return false
	}

	// Check if scheme and host are present
	return u.Scheme != "" && u.Host != ""
}
