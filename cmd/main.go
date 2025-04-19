package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"mcpauth/server"

	"github.com/rs/zerolog/log"
)

func main() {
	// Define command line flags
	port := flag.Int("port", 11000, "Port to run the server on")
	protectedPath := flag.String("protectedPath", "/sse", "Path to protect with authentication")
	oauthDomain := flag.String("oauthDomain", "localhost", "Domain for OAuth endpoints")
	devMode := flag.Bool("devMode", false, "Enable development mode")
	allowedEmails := flag.String("allowedEmails", "", "Comma-separated list of emails allowed to access protected resources (empty = allow all)")

	// OAuth provider configuration
	provider := flag.String("provider", "google", "OAuth provider to use (google, auth0, etc)")
	clientID := flag.String("clientID", "", "OAuth client ID")
	clientSecret := flag.String("clientSecret", "", "OAuth client secret")

	// For backward compatibility
	googleClientID := flag.String("googleClientID", "", "Google OAuth client ID (deprecated, use clientID)")
	googleClientSecret := flag.String("googleClientSecret", "", "Google OAuth client secret (deprecated, use clientSecret)")

	// Parse flags
	flag.Parse()

	// Check environment variables for configuration
	if envPort := os.Getenv("PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil {
			*port = p
		}
	}

	// Use PROTECTED_PATH instead of PATH to avoid system PATH variable conflict
	if envPath := os.Getenv("PROTECTED_PATH"); envPath != "" {
		*protectedPath = envPath
	}

	if envDomain := os.Getenv("OAUTH_DOMAIN"); envDomain != "" {
		*oauthDomain = envDomain
		log.Info().Str("domain_from_env", envDomain).Msg("Using domain from environment")
	}

	if envDevMode := os.Getenv("DEV_MODE"); envDevMode != "" {
		*devMode = strings.ToLower(envDevMode) == "true"
	}

	if envAllowedEmails := os.Getenv("ALLOWED_EMAILS"); envAllowedEmails != "" {
		*allowedEmails = envAllowedEmails
	}

	// Log the configuration
	log.Info().
		Int("port", *port).
		Str("protectedPath", *protectedPath).
		Str("oauthDomain", *oauthDomain).
		Bool("devMode", *devMode).
		Str("allowedEmails", *allowedEmails).
		Msg("Starting with configuration")

	// Create and configure the server
	s := server.NewServer(*protectedPath, *oauthDomain, *devMode)

	// Configure allowed emails if provided
	if *allowedEmails != "" {
		emailList := strings.Split(*allowedEmails, ",")
		// Trim spaces from each email
		for i, email := range emailList {
			emailList[i] = strings.TrimSpace(email)
		}
		s.SetAllowedEmails(emailList)
	}

	// Use provider-specific flags if available, otherwise use generic ones
	actualClientID := *clientID
	actualClientSecret := *clientSecret
	actualProvider := *provider

	// For backward compatibility with Google-specific flags
	if actualClientID == "" && *googleClientID != "" {
		actualClientID = *googleClientID
		actualProvider = "google"
	}
	if actualClientSecret == "" && *googleClientSecret != "" {
		actualClientSecret = *googleClientSecret
		actualProvider = "google"
	}

	// If still empty, try environment variables
	if actualClientID == "" {
		// Try provider-specific env var first
		if actualProvider == "google" {
			actualClientID = os.Getenv("GOOGLE_CLIENT_ID")
		}
		// Fall back to generic env var
		if actualClientID == "" {
			actualClientID = os.Getenv("CLIENT_ID")
		}
	}

	if actualClientSecret == "" {
		// Try provider-specific env var first
		if actualProvider == "google" {
			actualClientSecret = os.Getenv("GOOGLE_CLIENT_SECRET")
		}
		// Fall back to generic env var
		if actualClientSecret == "" {
			actualClientSecret = os.Getenv("CLIENT_SECRET")
		}
	}

	// Construct the redirect URI based on the base domain
	protocol := "https"
	if *devMode {
		protocol = "http"
	}
	redirectURI := fmt.Sprintf("%s://%s/callback", protocol, *oauthDomain)

	// Configure the OAuth provider
	if actualClientID != "" && actualClientSecret != "" {
		if err := s.ConfigureProvider(actualProvider, actualClientID, actualClientSecret, redirectURI, nil); err != nil {
			log.Warn().Err(err).Msg("Failed to configure OAuth provider")
		} else {
			log.Info().
				Str("provider", actualProvider).
				Str("redirectURI", redirectURI).
				Msg("Configured OAuth provider")
		}
	} else {
		log.Warn().Msg("OAuth credentials not provided. OAuth flows will not work.")
	}

	// Start the server
	address := fmt.Sprintf(":%d", *port)
	log.Info().Str("address", address).Str("path", *protectedPath).Msg("Starting server")

	err := http.ListenAndServe(address, s.Router)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to start server")
	}
}
