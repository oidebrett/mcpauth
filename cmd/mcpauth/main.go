package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"

	"mcpauth/server"

	"github.com/rs/zerolog/log"
)

func main() {
	// Define command line flags
	port := flag.Int("port", 11000, "Port to run the server on")
	path := flag.String("path", "/sse", "Path to protect with authentication")
	baseDomain := flag.String("baseDomain", "localhost", "Base domain for OAuth endpoints")
	devMode := flag.Bool("devMode", false, "Enable development mode")

	// OAuth provider configuration
	provider := flag.String("provider", "google", "OAuth provider to use (google, auth0, etc)")
	clientID := flag.String("clientID", "", "OAuth client ID")
	clientSecret := flag.String("clientSecret", "", "OAuth client secret")

	// For backward compatibility
	googleClientID := flag.String("googleClientID", "", "Google OAuth client ID (deprecated, use clientID)")
	googleClientSecret := flag.String("googleClientSecret", "", "Google OAuth client secret (deprecated, use clientSecret)")

	flag.Parse()

	// Create and configure the server
	s := server.NewServer(*path, *baseDomain, *devMode)

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
	redirectURI := fmt.Sprintf("%s://%s/callback", protocol, *baseDomain)

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
	log.Info().Str("address", address).Str("path", *path).Msg("Starting server")

	err := http.ListenAndServe(address, s.Router)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to start server")
	}
}
