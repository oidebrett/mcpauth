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

	// Google OAuth credentials
	googleClientID := flag.String("googleClientID", "", "Google OAuth client ID")
	googleClientSecret := flag.String("googleClientSecret", "", "Google OAuth client secret")

	flag.Parse()

	// Create and configure the server
	s := server.NewServer(*path, *baseDomain, *devMode)

	// Configure Google OAuth if credentials are provided
	if *googleClientID != "" && *googleClientSecret != "" {
		// Construct the redirect URI based on the base domain
		protocol := "https"
		if *devMode {
			protocol = "http"
		}
		redirectURI := fmt.Sprintf("%s://%s/callback", protocol, *baseDomain)

		// Set Google OAuth config
		s.SetGoogleOAuthConfig(*googleClientID, *googleClientSecret, redirectURI, nil)
		log.Info().Str("redirectURI", redirectURI).Msg("Configured Google OAuth")
	} else {
		// Try to get credentials from environment variables
		googleClientID := os.Getenv("GOOGLE_CLIENT_ID")
		googleClientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")

		if googleClientID != "" && googleClientSecret != "" {
			// Construct the redirect URI based on the base domain
			protocol := "https"
			if *devMode {
				protocol = "http"
			}
			redirectURI := fmt.Sprintf("%s://%s/callback", protocol, *baseDomain)

			// Set Google OAuth config
			s.SetGoogleOAuthConfig(googleClientID, googleClientSecret, redirectURI, nil)
			log.Info().Str("redirectURI", redirectURI).Msg("Configured Google OAuth from environment")
		} else {
			log.Warn().Msg("Google OAuth credentials not provided. OAuth flows will not work.")
		}
	}

	// Start the server
	address := fmt.Sprintf(":%d", *port)
	log.Info().Str("address", address).Str("path", *path).Msg("Starting server")

	err := http.ListenAndServe(address, s.Router)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to start server")
	}
}
