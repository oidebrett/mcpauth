package main

import (
	"flag"
	"mcpauth/server"
	"os"

	"github.com/rs/zerolog/log"
)

func main() {
	// Parse command line flags
	var devMode bool
	var provider string
	var clientID string
	var clientSecret string

	flag.BoolVar(&devMode, "dev", false, "Run in development mode")
	flag.StringVar(&provider, "provider", "google", "OAuth provider to use (google, auth0, etc)")
	flag.StringVar(&clientID, "clientID", "", "OAuth client ID")
	flag.StringVar(&clientSecret, "clientSecret", "", "OAuth client secret")
	flag.Parse()

	// Check environment variables if flags are not set
	if clientID == "" {
		clientID = os.Getenv("CLIENT_ID")
	}
	if clientSecret == "" {
		clientSecret = os.Getenv("CLIENT_SECRET")
	}
	if provider == "" {
		provider = os.Getenv("OAUTH_PROVIDER")
		if provider == "" {
			provider = "google" // Default to Google if not specified
		}
	}

	// Create a new server
	s := server.NewServer("/sse", "localhost:11000", devMode)

	// Configure OAuth provider
	googleRedirectURI := "http://localhost:11000/callback"
	scopes := []string{"openid", "email", "profile"}

	if err := s.ConfigureProvider(provider, clientID, clientSecret, googleRedirectURI, scopes); err != nil {
		log.Fatal().Err(err).Msg("Failed to configure OAuth provider")
	}

	// Start the server
	log.Info().Msg("Starting server on :11000")
	if err := s.Router.Run(":11000"); err != nil {
		log.Fatal().Err(err).Msg("Failed to start server")
	}
}
