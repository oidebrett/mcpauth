package main

import (
    "flag"

    "github.com/rs/zerolog/log"
    
    "mcpauth/server"
)

func main() {
    // Parse command line flags
    var devMode bool
    flag.BoolVar(&devMode, "dev", false, "Run in development mode")
    flag.Parse()

    // Create a new server
    s := server.NewServer("/sse", "localhost:11000", devMode)
    
    // Configure Google OAuth
    // Replace these with your actual Google OAuth credentials
    googleClientID := "252740974698-sm3m51upn5j2pqk4qm7qkagu7ja77n02.apps.googleusercontent.com"
    googleClientSecret := "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"
    googleRedirectURI := "http://localhost:11000/callback"
    googleScopes := []string{"openid", "email", "profile"}
    
    s.SetGoogleOAuthConfig(googleClientID, googleClientSecret, googleRedirectURI, googleScopes)
    
    // Start the server
    log.Info().Msg("Starting server on :11000")
    if err := s.Router.Run(":11000"); err != nil {
        log.Fatal().Err(err).Msg("Failed to start server")
    }
}
