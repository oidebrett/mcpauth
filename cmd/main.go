package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"mcpauth/server"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// Define command line flags
	port := flag.Int("port", 11000, "Port to run the server on")
	oauthDomain := flag.String("oauthDomain", "localhost", "Domain for OAuth endpoints")
	devMode := flag.Bool("devMode", false, "Enable development mode")
	allowedEmails := flag.String("allowedEmails", "", "Comma-separated list of emails allowed to access protected resources (empty = allow all)")
	logLevel := flag.Int("logLevel", 1, "Log level: 0=debug (all logs), 1=info (no secrets), 2=minimal (startup/shutdown only)")
	allowedScopes := flag.String("allowedScopes", "", "Comma-separated list of allowed OAuth scopes")
	requiredScopes := flag.String("requiredScopes", "", "Comma-separated list of required OAuth scopes")

	// OAuth provider configuration
	provider := flag.String("provider", "internal", "OAuth provider to use (google, internal, etc)")
	//provider := flag.String("provider", "google", "OAuth provider to use (google, internal, etc)")
	clientID := flag.String("clientID", "", "OAuth client ID")
	clientSecret := flag.String("clientSecret", "", "OAuth client secret")

	// Database and internal auth configuration
	dataDir := flag.String("dataDir", "./data", "Directory for database and other data files")
	useInternalAuth := flag.Bool("useInternalAuth", false, "Use internal authentication instead of external provider")

	// Default admin user (only used if no users exist and internal auth is enabled)
	adminUsername := flag.String("adminUsername", "admin", "Default admin username")
	adminEmail := flag.String("adminEmail", "admin@localhost", "Default admin email")
	adminPassword := flag.String("adminPassword", "admin123", "Default admin password")

	// Parse flags
	flag.Parse()

	// Check environment variables for configuration
	if envPort := os.Getenv("PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil {
			*port = p
		}
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

	// Check environment variables for log level
	if envLogLevel := os.Getenv("LOG_LEVEL"); envLogLevel != "" {
		if level, err := strconv.Atoi(envLogLevel); err == nil {
			*logLevel = level
		}
	}

	// Check environment variables for scopes
	if envAllowedScopes := os.Getenv("ALLOWED_SCOPES"); envAllowedScopes != "" {
		*allowedScopes = envAllowedScopes
	}
	if envRequiredScopes := os.Getenv("REQUIRED_SCOPES"); envRequiredScopes != "" {
		*requiredScopes = envRequiredScopes
	}

	// Configure logging based on log level
	configureLogging(*logLevel)

	// Log startup message
	log.Info().
		Int("port", *port).
		Str("oauthDomain", *oauthDomain).
		Bool("devMode", *devMode).
		Str("allowedEmails", *allowedEmails).
		Int("logLevel", *logLevel).
		Msg("Starting with configuration")

	// Create and configure the server
	s, err := server.NewServer(*oauthDomain, *devMode, *dataDir)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create server")
	}

	// Configure allowed emails if provided
	if *allowedEmails != "" {
		emailList := strings.Split(*allowedEmails, ",")
		// Trim spaces from each email
		for i, email := range emailList {
			emailList[i] = strings.TrimSpace(email)
		}
		s.SetAllowedEmails(emailList)
	}

	// Configure scopes if provided
	if *allowedScopes != "" || *requiredScopes != "" {
		allowed := strings.Split(*allowedScopes, ",")
		required := strings.Split(*requiredScopes, ",")
		for i, s := range allowed {
			allowed[i] = strings.TrimSpace(s)
		}
		for i, s := range required {
			required[i] = strings.TrimSpace(s)
		}
		s.SetScopes(allowed, required)
	}

	// Check environment variables for OAuth credentials if not provided via flags
	actualClientID := *clientID
	actualClientSecret := *clientSecret
	actualProvider := *provider

	log.Info().
		Str("provider", actualProvider). 
		Msg("Provider configuration")

    if actualProvider == "" {
        actualProvider = os.Getenv("PROVIDER")
        log.Info().
            Str("provider", actualProvider). 
            Msg("Provider configuration")
    }

	// If empty, try environment variables
	if actualClientID == "" {
		actualClientID = os.Getenv("CLIENT_ID")
		// Try provider-specific env var as fallback
		if actualClientID == "" && actualProvider == "google" {
			actualClientID = os.Getenv("GOOGLE_CLIENT_ID")
		}
	}

	if actualClientSecret == "" {
		actualClientSecret = os.Getenv("CLIENT_SECRET")
		// Try provider-specific env var as fallback
		if actualClientSecret == "" && actualProvider == "google" {
			actualClientSecret = os.Getenv("GOOGLE_CLIENT_SECRET")
		}
	}
	// Construct the redirect URI based on the base domain
	protocol := "https"
	if *devMode {
		protocol = "http"
	}
	redirectURI := fmt.Sprintf("%s://%s/callback", protocol, *oauthDomain)

	// Configure the OAuth provider
	if *useInternalAuth || actualProvider == "internal" {
		// Configure internal authentication
		if err := s.ConfigureProvider("internal", "", "", "", nil); err != nil {
			log.Fatal().Err(err).Msg("Failed to configure internal provider")
		}

		// Create default admin user if needed
		if err := s.CreateDefaultAdminUser(*adminUsername, *adminEmail, *adminPassword); err != nil {
			log.Warn().Err(err).Msg("Failed to create default admin user")
		}

		log.Info().Msg("Configured internal authentication provider")
	} else if actualClientID != "" && actualClientSecret != "" {
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
	log.Info().Str("address", address).Msg("Starting server")

	err = http.ListenAndServe(address, s.Router)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to start server...")
	}
}

// configureLogging sets up the logging configuration based on the specified log level
func configureLogging(level int) {
	switch level {
	case 0: // Debug - all logs including secrets
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
		log.Logger = log.With().Caller().Logger()
	case 1: // Info - no secrets
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
		// Create a hook to filter sensitive fields
		hook := zerolog.HookFunc(func(e *zerolog.Event, level zerolog.Level, message string) {
			// We can't directly remove fields that were already added
			// Instead, we'll need to be careful when logging sensitive data
		})
		log.Logger = log.Hook(hook)
	default: // Minimal - startup/shutdown only
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	}
}
