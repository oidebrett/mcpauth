package main

import (
    "flag"
    "fmt"
    "os"
    "os/signal"
    "syscall"

    "github.com/rs/zerolog/log"
    
    "mcpauth/server"
)

func main() {
    // Parse command line flags
    port := flag.Int("port", 11000, "Port to listen on")
    path := flag.String("path", "/sse", "Path to serve")
    baseDomain := flag.String("domain", "", "Base domain for OAuth endpoints")
    devMode := flag.Bool("dev", false, "Development mode (use HTTP instead of HTTPS)")
    flag.Parse()
    
    // If base domain is not set, use localhost:port
    domain := *baseDomain
    if domain == "" {
        domain = fmt.Sprintf("localhost:%d", *port)
    }

    // Create a new server
    server := server.NewServer(*path, domain, *devMode)
    
    // Start the server in a goroutine
    go func() {
        address := fmt.Sprintf(":%d", *port)
        log.Info().Str("address", address).Str("path", *path).Str("domain", domain).Bool("dev_mode", *devMode).Msg("Starting server")
        if err := server.Router.Run(address); err != nil {
            log.Fatal().Err(err).Msg("Failed to start server")
        }
    }()

    // Wait for interrupt signal to gracefully shutdown the server
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit
    
    log.Info().Msg("Shutting down server")
}
