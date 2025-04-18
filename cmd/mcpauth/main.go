package main

import (
    "flag"
    "fmt"
    "net/http"

    "github.com/rs/zerolog/log"
    "mcpauth/internal/server"
)

func main() {
    // Define command line flags
    port := flag.Int("port", 11000, "Port to run the server on")
    path := flag.String("path", "/sse", "Path to listen for and return 401")
    flag.Parse()

    // Create and configure the server
    s := server.NewServer(*path)

    // Start the server
    address := fmt.Sprintf(":%d", *port)
    log.Info().Str("address", address).Str("path", *path).Msg("Starting server")
    
    err := http.ListenAndServe(address, s.Router)
    if err != nil {
        log.Fatal().Err(err).Msg("Failed to start server")
    }
}