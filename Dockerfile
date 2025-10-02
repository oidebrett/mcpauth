# ----------------------
# Build stage
# ----------------------
FROM golang:1.23-bookworm AS builder

# Install build dependencies (for CGO + sqlite)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    libsqlite3-dev \
    sqlite3 \
    ca-certificates \    
 && rm -rf /var/lib/apt/lists/* /var/cache/apt/*

WORKDIR /app

# Copy go.mod first and download deps
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build the application binary
# Output goes to /app/bin/main
RUN go build -o /app/bin/main ./cmd/main.go

# ----------------------
# Final runtime stage
# ----------------------
FROM debian:bookworm-slim AS production

# Install only sqlite runtime (no dev headers, smaller image)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsqlite3-0 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/bin/main /app/main

# Copy assets (if your app needs them at runtime)
COPY --from=builder /app/assets /app/assets
COPY --from=builder /app/data /app/data

# Expose default port
EXPOSE 11000

# Run the app
CMD ["/app/main"]
