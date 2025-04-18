FROM golang:1.21-alpine AS builder

WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY *.go ./
COPY server/ ./server/

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o /mcpauth .

# Create a minimal image
FROM alpine:latest

WORKDIR /

# Copy the binary from the builder stage
COPY --from=builder /mcpauth /mcpauth

# Expose the default port
EXPOSE 11000

# Run the application
ENTRYPOINT ["/mcpauth"]