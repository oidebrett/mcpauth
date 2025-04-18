FROM golang:1.20-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o mcpauth ./cmd/mcpauth

# Use a small alpine image for the final container
FROM alpine:3.17

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/mcpauth .

# Expose the port
EXPOSE 11000

# Run the application
ENTRYPOINT ["./mcpauth"]
