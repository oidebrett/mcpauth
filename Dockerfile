FROM golang:1.22-alpine AS builder

WORKDIR /app

# Install build dependencies (needed for CGO + go-sqlite3)
RUN apk add --no-cache gcc musl-dev

# Copy go.mod and go.sum files first
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source code
COPY . .

# Build the application with CGO enabled
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 GOOS=linux go build -o mcpauth ./cmd

# Final minimal image
FROM alpine:3.17

WORKDIR /app

# Install runtime dependencies for SQLite
RUN apk add --no-cache libstdc++ sqlite-libs

# Copy the compiled binary
COPY --from=builder /app/mcpauth .

EXPOSE 11000

ENTRYPOINT ["./mcpauth"]

