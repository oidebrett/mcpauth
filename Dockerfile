FROM golang:1.22 AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y gcc libc6-dev make && rm -rf /var/lib/apt/lists/*
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build -o mcpauth ./cmd

# Final runtime image (Debian slim instead of Alpine)
FROM debian:bullseye-slim
WORKDIR /app

# Install only what’s needed for runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates sqlite3 libsqlite3-0 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/mcpauth .

EXPOSE 11000
ENTRYPOINT ["./mcpauth"]
