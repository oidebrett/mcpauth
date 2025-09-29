FROM golang:1.22 AS builder

WORKDIR /app

# Install GCC and dependencies
RUN apt-get update && apt-get install -y gcc libc6-dev make && rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=1 GOOS=linux go build -o mcpauth ./cmd

# Final image: still Alpine, minimal runtime
FROM alpine:3.17
WORKDIR /app

RUN apk add --no-cache libstdc++ sqlite-libs

COPY --from=builder /app/mcpauth .

EXPOSE 11000
ENTRYPOINT ["./mcpauth"]
