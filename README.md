# MCP Auth Server

A minimal Go application that returns a 401 Unauthorized response for MCP (Model Context Protocol) authentication.

## Requirements

- Go 1.21 or later
- Git (for cloning the repository)

## Installation

### Install Go

1. Download and install Go from [golang.org/dl](https://golang.org/dl/)
2. Verify installation:
   ```bash
   go version
   ```

### Get the code

```bash
# Clone the repository
git clone <repository-url>
cd mcpauth
```

### Install dependencies

```bash
# Initialize the module and download dependencies
go mod tidy
```

## Running and Debugging

### Run the application

```bash
# Run with default settings
go run cmd/main.go

# Run with custom port and path
go run cmd/main.go -port=8080 -protected_path=/sse
```

### Environment Variables

The application can be configured using environment variables:

```
PORT=11000                      # Port to run the server on
PROTECTED_PATH=/sse             # Path of the MCP SSE server endpoint (replaces PATH to avoid conflicts with system PATH)
OAUTH_DOMAIN=your-domain.com    # Domain for OAuth endpoints
DEV_MODE=false                  # Enable development mode
CLIENT_ID=YOUR_CLIENT_ID        # OAuth client ID
CLIENT_SECRET=YOUR_CLIENT_SECRET # OAuth client secret
ALLOWED_EMAILS=user1@example.com,user2@example.com  # Comma-separated list of authorized emails (empty = allow all)
```

### Build and run

```bash
# Build the application
go build -o mcpauth ./cmd

# Run the built application
./mcpauth
```

### Debugging

#### Using VS Code

1. Install the Go extension for VS Code
2. Open the project folder in VS Code
3. Create a `.vscode/launch.json` file:
   ```json
   {
     "version": "0.2.0",
     "configurations": [
       {
         "name": "Launch",
         "type": "go",
         "request": "launch",
         "mode": "auto",
         "program": "${workspaceFolder}",
         "args": ["-port=11000", "-protectedPath=/sse"]
       }
     ]
   }
   ```
4. Press F5 to start debugging

#### Using GoLand

1. Open the project in GoLand
2. Create a new Run/Debug Configuration
3. Set the configuration to "Go Build"
4. Set the program arguments to "-port=11000 -protectedPath=/sse"
5. Click Debug to start debugging

### Testing with curl

```bash
# Test the unauthorized endpoint
curl -i http://localhost:11000/sse

# Test the health endpoint
curl -i http://localhost:11000/health
```

## Docker

### Run with Docker

```bash
# Build the Docker image
docker build -t mcpauth .

# Run the container
docker run -p 11000:11000 mcpauth
```

### Run with Docker Compose

```bash
# Start the service
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the service
docker-compose down
```

## Docker Compose Configuration

### Basic Configuration

To run the MCP Auth Server with Docker Compose, add the following service definition to your `docker-compose.yml` file:

```yaml
services:
  mcpauth:
    container_name: mcpauth
    build:
      context: ./mcpauth  # Path to your project root
      dockerfile: Dockerfile
    command: [
      "-port=11000", 
      "-protectedPath=/sse", 
      "-oauthDomain=your-domain.com", 
      "-devMode=false"
    ]
    restart: unless-stopped
    ports:
      - "11000:11000"
```

### Environment Variable Configuration

You can configure all parameters using environment variables, which is the recommended approach:

1. Create a `.env` file in the same directory as your `docker-compose.yml`:

```
PORT=11000
PROTECTED_PATH=/sse
OAUTH_DOMAIN=your-domain.com
DEV_MODE=false
CLIENT_ID=YOUR_OAUTH_CLIENT_ID_HERE
CLIENT_SECRET=YOUR_OAUTH_CLIENT_SECRET_HERE
```

2. Update your `docker-compose.yml` to use these environment variables:

```yaml
services:
  mcpauth:
    container_name: mcpauth
    build:
      context: ./mcpauth
      dockerfile: Dockerfile
    env_file:
      - .env
    environment:
      - PORT=${PORT}
      - PROTECTED_PATH=${PROTECTED_PATH}
      - OAUTH_DOMAIN=${OAUTH_DOMAIN}
      - DEV_MODE=${DEV_MODE}
      - OAUTH_PROVIDER=google  # Currently supported: google
      - CLIENT_ID=${CLIENT_ID}
      - CLIENT_SECRET=${CLIENT_SECRET}
    restart: unless-stopped
    ports:
      - "${PORT}:${PORT}"
```

3. Make sure to add `.env` to your `.gitignore` file to avoid committing sensitive credentials.

### Mixed Configuration

You can also mix command-line arguments with environment variables. Command-line arguments take precedence:

```yaml
services:
  mcpauth:
    container_name: mcpauth
    build:
      context: ./mcpauth
      dockerfile: Dockerfile
    command: [
      "-port=11000", 
      "-protected_path=/sse"
    ]
    env_file:
      - .env
    environment:
      - OAUTH_DOMAIN=your-domain.com
      - DEV_MODE=false
      - OAUTH_PROVIDER=google
      - CLIENT_ID=${CLIENT_ID}
      - CLIENT_SECRET=${CLIENT_SECRET}
    restart: unless-stopped
    ports:
      - "11000:11000"
```

## Authorization with Email Whitelist

MCP Auth Server now supports authorization via an email whitelist. After a user authenticates through OAuth, their email is checked against a configurable whitelist.

### How it works

1. When a user authenticates via OAuth, their email is retrieved from the OAuth provider
2. If a whitelist is configured, the user's email is checked against it
3. If the whitelist is empty, all authenticated users are allowed access
4. If the whitelist contains emails, only users with matching emails are allowed access

### Configuration

You can configure the email whitelist using either:

#### Command-line flag:

```bash
go run cmd/main.go -allowedEmails="user1@example.com,user2@example.com"
```

#### Environment variable:

```
ALLOWED_EMAILS=user1@example.com,user2@example.com
```

### Docker Compose Configuration

Update your `docker-compose.yml` to include the allowed emails:

```yaml
services:
  mcpauth:
    container_name: mcpauth
    build:
      context: ./mcpauth
      dockerfile: Dockerfile
    env_file:
      - .env
    environment:
      - PORT=${PORT}
      - PROTECTED_PATH=${PROTECTED_PATH}
      - OAUTH_DOMAIN=${OAUTH_DOMAIN}
      - DEV_MODE=${DEV_MODE}
      - OAUTH_PROVIDER=google
      - CLIENT_ID=${CLIENT_ID}
      - CLIENT_SECRET=${CLIENT_SECRET}
      - ALLOWED_EMAILS=${ALLOWED_EMAILS}
    restart: unless-stopped
    ports:
      - "${PORT}:${PORT}"
```

And in your `.env` file:

```
ALLOWED_EMAILS=user1@example.com,user2@example.com
```

Leave `ALLOWED_EMAILS` empty or omit it entirely to allow all authenticated users.
