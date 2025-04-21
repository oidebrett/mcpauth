# MCP Auth Server

A minimal Go application that implement OAuth for MCP (Model Context Protocol) authentication.

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
LOG_LEVEL=1                     # Log level: 0=debug (all logs), 1=info (no secrets), 2=minimal (startup/shutdown only)
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
    ports:              #dont use if using gerbil
      - "11000:11000"   #dont use if using gerbil
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
      - "${PORT}:${PORT}"  #dont use if using gerbil
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
      - "11000:11000" #dont use if using gerbil
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
      - "${PORT}:${PORT}" #dont use if using gerbil
```

And in your `.env` file:

```
ALLOWED_EMAILS=user1@example.com,user2@example.com
```

Leave `ALLOWED_EMAILS` empty or omit it entirely to allow all authenticated users.



## Setting up a `forwardAuth` middleware

1. **Defining the middleware in a dynamic config file**, and  
2. **Attaching that middleware to a container via labels**.


---

### **1. Defining the Middleware**

In your `dynamic_config.yml` (or wherever you're loading dynamic configs), you've already defined the middleware:

```yaml
mymcpauth:
  forwardAuth:
    address: http://mcpauth:11000/sse
    authResponseHeaders:
      - "X-Forwarded-User"
```

This tells Traefik:

- When this middleware is used, forward the request to `http://mcpauth:11000/sse` for authentication.
- If the response is a 2xx, the request continues.
- It will pass along the `X-Forwarded-User` header from the auth response to the backend.

✅ **Good to point out**: `mcpauth` is the name of the service in the Docker network Traefik is in — typically a container named `mcpauth`.

---

### **2. Attaching Middleware to a Container**

Let’s say you have a `whoami` container and want to attach `mymcpauth`.

Here’s what you’d tell the user to add in the container’s `labels` section:

```yaml
services:
  whoami:
    image: ghcr.io/traefik/whoami:latest
    environment:
      - WHOAMI_PORT_NUMBER=4545
    labels:
      - "traefik.http.routers.whoami.rule=Host(`whoami.example.com`)"
      - "traefik.http.routers.whoami.middlewares=mymcpauth@file"
      - "traefik.http.services.whoami.loadbalancer.server.port=4545"
      - "traefik.http.routers.whoami.entrypoints=websecure"
      - "traefik.http.routers.whoami.tls=true"
```

### ✅ Key label:
```yaml
- "traefik.http.routers.whoami.middlewares=mymcpauth@file"
```

That tells Traefik:  
> "Hey, go look in the file-based dynamic config for a middleware named `mymcpauth`."

---

### Bonus: Explaining the `@file` vs `@docker`

- `@file` → dynamic config (like your `dynamic_config.yml`)
- `@docker` → Docker label-based middlewares

If the middleware had been defined in Docker labels instead, it would be:  
```yaml
- "traefik.http.routers.whoami.middlewares=mymcpauth@docker"
```

---

### Summary

1. **Define the middleware** (in `dynamic_config.yml`):
    ```yaml
    mymcpauth:
      forwardAuth:
        address: http://mcpauth:11000/sse
        authResponseHeaders:
          - "X-Forwarded-User"
    ```

2. **Attach to a container with a router label**:
    ```yaml
    - "traefik.http.routers.myapp.middlewares=mymcpauth@file"
    ```

### How to configure middleware manager

#### Edit templates.yml and include
```yaml
# Add these middleware templates
middlewares:
  - id: mcp-auth
    name: MCP Authentication
    type: forwardAuth
    config:
      address: "http://mcpauth:11000/sse"
      authResponseHeaders:
        - "X-Forwarded-User"

  - id: mcp-cors-headers
    name: MCP CORS Headers
    type: headers
    config:
      accessControlAllowMethods:
        - GET
        - POST
        - OPTIONS
      accessControlAllowOriginList:
        - "*"
      accessControlAllowHeaders:
        - Authorization
        - Content-Type
        - mcp-protocol-version
      accessControlMaxAge: 86400
      accessControlAllowCredentials: true
      addVaryHeader: true

  - id: redirect-regex
    name: Regex Redirect
    type: redirectregex
    config:
      regex: "^https://([a-z0-9-]+).yourdomain.com/.well-known/oauth-authorization-server"
      replacement: "https://oauth.yourdomain.com/.well-known/oauth-authorization-server"
      permanent: true

```

#### Apply middleware (stritly in this order)

- mcp-cors-headers@file
- redirect-regex@file
- mcp-auth@file