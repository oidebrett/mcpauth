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
go run main.go

# Run with custom port and path
go run main.go -port=8080 -path=/auth
```

### Build and run

```bash
# Build the application
go build -o mcpauth

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
         "args": ["-port=11000", "-path=/sse"]
       }
     ]
   }
   ```
4. Press F5 to start debugging

#### Using GoLand

1. Open the project in GoLand
2. Create a new Run/Debug Configuration
3. Set the configuration to "Go Build"
4. Set the program arguments to "-port=11000 -path=/sse"
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
