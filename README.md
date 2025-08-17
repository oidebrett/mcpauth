
<div align="center">
  <h1>MCPAuth</h1>
  <p><strong>MCPAuth: Gateway Authentication for Secure Enterprise MCP Integrations</strong></p>

  <img src="https://img.shields.io/github/license/oidebrett/mcpauth" alt="License">
  <img src="https://img.shields.io/github/v/release/oidebrett/mcpauth" alt="Release">
  <img src="https://img.shields.io/github/go-mod/go-version/oidebrett/mcpauth" alt="Go Version">
  <img src="https://github.com/oidebrett/mcpauth/actions/workflows/ci.yml/badge.svg" alt="CI Status">
</div>

## 🔐 MCPAuth: Gateway Authentication for Secure Enterprise MCP Integrations

**McpAuth** is the authentication and authorization component of the **MCP Gateway** Proof of Concept (PoC) described in the paper:

> *Simplified and Secure MCP Gateways for Enterprise AI Integration*  
> **Ivo Brett, CISSP, B.Eng, MSc**  
> [View Paper](https://arxiv.org/pdf/2504.19997) (2025)

This repository is part of a broader initiative to enable **secure, scalable, and compliant enterprise integration** with the **Model Context Protocol (MCP)**. See the website [SelfHostedMCP.com](https://selfhostedmcp.com). It provides an extensible OAuth2.1-based authentication gateway that offloads identity, authorization, and policy management from backend MCP servers—ensuring conformance with the 2025-03-26 MCP Specification.

<img src="assets/resource_authorization.png" width="80%"/> 
---

### 🔍 Purpose

McpAuth is designed to:
- **Decouple security logic** from MCP servers
- **Centralize identity management** using OAuth 2.1 & OIDC
- Support **dynamic client registration**
- Enforce **fine-grained token scopes and policy controls**
- Act as a **composable module** in enterprise-grade Zero Trust architectures

---

### 📚 Background

This implementation is part of a larger PoC that validates:
- A reference **MCP Gateway architecture** for secure deployments
- Threat model mapping aligned with frameworks such as MAESTRO and Narajala & Habler
- Real-world compatibility with tools like Cloudflare Tunnels, WireGuard, Traefik, and CrowdSec

The **full proof of concept** includes:
- Two isolated MCP servers (local and cloud-based)
- Secure tunneling via WireGuard and Pangolin
- Centralized intrusion detection and observability
- Seamless integration with Anthropic's MCP Inspector


## ✨ Features

- 🔐 OAuth2 authentication with PKCE via Traefik `forwardAuth`
- ⚡ Seamless integration with MCP Gateway SSE endpoints
- ✅ Email whitelisting for controlled access
- 🐳 Docker-ready, easy to deploy
- 🧪 Includes a Python-based test server


<img src="assets/MCPAuthFlow.png" width="80%"/> 

---

## 🚀 Quick Start (assuming a completely standalone working environment)

### Set Up Google OAuth
Go to the Google Cloud Console
Navigate to APIs & Services > Credentials
Click Create Credentials → OAuth client ID
Choose Web Application
Add an Authorized redirect URI — you’ll get this later when you set up Traefik, but it will look like:
https://oauth.yourdomain.com/callback

Save the Client ID and Client Secret for later use.

### Create .env file
```
CLIENT_ID=<INSERT_VALUE_FROM_GOOGLE>
CLIENT_SECRET=<INSERT_VALUE_FROM_GOOGLE>
```

### 🔧 Note the Configuration Flags

Use flags or environment variables:

| Variable         | Default   | Description                              |
|------------------|-----------|------------------------------------------|
| `PORT`           | `11000`   | Port for the auth server                 |
| `PROTECTED_PATH` | `/sse`    | Protected endpoint path                  |
| `OAUTH_DOMAIN`   | *(none)*  | OAuth issuer domain                      |
| `CLIENT_ID`      | *(none)*  | OAuth client ID                          |
| `CLIENT_SECRET`  | *(none)*  | OAuth client secret                      |
| `ALLOWED_EMAILS` | *(none)*  | Comma-separated list of allowed emails   |
| `LOG_LEVEL`      | `1`       | 0=debug, 1=info, 2=minimal               |


### Docker Compose

```yaml
services:
  mcpauth:
    image: oideibrett/mcpauth:latest
    environment:
      - PORT=11000
      - CLIENT_ID=${CLIENT_ID}
      - CLIENT_SECRET=${CLIENT_SECRET}
    ports:
      - "11000:11000"

  traefik:
    image: traefik::v3.4.1
    command:
      - "--providers.docker=true"
      - "--entrypoints.websecure.address=:443"
    ports:
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
```



## 🚀 Developers Installation

### 📦 Prerequisites

- Go 1.21+
- Traefik v2.x+
- An OAuth provider (e.g., Google, GitHub)

### 🛠️ Installation

```bash
git clone https://github.com/oidebrett/mcpauth
cd mcpauth
go mod tidy
```

```bash
go run cmd/main.go -port=11000 -oauthDomain=your-domain.com
```

---


## 🐳 Docker Deployment

### Docker build

```bash
docker buildx build --platform linux/amd64,linux/arm64 -t oideibrett/mcpauth:dev --push .
```

### Basic Docker Compose

```yaml
services:
  mcpauth:
    build: .
    environment:
      - PORT=11000
      - CLIENT_ID=${CLIENT_ID}
      - CLIENT_SECRET=${CLIENT_SECRET}
    ports:
      - "11000:11000"
```

---


## 🔐 Traefik Integration

### ForwardAuth Middleware

```yaml
http:
  middlewares:
    mcp-auth:
      forwardAuth:
        address: "http://mcpauth:11000/sse"
        authResponseHeaders:
          - "X-Forwarded-User"
```

### Attach to a Router

```yaml
labels:
  - "traefik.http.routers.myapp.middlewares=mcp-auth@file"
```

---


## 🧪 Testing

### Run Included Test Server

```bash
cd test_mcp_server
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python mcp-server-sse.py
```

### With `curl`

Here are a few `curl` commands to test different authentication and authorization scenarios.

**1. Health Check**

This command checks if the `mcpauth` service is running and responsive. You should receive a `200 OK` response.

```bash
curl -i http://localhost:11000/health
```

**2. Accessing a Protected Endpoint (No Token)**

When you try to access a protected endpoint like `/sse` without a valid token, `mcpauth` should initiate the OAuth2 authentication flow. For a non-browser client like `curl`, this will result in a `302 Found` redirect to the Google login page.

```bash
curl -i http://localhost:11000/sse
```
*Expected Output:* An HTTP `302 Found` redirecting to `https://accounts.google.com/...

**3. Accessing a Protected Endpoint (Valid Token)**

Once you have a valid bearer token from the OAuth provider, you can use it to access the protected endpoint. This request should be successful (`200 OK`), and `mcpauth` will forward the request to the upstream service.

```bash
# Replace YOUR_VALID_TOKEN with an actual bearer token
curl -i -H "Authorization: Bearer YOUR_VALID_TOKEN" http://localhost:11000/sse
```
*Expected Output:* An HTTP `200 OK` and the response from the test server (e.g., the SSE stream).

**4. Accessing a Protected Endpoint (Invalid/Expired Token)**

If you use a token that is invalid, malformed, or expired, `mcpauth` should deny access. This will likely result in a `401 Unauthorized` error, prompting for re-authentication.

```bash
curl -i -H "Authorization: Bearer INVALID_TOKEN" http://localhost:11000/sse
```
*Expected Output:* An HTTP `401 Unauthorized` response.

**5. Accessing with a Token from an Unauthorized User**

If the `ALLOWED_EMAILS` list is configured, `mcpauth` will validate the user's email from the token. If the user is not on the whitelist, access will be denied.

```bash
# Use a valid token from a user whose email is NOT in ALLOWED_EMAILS
curl -i -H "Authorization: Bearer TOKEN_FROM_UNAUTHORIZED_USER" http://localhost:11000/sse
```
*Expected Output:* An HTTP `403 Forbidden` response.

---


## 🧱 Middleware Chain (Traefik)

Apply middlewares in this order:

1. `mcp-cors-headers`
2. `redirect-regex`
3. `mcp-auth`

Example dynamic config:

```yaml
http:
  middlewares:
    mcp-cors-headers:
      headers:
        accessControlAllowCredentials: true
        accessControlAllowHeaders:
          - Authorization
          - Content-Type
          - mcp-protocol-version
        accessControlAllowMethods:
          - GET
          - POST
          - OPTIONS
        accessControlAllowOriginList:
          - "*"
        accessControlMaxAge: 86400
        addVaryHeader: true

    redirect-regex:
      redirectRegex:
        regex: "^https://([a-z0-9-]+)\.(.+)/\.well-known/(.+)"
        replacement: "https://oauth.${2}/.well-known/${3}"
        permanent: true

    mcp-auth:
      forwardAuth:
        address: "http://mcpauth:11000/sse"
        authResponseHeaders:
          - X-Forwarded-User
```

---


## 🧠 Middleware Manager Support

This project supports [middleware-manager](https://github.com/hhftechnology/middleware-manager).

Example `templates.yml`:

```yaml
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
      regex: "^https://([a-z0-9-]+)\.yourdomain\.com/\.well-known/oauth-authorization-server"
      replacement: "https://oauth.yourdomain.com/.well-known/oauth-authorization-server"
      permanent: true
```

---


## 📜 License

Licensed under the [GNU General Public License v3.0](LICENSE).

