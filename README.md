
<div align="center">
  <h1>MCPAuth</h1>
  <p><strong>MCPAuth: Gateway Authentication for Secure Enterprise MCP Integrations</strong></p>

  <img src="https://img.shields.io/github/license/oidebrett/mcpauth" alt="License">
  <img src="https://img.shields.io/github/v/release/oidebrett/mcpauth" alt="Release">
  <img src="https://img.shields.io/github/go-mod/go-version/oidebrett/mcpauth" alt="Go Version">
  <img src="https://github.com/oidebrett/mcpauth/actions/workflows/ci.yml/badge.svg" alt="CI Status">
</div>

## MCPAuth: Gateway Authentication for Secure Enterprise MCP Integrations

**McpAuth** is the authentication and authorization component of the **MCP Gateway** Proof of Concept (PoC) described in the paper:

> *Simplified and Secure MCP Gateways for Enterprise AI Integration*  
> **Ivo Brett, CISSP, B.Eng, MSc**  
> [View Paper](https://arxiv.org/pdf/2504.19997) (2025)

This repository is part of a broader initiative to enable **secure, scalable, and compliant enterprise integration** with the **Model Context Protocol (MCP)**. See the website [SelfHostedMCP.com](https://selfhostedmcp.com). It provides an extensible OAuth2.1-based authentication gateway that offloads identity, authorization, and policy management from backend MCP servers—ensuring conformance with the 2025-03-26 MCP Specification.

<img src="assets/resource_authorization.png" width="80%"/> 
---

### Purpose

McpAuth is designed to:
- **Decouple security logic** from MCP servers
- **Centralize identity management** using OAuth 2.1 & OIDC
- Support **dynamic client registration**
- Enforce **fine-grained token scopes and policy controls**
- Act as a **composable module** in enterprise-grade Zero Trust architectures

---

### Background

This implementation is part of a larger PoC that validates:
- A reference **MCP Gateway architecture** for secure deployments
- Threat model mapping aligned with frameworks such as MAESTRO and Narajala & Habler
- Real-world compatibility with tools like Cloudflare Tunnels, WireGuard, Traefik, and CrowdSec

The **full proof of concept** includes:
- Two isolated MCP servers (local and cloud-based)
- Secure tunneling via WireGuard and Pangolin
- Centralized intrusion detection and observability
- Seamless integration with Anthropic's MCP Inspector


## Features

- OAuth2 authentication with PKCE via Traefik `forwardAuth`
- Seamless integration with MCP Gateway SSE endpoints
- Email whitelisting for controlled access
- Docker-ready, easy to deploy
- Includes a Python-based test server


<img src="assets/MCPAuthFlow.png" width="80%"/> 

---

## Quick Start (assuming a completely standalone working environment)

### Set Up Google OAuth
Go to the Google Cloud Console
Navigate to APIs & Services > Credentials
Click Create Credentials → OAuth client ID
Choose Web Application
Add an Authorized redirect URI — you’ll get this later when you set up Traefik, but it will look like:
https://oauth.yourdomain.com/callback

Save the Client ID and Client Secret for later use.

### Alternative: Set Up Keycloak OAuth

MCPAuth now supports Keycloak as an identity provider. This is useful for enterprise environments that want to use their existing Keycloak infrastructure.

For complete MCP + Keycloak setup instructions, see the official guide: [MCP Security Authorization with Keycloak](https://modelcontextprotocol.io/docs/tutorials/security/authorization#keycloak-setup)

#### Detailed Keycloak Client Configuration

##### 1. Create a Keycloak Realm
- Use an existing realm (e.g., `master`) or create a new one

##### 2. Create and Configure the Client

**Basic Settings:**
- Go to your realm → **Clients** → **Create**
- **Client ID:** `mcp-server` (or your preferred ID)
- **Client Protocol:** `openid-connect`
- **Access Type / Client Authentication:** `confidential`
- **Save** the client

**Settings Tab:**

**Valid Redirect URIs** (add ALL of these):
```
https://oauth.yourdomain.com/callback
http://localhost:*/oauth/callback
http://localhost:*/oauth/callback/debug
```

**Explanation:**
- First line: Production callback for your mcpauth server
- Second line: Development - MCP clients running locally (wildcard port)
- Third line: MCP Inspector debug interface (includes `/debug` suffix)

**Web Origins** (for CORS - add ALL of these):
```
https://oauth.yourdomain.com
http://localhost:*
+
```

**Explanation:**
- Allows CORS requests from your production domain
- Allows CORS from any localhost port (development)
- `+` = Keycloak shortcut meaning "allow all redirect URIs as origins"

##### 3. Configure Audience Mapper (CRITICAL)

This step is **required** for mcpauth to validate tokens properly.

- Go to **Client Scopes** or **Mappers** tab
- Click **Add Mapper** → **By Configuration** → **Audience**
- **Name:** `audience-config`
- **Mapper Type:** `Audience`
- **Included Client Audience:** Leave empty
- **Included Custom Audience:** `https://oauth.yourdomain.com`
- **Add to ID token:** OFF
- **Add to access token:** ON
- **Save**

**Important:** Set the audience to your **mcpauth gateway URL**, not individual MCP server URLs. All MCP servers protected by mcpauth should use the same audience.

##### 4. Get Client Credentials

- Go to the **Credentials** tab
- Copy the **Client Secret**
- Save this for your `KEYCLOAK_CLIENT_SECRET` environment variable

##### 5. Configure Keycloak for Reverse Proxy (if behind Traefik/Nginx)

**Keycloak Environment Variables:**
```bash
KC_PROXY=edge
KC_HOSTNAME=keycloak.yourdomain.com
KC_HOSTNAME_PORT=443
KC_HOSTNAME_STRICT=false
KC_HTTP_ENABLED=true
```

**Run Keycloak with:**
```bash
docker run -p 127.0.0.1:9080:8080 \
  -e KC_PROXY=edge \
  -e KC_HOSTNAME=keycloak.yourdomain.com \
  -e KC_HOSTNAME_PORT=443 \
  quay.io/keycloak/keycloak start-dev
```

#### Traefik Configuration (IMPORTANT)

If using Traefik, you **must** make Keycloak's OAuth endpoints publicly accessible (no authentication required):

```yaml
http:
  routers:
    # Public Keycloak OAuth endpoints - NO AUTHENTICATION
    keycloak-public:
      rule: "Host(`keycloak.yourdomain.com`) && (PathPrefix(`/realms/{realm}/.well-known`) || PathPrefix(`/realms/{realm}/protocol/openid-connect`) || PathPrefix(`/realms/{realm}/resources`))"
      priority: 300  # Higher priority than authenticated routes
      service: keycloak-service
      entrypoints:
        - websecure
      tls:
        certResolver: letsencrypt
      # NO auth middleware here!

    # Protected Keycloak admin endpoints - WITH AUTHENTICATION
    keycloak-admin:
      rule: "Host(`keycloak.yourdomain.com`)"
      priority: 200
      service: keycloak-service
      middlewares:
        - your-auth-middleware
      entrypoints:
        - websecure
      tls:
        certResolver: letsencrypt

  services:
    keycloak-service:
      loadBalancer:
        servers:
          - url: "http://keycloak:8080"
```

**Critical Paths That Must Be Public:**
- `/.well-known/oauth-authorization-server` - OAuth discovery
- `/.well-known/openid-configuration` - OpenID Connect discovery
- `/protocol/openid-connect/auth` - Authorization endpoint
- `/protocol/openid-connect/token` - Token endpoint
- `/protocol/openid-connect/certs` - Public keys (JWKS)
- `/resources/*` - Static resources

#### Keycloak Environment Variables

| Variable                  | Default     | Description                              |
|---------------------------|-------------|------------------------------------------|
| `PROVIDER`                | *(none)*    | Set to `keycloak` to use Keycloak       |
| `CLIENT_ID`               | *(none)*    | Keycloak client ID                       |
| `CLIENT_SECRET`           | *(none)*    | Keycloak client secret                   |
| `KEYCLOAK_AUTH_HOST`      | `localhost` | Keycloak server host                     |
| `KEYCLOAK_AUTH_PORT`      | `8080`      | Keycloak server port                     |
| `KEYCLOAK_AUTH_PROTOCOL`  | `https`     | Keycloak protocol (http or https)        |
| `KEYCLOAK_REALM`          | `master`    | Keycloak realm name                      |

#### Example Keycloak .env file

```bash
PROVIDER=keycloak
CLIENT_ID=mcp-server
CLIENT_SECRET=your-keycloak-client-secret
KEYCLOAK_AUTH_HOST=keycloak.yourdomain.com
KEYCLOAK_AUTH_PORT=443
KEYCLOAK_AUTH_PROTOCOL=https
KEYCLOAK_REALM=your-realm
OAUTH_DOMAIN=oauth.yourdomain.com
```

#### Running with Keycloak

```bash
go run cmd/main.go \
  -provider=keycloak \
  -clientID=mcp-server \
  -clientSecret=your-client-secret \
  -keycloakAuthHost=localhost \
  -keycloakAuthPort=8080 \
  -keycloakRealm=master \
  -oauthDomain=oauth.yourdomain.com
```

Or using Docker Compose:

```yaml
services:
  mcpauth:
    image: oideibrett/mcpauth:latest
    environment:
      - PROVIDER=keycloak
      - CLIENT_ID=mcp-server
      - CLIENT_SECRET=${KEYCLOAK_CLIENT_SECRET}
      - KEYCLOAK_AUTH_HOST=keycloak
      - KEYCLOAK_AUTH_PORT=8080
      - KEYCLOAK_REALM=master
      - OAUTH_DOMAIN=oauth.yourdomain.com
    ports:
      - "11000:11000"

  keycloak:
    image: quay.io/keycloak/keycloak:latest
    environment:
      - KEYCLOAK_ADMIN=admin
      - KEYCLOAK_ADMIN_PASSWORD=admin
    command: start-dev
    ports:
      - "8080:8080"
```

#### Testing Your Keycloak Setup

##### 1. Verify Metadata Endpoints

```bash
# Check MCP protected resource metadata
curl https://your-mcp-server.com/.well-known/oauth-protected-resource/mcp

# Should return:
# {
#   "authorization_servers": ["https://keycloak.yourdomain.com/realms/master/"],
#   "resource": "https://your-mcp-server.com",
#   "scopes_supported": ["openid", "email"]
# }

# Check Keycloak OAuth metadata
curl https://keycloak.yourdomain.com/realms/master/.well-known/oauth-authorization-server

# Should return Keycloak's full OAuth configuration with endpoints
```

##### 2. Test with MCP Inspector

1. Install MCP Inspector: `npm install -g @modelcontextprotocol/inspector`
2. Run: `mcp-inspector`
3. Add your protected MCP server URL
4. Click "Connect" - you should be redirected to Keycloak login
5. After login, you should be redirected back and connected

##### 3. Test with Claude Desktop

Add to your Claude Desktop config (`~/Library/Application Support/Claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "protected-server": {
      "url": "https://your-mcp-server.com"
    }
  }
}
```

Restart Claude Desktop and try to use the MCP server - you'll be prompted for Keycloak authentication.

#### Troubleshooting

**"Page not found" when redirected to Keycloak:**
- Check that Keycloak's OAuth endpoints are NOT protected by authentication
- Verify the Traefik public router configuration (priority 300)
- Test: `curl https://keycloak.yourdomain.com/realms/master/.well-known/oauth-authorization-server`

**"Invalid redirect URI" error:**
- Add the exact redirect URI to Keycloak client settings
- For MCP Inspector, include: `http://localhost:*/oauth/callback/debug`
- For production, include: `https://oauth.yourdomain.com/callback`

**CORS errors in browser:**
- Configure **Web Origins** in Keycloak client
- Add `http://localhost:*` for development
- Add `+` to allow all redirect URIs as origins

**"Audience validation failed" errors:**
- Verify the **Audience Mapper** is configured correctly
- Audience should be: `https://oauth.yourdomain.com` (your mcpauth gateway)
- Check mcpauth logs for the expected audience value

**Token introspection fails:**
- Verify `KEYCLOAK_AUTH_HOST`, `KEYCLOAK_AUTH_PORT`, and `KEYCLOAK_AUTH_PROTOCOL` are correct
- Test introspection endpoint: `curl -X POST https://keycloak.yourdomain.com/realms/master/protocol/openid-connect/token/introspect`

### Create .env file (for Google OAuth)
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


### Scope Configuration

MCPAuth supports fine-grained scope control to enhance security by limiting token privileges. You can define which scopes are allowed in an OAuth request and which are required for a token to be considered valid.

- **Allowed Scopes**: A whitelist of scopes that the middleware is permitted to request from the OAuth provider. If a client requests scopes not in this list, they will be ignored.
- **Required Scopes**: A list of scopes that *must* be present in the granted token after the user authenticates. If the token does not contain all of these scopes, access will be denied with a `403 Forbidden (Insufficient Scope)` error.

This allows you to enforce policies like requiring an `email` scope for all users while allowing clients to optionally request additional permissions like `profile` or custom API scopes.

#### Configuration

You can configure scopes using command-line flags or environment variables:

| Variable           | Flag                | Description                                  |
|--------------------|---------------------|----------------------------------------------|
| `ALLOWED_SCOPES`   | `-allowedScopes`    | Comma-separated list of allowed OAuth scopes.  |
| `REQUIRED_SCOPES`  | `-requiredScopes`   | Comma-separated list of required OAuth scopes. |

**Example:**
To allow clients to request `openid`, `email`, and `profile` scopes, but require that all valid tokens include at least `openid` and `email`, you would set:
- `ALLOWED_SCOPES=openid,email,profile`
- `REQUIRED_SCOPES=openid,email`


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



## Developers Installation

### Prerequisites

- Go 1.21+
- Traefik v2.x+
- An OAuth provider (e.g., Google, GitHub)

### Installation

```bash
git clone https://github.com/oidebrett/mcpauth
cd mcpauth
go mod tidy
```

```bash
go run cmd/main.go -port=11000 -oauthDomain=your-domain.com
```

---


## Docker Deployment

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


## Traefik Integration

### ForwardAuth Middleware

```yaml
http:
  middlewares:
    mcp-auth:
      forwardAuth:
        address: "http://mcpauth:11000/auth"
        authResponseHeaders:
          - "X-Forwarded-User"
```

### Attach to a Router

```yaml
labels:
  - "traefik.http.routers.myapp.middlewares=mcp-auth@file"
```

---


## Testing

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


## Middleware Chain (Traefik)

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


## Middleware Manager Support

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


## License

Licensed under the [GNU General Public License v3.0](LICENSE).

