
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

## Static Bearer Token (For Third-Party Testing)

When you need to give a third party a simple token to test their MCP client integration — without going through the full OAuth flow — you can set a static bearer token via the `AUTHORIZATION_BEARER_TOKEN` environment variable.

When this variable is set, any request that presents it as a `Bearer` token will be immediately granted access (returning `200 OK` with `X-Forwarded-User: static-authorized-user`). Requests with any other token fall through to the normal OAuth/session validation as usual. If the variable is unset or empty, the feature is completely disabled.

This is intended for **short-lived testing only** — not as a permanent auth mechanism.

### .env

Add the token to your `.env` file alongside your other secrets:

```env
AUTHORIZATION_BEARER_TOKEN=your-secret-token-here
```

### Docker Compose

```yaml
mcpauth:
  image: oideibrett/mcpauth:latest
  volumes:
    - ./config/data:/app/data
  environment:
    - ENABLE_EDGE_AUTH=true
    - COOKIE_DOMAIN=.yourdomain.com  # leading dot for subdomains
    - PORT=11000
    - PROVIDER=keycloak
    - CLIENT_ID=${CLIENT_ID}
    - CLIENT_SECRET=${CLIENT_SECRET}
    - OAUTH_DOMAIN=${OAUTH_DOMAIN:-oauth.yourdomain.com}
    - KEYCLOAK_AUTH_HOST=keycloak.yourdomain.com
    - KEYCLOAK_AUTH_PORT=443
    - KEYCLOAK_AUTH_PROTOCOL=https
    - KEYCLOAK_REALM=master
    - ALLOWED_SCOPES=openid,email,profile
    - AUTHORIZATION_BEARER_TOKEN=${AUTHORIZATION_BEARER_TOKEN}
    #- REQUIRED_SCOPES=openid,email
    - REQUIRED_SCOPES=email
  restart: unless-stopped
  ports:
    - "127.0.0.1:11000:11000"
```

### Testing with curl

```bash
# Should return 200 OK
curl -i -H "Authorization: Bearer your-secret-token-here" http://localhost:11000/auth

# Wrong token — falls through to OAuth validation, returns 401
curl -i -H "Authorization: Bearer wrongtoken" http://localhost:11000/auth
```

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
        regex: "^https://[^/]+\.([^.]+\.[^./]+)/\.well-known/(.+)"
        replacement: "https://oauth.${1}/.well-known/${2}"
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
      regex: "^https://[^/]+\.(yourdomain\.com)/\.well-known/(.+)"
      replacement: "https://oauth.${1}/.well-known/${2}"
      permanent: true
```

---


## Edge Auth (CF_Authorization Cookie Flow)

MCPAuth can act as a replacement for Cloudflare Access when protecting an OpenShell-style gateway behind Traefik. When enabled, it provides:

- **`/auth/connect`** — Browser-based login relay that authenticates the user via your IdP (Keycloak, Google, or internal), issues a `CF_Authorization` JWT cookie, and serves a connect page that relays the token to the CLI's localhost callback server.
- **`/_ws_tunnel`** — Forward-auth endpoint for Traefik that validates the `CF_Authorization` cookie before allowing WebSocket connections through to the gateway.
- **`/auth` (existing)** — Also accepts the `CF_Authorization` cookie as a fallback token source when edge auth is enabled.

Edge auth runs **in parallel** with the existing OAuth/Bearer token flow. The same mcpauth instance can serve both MCP OAuth clients and OpenShell gateway browser logins using the same IdP.

### Edge Auth Environment Variables

| Variable            | Flag               | Default        | Description                                           |
|---------------------|--------------------|----------------|-------------------------------------------------------|
| `ENABLE_EDGE_AUTH`  | `-enableEdgeAuth`  | `false`        | Enable edge auth endpoints                            |
| `COOKIE_DOMAIN`     | `-cookieDomain`    | `OAUTH_DOMAIN` | Domain for the `CF_Authorization` cookie              |

All other provider config (`PROVIDER`, `CLIENT_ID`, `CLIENT_SECRET`, Keycloak settings, etc.) is shared with the existing OAuth flow.

### Docker Compose with Edge Auth

```yaml
services:
  mcpauth:
    image: oideibrett/mcpauth:edge_auth
    environment:
      - ENABLE_EDGE_AUTH=true
      - COOKIE_DOMAIN=.yourdomain.com
      - OAUTH_DOMAIN=oauth.yourdomain.com
      - PROVIDER=keycloak
      - CLIENT_ID=mcp-server
      - CLIENT_SECRET=${KEYCLOAK_CLIENT_SECRET}
      - KEYCLOAK_AUTH_HOST=keycloak.yourdomain.com
      - KEYCLOAK_AUTH_PORT=443
      - KEYCLOAK_AUTH_PROTOCOL=https
      - KEYCLOAK_REALM=master
    restart: unless-stopped

  # If using internal auth instead of Keycloak:
  # mcpauth:
  #   image: oideibrett/mcpauth:edge_auth
  #   environment:
  #     - ENABLE_EDGE_AUTH=true
  #     - COOKIE_DOMAIN=.yourdomain.com
  #     - OAUTH_DOMAIN=oauth.yourdomain.com
  #     - DEV_MODE=false
  #   command: ["-useInternalAuth"]
```

### Traefik Dynamic Configuration for Edge Auth

Edge auth requires three Traefik components: the `edge-auth` forwardAuth middleware, a high-priority login router (so the login flow isn't blocked by forwardAuth), and the gateway router with the middleware applied.

#### 1. ForwardAuth Middleware

Add an `edge-auth` forwardAuth middleware. Traefik calls mcpauth's `/_ws_tunnel` endpoint to validate the `CF_Authorization` cookie before proxying to the gateway.

```yaml
http:
  middlewares:
    edge-auth:
      forwardAuth:
        address: "http://mcpauth:11000/_ws_tunnel"
        authResponseHeaders:
          - X-Forwarded-User
          - X-Forwarded-Scopes
```

#### 2. Routers

You need two routers on the **gateway domain** with different priorities:

```yaml
http:
  routers:
    # ── Login flow (NO middleware, priority 300) ─────────────────
    # CRITICAL: The login paths must have a HIGHER priority than
    # any router that applies the edge-auth middleware on the same
    # domain. Otherwise forwardAuth intercepts the login redirects
    # and returns 401 before the user can log in.
    gateway-login:
      rule: "Host(`gateway.yourdomain.com`) && (PathPrefix(`/auth/connect`) || PathPrefix(`/authorize`) || PathPrefix(`/callback`) || PathPrefix(`/internal`))"
      service: mcpauth-service
      priority: 300
      entryPoints:
        - websecure
      tls:
        certResolver: letsencrypt

    # ── Gateway (PROTECTED by edge-auth, priority 250) ───────────
    # All other requests to the gateway domain go through forwardAuth.
    # The edge-auth middleware validates the CF_Authorization cookie;
    # if valid (200), Traefik proxies to the gateway service.
    # If invalid/missing (401), the request is blocked.
    gateway-protected:
      rule: "Host(`gateway.yourdomain.com`)"
      service: gateway-service
      middlewares:
        - edge-auth
      priority: 250
      entryPoints:
        - websecure
      tls:
        certResolver: letsencrypt
```

> **Why two routers?** The gateway's catch-all router applies `edge-auth` forwardAuth to all requests. But the login flow itself (`/auth/connect` → `/authorize` → IdP → `/callback`) must reach mcpauth without authentication — these paths ARE the login. The higher-priority (300 vs 250) login router matches first and routes directly to mcpauth.

#### 3. Services

```yaml
http:
  services:
    mcpauth-service:
      loadBalancer:
        servers:
          - url: "http://mcpauth:11000"

    gateway-service:
      loadBalancer:
        servers:
          - url: "http://gateway:8080"
```

#### Existing MCP OAuth Routes (Unchanged)

The existing Bearer-token OAuth routes on the `oauth.yourdomain.com` domain are completely unaffected:

```yaml
http:
  middlewares:
    mcp-auth:
      forwardAuth:
        address: "http://mcpauth:11000/auth"
        authResponseHeaders:
          - X-Forwarded-User
          - X-Forwarded-Scopes

  routers:
    mcp-server:
      rule: "Host(`mcp.yourdomain.com`)"
      service: mcp-service
      middlewares:
        - mcp-auth
      entrypoints:
        - websecure
      tls:
        certResolver: letsencrypt
```

### How the Edge Auth Flow Works

1. The CLI opens the user's browser to `https://oauth.yourdomain.com/auth/connect?callback_port=<port>&code=<code>`
2. MCPAuth checks for a `CF_Authorization` cookie — none exists yet
3. MCPAuth redirects through the OAuth login flow (Keycloak, Google, or internal)
4. After successful IdP login, MCPAuth mints a `CF_Authorization` JWT cookie (24h TTL) and redirects back to `/auth/connect`
5. Now the cookie is present — MCPAuth serves the connect page showing the confirmation code
6. The user clicks "Connect" — JavaScript POSTs the token to the CLI's localhost callback
7. Subsequent `/_ws_tunnel` WebSocket connections include the cookie and are validated by the `edge-auth` forwardAuth middleware

### Keycloak Notes

- MCPAuth extracts the user's `email` from the Keycloak userinfo response. If no email is set on the Keycloak user, it falls back to `preferred_username`.
- Ensure your Keycloak client has `email` and `openid` in its client scopes so the email claim is returned.

### Testing Edge Auth with curl

```bash
# Start mcpauth with edge auth enabled (internal auth, dev mode)
go run cmd/main.go -devMode -useInternalAuth -enableEdgeAuth -port 11000 -oauthDomain localhost:11000

# 1. /auth/connect without cookie → redirects to login
curl -v 'http://localhost:11000/auth/connect?callback_port=9999&code=TEST-1234'
# Expect: 307 redirect to /authorize

# 2. /_ws_tunnel without cookie → 401
curl -v http://localhost:11000/_ws_tunnel
# Expect: 401 {"error":"authentication required"}

# 3. /_ws_tunnel with valid CF_Authorization cookie → 200
curl -v -H "Cookie: CF_Authorization=<jwt-from-login-flow>" http://localhost:11000/_ws_tunnel
# Expect: 200 with X-Forwarded-User header

# 4. /auth with CF_Authorization cookie → 200 (fallback token source)
curl -v -H "Cookie: CF_Authorization=<jwt-from-login-flow>" http://localhost:11000/auth
# Expect: 200 with X-Forwarded-User header

# 5. /_ws_tunnel with invalid cookie → 401
curl -v -H "Cookie: CF_Authorization=bad-token" http://localhost:11000/_ws_tunnel
# Expect: 401 {"error":"invalid or expired token"}
```

---


## License

Licensed under the [GNU General Public License v3.0](LICENSE).

