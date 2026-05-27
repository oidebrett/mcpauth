package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
)

const (
	edgeAuthClientID   = "edge-auth-client"
	edgeAuthCookieName = "edge_auth_params"
	cfAuthCookieName   = "CF_Authorization"
	cfAuthTTL          = 24 * time.Hour
)

// edgeAuthConnectHandler handles GET /auth/connect.
// If the CF_Authorization cookie is present and valid, it serves the connect page.
// Otherwise it saves the callback params and redirects to the OAuth login flow.
func (s *Server) edgeAuthConnectHandler(c *gin.Context) {
	callbackPort := c.Query("callback_port")
	code := c.Query("code")

	if callbackPort == "" || code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "callback_port and code are required"})
		return
	}

	// Check for existing CF_Authorization cookie
	cfToken, err := c.Cookie(cfAuthCookieName)
	if err == nil && cfToken != "" {
		// Validate the JWT
		claims, err := validateJWT(cfToken)
		if err == nil {
			email, _ := (*claims)["email"].(string)
			// Derive display name from headers
			gateway := c.GetHeader("X-Forwarded-Host")
			if gateway == "" {
				gateway = c.GetHeader("Host")
			}
			if gateway == "" {
				gateway = s.OAuthDomain
			}

			c.Header("Content-Type", "text/html")
			c.String(http.StatusOK, renderEdgeConnectPage(gateway, callbackPort, cfToken, code, email))
			return
		}
		// Invalid/expired cookie — clear it and restart flow
		log.Warn().Err(err).Msg("[EdgeAuth] CF_Authorization cookie invalid, clearing")
		c.SetCookie(cfAuthCookieName, "", -1, "/", s.CookieDomain, !s.DevMode, true)
	}

	// No valid cookie — save params and redirect to OAuth login
	paramVal := callbackPort + "|" + code
	c.SetCookie(edgeAuthCookieName, paramVal, 600, "/", s.CookieDomain, !s.DevMode, true)

	protocol := "https"
	if s.DevMode {
		protocol = "http"
	}
	redirectURI := fmt.Sprintf("%s://%s/auth/connect/callback", protocol, s.OAuthDomain)

	authorizeURL := fmt.Sprintf("/authorize?client_id=%s&redirect_uri=%s&response_type=code&scope=openid+email",
		edgeAuthClientID, redirectURI)

	c.Redirect(http.StatusTemporaryRedirect, authorizeURL)
}

// edgeAuthConnectCallbackHandler handles GET /auth/connect/callback.
// This is the redirect_uri target after the OAuth login flow completes.
// It mints a CF_Authorization JWT cookie and redirects back to /auth/connect.
func (s *Server) edgeAuthConnectCallbackHandler(c *gin.Context) {
	code := c.Query("code")
	if code == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing authorization code"})
		return
	}

	var email string
	var scopes []string

	// Try external provider session first (stored by callbackHandler)
	sessionData, found := s.Sessions.GetByCode(code)
	if found {
		email = sessionData.Email
		scopes = sessionData.Scopes
		s.Sessions.DeleteCode(code)
	} else if s.UseInternalAuth && s.InternalProvider != nil {
		// Internal auth: exchange the authorization code for tokens
		protocol := "https"
		if s.DevMode {
			protocol = "http"
		}
		redirectURI := fmt.Sprintf("%s://%s/auth/connect/callback", protocol, s.OAuthDomain)

		accessToken, _, err := s.InternalProvider.ExchangeAuthorizationCode(code, edgeAuthClientID, redirectURI)
		if err != nil {
			log.Error().Err(err).Msg("[EdgeAuth] Failed to exchange authorization code")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization code"})
			return
		}

		userInfo, err := s.InternalProvider.GetUserInfo(accessToken.Token)
		if err != nil {
			log.Error().Err(err).Msg("[EdgeAuth] Failed to get user info")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get user info"})
			return
		}

		email, _ = userInfo["email"].(string)
		if scopeList, ok := userInfo["scopes"].([]string); ok {
			scopes = scopeList
		}
	} else {
		log.Warn().Msg("[EdgeAuth] Authorization code not found in session store")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization code"})
		return
	}

	if email == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not determine user email"})
		return
	}

	log.Info().Str("email", email).Msg("[EdgeAuth] User authenticated, minting CF_Authorization JWT")

	// Mint CF_Authorization JWT
	cfToken, err := mintCFAuthorizationJWT(email, scopes, cfAuthTTL)
	if err != nil {
		log.Error().Err(err).Msg("[EdgeAuth] Failed to mint CF_Authorization JWT")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create auth token"})
		return
	}

	// Set the CF_Authorization cookie
	c.SetCookie(cfAuthCookieName, cfToken, int(cfAuthTTL.Seconds()), "/", s.CookieDomain, !s.DevMode, true)

	// Recover callback_port and code from the edge_auth_params cookie
	paramsCookie, err := c.Cookie(edgeAuthCookieName)
	if err != nil || paramsCookie == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "missing edge auth params cookie — please restart the connect flow"})
		return
	}

	parts := strings.SplitN(paramsCookie, "|", 2)
	if len(parts) != 2 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "malformed edge auth params cookie"})
		return
	}
	callbackPort, connectCode := parts[0], parts[1]

	// Clear the params cookie
	c.SetCookie(edgeAuthCookieName, "", -1, "/", s.CookieDomain, !s.DevMode, true)

	// Redirect back to /auth/connect with the original params
	redirectURL := fmt.Sprintf("/auth/connect?callback_port=%s&code=%s", callbackPort, connectCode)
	c.Redirect(http.StatusTemporaryRedirect, redirectURL)
}

// edgeAuthWsTunnelHandler handles forward-auth for /_ws_tunnel.
// Validates the CF_Authorization cookie and returns 200 or 401.
func (s *Server) edgeAuthWsTunnelHandler(c *gin.Context) {
	cfToken, err := c.Cookie(cfAuthCookieName)
	if err != nil || cfToken == "" {
		log.Warn().Msg("[EdgeAuth] /_ws_tunnel: no CF_Authorization cookie")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "authentication required"})
		return
	}

	claims, err := validateJWT(cfToken)
	if err != nil {
		log.Warn().Err(err).Msg("[EdgeAuth] /_ws_tunnel: invalid CF_Authorization JWT")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid or expired token"})
		return
	}

	email, _ := (*claims)["email"].(string)
	if email == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "token missing email claim"})
		return
	}

	log.Info().Str("email", email).Msg("[EdgeAuth] /_ws_tunnel: authenticated")
	c.Header("X-Forwarded-User", email)

	if rawScopes, ok := (*claims)["scopes"]; ok {
		if scopeSlice := toStringSlice(rawScopes); len(scopeSlice) > 0 {
			c.Header("X-Forwarded-Scopes", strings.Join(scopeSlice, " "))
		}
	}

	c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte("authenticated"))
}

// extractCFAuthCookie extracts the CF_Authorization cookie value from the request.
func extractCFAuthCookie(c *gin.Context) string {
	cfToken, err := c.Cookie(cfAuthCookieName)
	if err != nil {
		return ""
	}
	return cfToken
}



// BootstrapClient represents the JSON format for configuring static clients at startup.
type BootstrapClient struct {
	ClientID     string   `json:"client_id"`
	ClientSecret string   `json:"client_secret"`
	ClientName   string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
	Scopes       []string `json:"scopes"`
}

// bootstrapClients registers OAuth clients defined dynamically in the
// MCPAUTH_BOOTSTRAP_CLIENTS environment variable on startup.
func (s *Server) bootstrapClients() error {
	rawClientsJSON := os.Getenv("MCPAUTH_BOOTSTRAP_CLIENTS")
	if rawClientsJSON == "" {
		return nil
	}

	var clients []BootstrapClient
	if err := json.Unmarshal([]byte(rawClientsJSON), &clients); err != nil {
		log.Error().Err(err).Msg("[MCPAuth] Failed to parse MCPAUTH_BOOTSTRAP_CLIENTS JSON")
		return err
	}

	for _, bc := range clients {
		if bc.ClientID == "" || bc.ClientSecret == "" || len(bc.RedirectURIs) == 0 {
			log.Warn().Interface("client", bc).Msg("[MCPAuth] Skipping invalid bootstrap client configuration")
			continue
		}

		// Register in the in-memory client map
		s.Clients[bc.ClientID] = Client{
			ClientID:     bc.ClientID,
			ClientName:   bc.ClientName,
			RedirectURIs: bc.RedirectURIs,
		}

		if s.UseInternalAuth && s.ClientService != nil {
			scopes := bc.Scopes
			if len(scopes) == 0 {
				scopes = []string{"openid", "email", "profile"}
			}
			_, err := s.ClientService.CreateClientWithIDAndSecret(
				bc.ClientID,
				bc.ClientSecret,
				bc.ClientName,
				bc.RedirectURIs,
				scopes,
			)
			if err != nil {
				return fmt.Errorf("failed to register bootstrap client %s: %w", bc.ClientID, err)
			}
			log.Info().Str("client_id", bc.ClientID).Msg("[MCPAuth] Successfully registered bootstrap client in database")
		}
	}

	return nil
}

// renderEdgeConnectPage renders the styled confirmation page with the token embedded.
func renderEdgeConnectPage(gatewayAddr, callbackPort, cfToken, code, email string) string {
	escapedToken := escapeJSString(cfToken)
	escapedCode := escapeJSString(code)
	escapedEmail := escapeHTMLAttr(email)
	escapedGateway := escapeHTMLAttr(gatewayAddr)

	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Connect to Gateway</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'SF Mono', 'Fira Code', 'JetBrains Mono', monospace;
            background: #f5f5f5;
            color: #1a1a1a;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .card {
            background: #ffffff;
            border: 1px solid #e0e0e0;
            border-radius: 12px;
            padding: 48px;
            max-width: 480px;
            width: 100%%;
            text-align: center;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
        }
        .logo {
            font-size: 28px;
            font-weight: 700;
            color: #76b900;
            margin-bottom: 8px;
            letter-spacing: -0.5px;
        }
        .subtitle {
            color: #666;
            font-size: 14px;
            margin-bottom: 32px;
        }
        .info {
            background: #fafafa;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 24px;
            text-align: left;
        }
        .info-row {
            display: flex;
            justify-content: space-between;
            padding: 6px 0;
            font-size: 13px;
        }
        .info-label { color: #888; }
        .info-value {
            color: #333;
            font-weight: 500;
            word-break: break-all;
            text-align: right;
            max-width: 60%%;
        }
        .code-box {
            background: #fafafa;
            border: 2px solid #76b900;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 24px;
        }
        .code-label {
            color: #666;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 8px;
        }
        .code-value {
            font-size: 32px;
            font-weight: 700;
            color: #76b900;
            letter-spacing: 4px;
        }
        .code-hint {
            color: #888;
            font-size: 11px;
            margin-top: 8px;
        }
        .connect-btn {
            background: #76b900;
            color: #ffffff;
            border: none;
            border-radius: 8px;
            padding: 14px 32px;
            font-size: 15px;
            font-weight: 600;
            font-family: inherit;
            cursor: pointer;
            width: 100%%;
            transition: background 0.15s;
        }
        .connect-btn:hover { background: #8ad100; }
        .connect-btn:active { background: #6aa000; }
        .connect-btn:disabled {
            background: #ccc;
            color: #888;
            cursor: not-allowed;
        }
        .hint {
            color: #888;
            font-size: 12px;
            margin-top: 16px;
        }
        .status {
            margin-top: 16px;
            font-size: 13px;
            min-height: 20px;
        }
        .status-ok { color: #76b900; }
        .status-err { color: #d32f2f; }
    </style>
</head>
<body>
    <div class="card">
        <div class="logo">MCPAuth</div>
        <div class="subtitle">Connect to Gateway</div>
        <div class="code-box">
            <div class="code-label">Confirmation Code</div>
            <div class="code-value">%s</div>
            <div class="code-hint">Verify this matches the code shown in your terminal</div>
        </div>
        <div class="info">
            <div class="info-row">
                <span class="info-label">Gateway</span>
                <span class="info-value">%s</span>
            </div>
            <div class="info-row">
                <span class="info-label">User</span>
                <span class="info-value">%s</span>
            </div>
        </div>
        <button class="connect-btn" id="connectBtn" onclick="connect()">
            Connect to Gateway
        </button>
        <div class="hint">
            This will authorize the CLI to connect to this gateway.
        </div>
        <div class="status" id="status"></div>
    </div>
    <script>
        var token = '%s';
        var code = '%s';
        var port = %s;
        function connect() {
            var btn = document.getElementById('connectBtn');
            var status = document.getElementById('status');
            btn.disabled = true;
            btn.textContent = 'Connecting...';
            status.textContent = '';
            status.className = 'status';

            fetch('http://127.0.0.1:' + port + '/callback', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ token: token, code: code })
            })
            .then(function(resp) { return resp.json(); })
            .then(function(data) {
                if (data.ok) {
                    btn.textContent = 'Connected';
                    status.className = 'status status-ok';
                    status.textContent = 'Connected! You can close this tab.';
                } else {
                    btn.disabled = false;
                    btn.textContent = 'Connect to Gateway';
                    status.className = 'status status-err';
                    status.textContent = data.error || 'Connection failed. Please try again.';
                }
            })
            .catch(function(err) {
                btn.disabled = false;
                btn.textContent = 'Connect to Gateway';
                status.className = 'status status-err';
                status.textContent = 'Could not reach the CLI. Is it still running?';
            });
        }
    </script>
</body>
</html>`, escapedCode, escapedGateway, escapedEmail, escapedToken, escapedCode, callbackPort)
}

// renderEdgeWaitingPage renders a waiting/authenticating page with auto-refresh.
func renderEdgeWaitingPage(callbackPort, code string) string {
	safeCode := escapeHTMLAttr(code)
	return fmt.Sprintf(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta http-equiv="refresh" content="2;url=/auth/connect?callback_port=%s&amp;code=%s">
    <title>Authenticating</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'SF Mono', 'Fira Code', 'JetBrains Mono', monospace;
            background: #f5f5f5;
            color: #1a1a1a;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .card {
            background: #ffffff;
            border: 1px solid #e0e0e0;
            border-radius: 12px;
            padding: 48px;
            max-width: 480px;
            width: 100%%;
            text-align: center;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
        }
        .logo {
            font-size: 28px;
            font-weight: 700;
            color: #76b900;
            margin-bottom: 8px;
        }
        .message {
            color: #666;
            font-size: 14px;
            margin-top: 16px;
        }
        .spinner {
            margin: 24px auto;
            width: 32px;
            height: 32px;
            border: 3px solid #e0e0e0;
            border-top-color: #76b900;
            border-radius: 50%%;
            animation: spin 0.8s linear infinite;
        }
        @keyframes spin {
            to { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="card">
        <div class="logo">MCPAuth</div>
        <div class="spinner"></div>
        <div class="message">Authenticating...</div>
    </div>
</body>
</html>`, callbackPort, safeCode)
}

// escapeJSString escapes a string for safe embedding in a JS string literal.
func escapeJSString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `'`, `\'`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, `<`, `\x3c`)
	s = strings.ReplaceAll(s, `>`, `\x3e`)
	return s
}

// escapeHTMLAttr escapes a string for safe embedding in an HTML attribute or content.
func escapeHTMLAttr(s string) string {
	s = strings.ReplaceAll(s, `&`, `&amp;`)
	s = strings.ReplaceAll(s, `"`, `&quot;`)
	s = strings.ReplaceAll(s, `'`, `&#x27;`)
	s = strings.ReplaceAll(s, `<`, `&lt;`)
	s = strings.ReplaceAll(s, `>`, `&gt;`)
	return s
}
