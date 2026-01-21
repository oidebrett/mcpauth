# JWT Validation Solution - Resolving Cross-Client Introspection Issue

## Executive Summary

Your instinct was **100% correct**. The issue is a well-documented OAuth 2.0 security behavior where Keycloak returns `{"active": false}` when a token issued to one client is introspected by a different client. We've implemented **local JWT validation** as the recommended solution.

## What Was Happening

### The Problem

1. **MCP Client** (client_id: `mcp-server`) obtains a token from Keycloak
2. **Your forward auth middleware** (mcpauth) tries to introspect the token using its own client credentials
3. **Keycloak sees**: "Token issued to `mcp-server`, but introspection request is from `<mcpauth-client-id>`"
4. **Keycloak returns**: `{"active": false}` for security reasons
5. **Result**: Valid tokens are rejected

### Why This Happens

According to the [OAuth 2.0 specification](https://devforum.okta.com/t/introspection-endpoint-should-work-for-tokens-issued-by-different-client/13587):

> "When the token was issued to a different client than is making this request, it should be considered an 'inactive' token"

This is **by design** - not a bug. It's a security feature to prevent unauthorized clients from checking arbitrary tokens.

### Known Issues

- [Keycloak cross-client introspection commonly returns false](https://github.com/keycloak/keycloak/discussions/35463)
- [Keycloak 26.2.0+ has a regression](https://github.com/keycloak/keycloak/issues/39599) with session-based introspection
- [Token introspection always fails with {"active":false}](https://github.com/Nerzal/gocloak/issues/106) for different clients

## The Solution: Local JWT Validation

We've implemented **local JWT validation** which is the **industry-standard approach** used by most production systems.

### What Changed

**Before (Introspection):**
```go
// Made network call to Keycloak for EVERY request
tokenInfo, err := KeycloakProvider.IntrospectToken(token)
```

**After (JWT Validation):**
```go
// Validates locally using cached public keys
tokenInfo, err := KeycloakProvider.ValidateJWT(token)
```

### How It Works

1. **Fetches Keycloak's public keys** (JWKS) from:
   ```
   https://keycloak.mcpgateway.online/realms/master/protocol/openid-connect/certs
   ```

2. **Verifies the JWT signature** locally using RSA public key cryptography

3. **Validates claims**:
   - `exp` (expiration) - Token must not be expired
   - `iss` (issuer) - Must match Keycloak
   - `aud` (audience) - Must match configured MCP server URL
   - Scopes and roles

4. **Caches public keys** for 10 minutes (respects Keycloak's cache headers)

### Benefits

According to [Keycloak JWT validation documentation](https://skycloak.io/blog/how-to-verify-a-keycloak-issued-access-token-on-the-backend/):

| Feature | Introspection | JWT Validation |
|---------|---------------|----------------|
| **Performance** | Network call per request | Local validation (fast) |
| **Reliability** | Fails if Keycloak is down | Works offline |
| **Scalability** | High load on Keycloak | Minimal load |
| **Cross-client** | ❌ Fails with different clients | ✅ Works |
| **Real-time revocation** | ✅ Immediate | ❌ Valid until expiry |

## Trade-off: Token Revocation

From the [comparison article](https://medium.com/@kspoyraz7/keycloak-spring-boot-security-with-jwt-decoder-vs-introspection-methods-f6edc8b899f6):

> "When using the JWT decoder method, even if the session on Keycloak is deleted, API calls continue to be processed successfully until the token expires."

### What This Means

- **Introspection**: Real-time session validation, but has cross-client issues and performance overhead
- **JWT Validation**: Fast and reliable, but tokens remain valid until natural expiration (30 minutes in your case)

### Why JWT Validation is Still Preferred

1. **OAuth tokens should have short lifetimes** (yours is 30 minutes - perfect)
2. **Real-time revocation is rarely needed** - most use cases don't require immediate invalidation
3. **Performance and reliability matter more** - especially for high-traffic APIs
4. **Industry standard** - This is how JWT is designed to work

### When You Might Need Introspection

Only if you have strict security requirements requiring:
- Immediate token revocation (logout must terminate all active sessions instantly)
- Real-time session validation
- Compliance requirements for continuous validation

In those cases, you'd need to:
- Use the same client_id for both issuing and introspecting tokens
- OR grant special service account roles to the introspecting client
- Accept the performance overhead and cross-client limitations

## Implementation Details

### What Was Added

1. **JWKS Cache Structure** (`server/providers/keycloak/keycloak.go`):
   ```go
   type jwksCache struct {
       keys        map[string]*rsa.PublicKey
       lastFetched time.Time
       ttl         time.Duration  // 10 minutes
       jwksURL     string
   }
   ```

2. **JWT Validation Method**:
   - Parses JWT header to extract `kid` (key ID)
   - Fetches/caches public key from JWKS endpoint
   - Verifies RSA signature using SHA256
   - Validates all required claims
   - Returns TokenInfo with user details

3. **Updated Auth Handler** (`server/server.go`):
   ```go
   // Changed from IntrospectToken to ValidateJWT
   tokenInfo, err := s.KeycloakProvider.ValidateJWT(token)
   ```

### Logging

The new implementation includes detailed logging:

```
[Keycloak] Starting JWT validation (local, no introspection)
[Keycloak] JWT header parsed kid=<key-id> alg=RS256
[Keycloak] Fetching JWKS (first time or expired cache)
[Keycloak] JWKS fetched successfully key_count=2
[Keycloak] JWT signature verified successfully
[Keycloak] JWT validation successful email=admin scopes=[openid mcp:tools profile email]
```

Subsequent requests will show:
```
[Keycloak] Using cached public key
```

## Deployment

### Docker Image

**Image**: `oideibrett/mcpauth:dev`
**Latest Digest**: `sha256:361f2ae28b46ea35caab5f495e1d20c207dad93216d72f9e01cbb2c5e8817637`

### Bug Fix (2026-01-21 16:20)

**Issue**: Initial implementation had a bug in RSA signature verification - was passing `0` instead of `crypto.SHA256` as the hash algorithm.

**Fixed**: Updated `rsa.VerifyPKCS1v15()` call to correctly specify SHA256:
```go
// Before (broken):
rsa.VerifyPKCS1v15(publicKey, 0, hashed[:], signatureBytes)

// After (fixed):
rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashed[:], signatureBytes)
```

**Error seen**: `crypto/rsa: verification error` during JWT validation

**Status**: ✅ Fixed in latest image

### To Deploy

```bash
# Pull the new image
docker pull oideibrett/mcpauth:dev

# Restart your container
docker-compose restart mcpauth
# OR
docker restart <container-name>
```

### No Configuration Changes Required

The implementation automatically uses JWT validation when `UseKeycloak` is enabled. Your existing environment variables work as-is:

```bash
PROVIDER=keycloak
CLIENT_ID=mcp-server
CLIENT_SECRET=<your-secret>
KEYCLOAK_AUTH_HOST=keycloak.mcpgateway.online
KEYCLOAK_REALM=master
```

## Testing

### What to Expect

1. **First request**: Will fetch JWKS from Keycloak (one-time network call)
   ```
   [Keycloak] Fetching JWKS
   [Keycloak] JWKS fetched successfully
   ```

2. **Subsequent requests**: Use cached public keys (instant validation)
   ```
   [Keycloak] Using cached public key
   [Keycloak] JWT validation successful
   ```

3. **After 10 minutes**: Cache expires, refetches JWKS automatically

### Expected Behavior Changes

- ✅ **Tokens will now work** across different OAuth clients
- ✅ **Much faster validation** (no network call per request)
- ✅ **More reliable** (works even if Keycloak is temporarily unavailable)
- ⚠️ **Tokens remain valid until expiration** even if Keycloak session is terminated

### Testing the Fix

1. **Start a new chat session** in your MCP client
2. **Authenticate** and get a new token
3. **Try using the MCP server** - should work immediately
4. **Disconnect and reconnect** - tokens should remain valid for their full 30-minute lifetime

## Alternative Approaches (If JWT Validation Isn't Suitable)

If you absolutely need real-time introspection despite the cross-client issues:

### Option 1: Same Client Credentials (Simplest)

Configure mcpauth to use the **same client_id** (`mcp-server`) for introspection:

```bash
CLIENT_ID=mcp-server  # Same as MCP client
CLIENT_SECRET=<same-secret>
```

**Pros**: Simple, will work immediately
**Cons**: Less secure (both systems share credentials), not architecturally clean

### Option 2: Service Account Roles (Complex)

Grant your mcpauth client special [service account roles](https://docs.redhat.com/en/documentation/red_hat_build_of_keycloak/22.0/html/authorization_services_guide/service_overview) in Keycloak. Note: This is for UMA (User-Managed Access) and may not apply to standard OAuth tokens.

### Option 3: Hybrid Approach

Use JWT validation as primary, with optional introspection for critical operations:

```go
// Fast path - JWT validation
tokenInfo, err := ValidateJWT(token)
if err != nil {
    return unauthorized
}

// Slow path - only for sensitive operations
if criticalOperation {
    active, err := IntrospectToken(token)
    if !active {
        return forbidden
    }
}
```

## References

- [Cross-client introspection issue in Keycloak](https://github.com/keycloak/keycloak/discussions/35463)
- [Keycloak JWT validation guide](https://skycloak.io/blog/how-to-verify-a-keycloak-issued-access-token-on-the-backend/)
- [JWT vs Introspection comparison](https://medium.com/@kspoyraz7/keycloak-spring-boot-security-with-jwt-decoder-vs-introspection-methods-f6edc8b899f6)
- [OAuth 2.0 introspection specification behavior](https://devforum.okta.com/t/introspection-endpoint-should-work-for-tokens-issued-by-different-client/13587)
- [Keycloak 26.2.0 introspection regression](https://github.com/keycloak/keycloak/issues/39599)

## Support

If you encounter any issues:

1. **Check logs** for JWT validation details
2. **Verify JWKS endpoint** is accessible:
   ```bash
   curl https://keycloak.mcpgateway.online/realms/master/protocol/openid-connect/certs
   ```
3. **Confirm token format** - should be a JWT (three parts separated by dots)
4. **Check Keycloak public key rotation** - keys are cached for 10 minutes

## Summary

✅ **Implemented local JWT validation** - the industry-standard approach
✅ **Resolves cross-client introspection issues** - works regardless of client_id
✅ **Better performance** - no network call per request
✅ **Higher reliability** - works even if Keycloak is temporarily down
✅ **Production-ready** - this is how most OAuth systems operate
⚠️ **Trade-off**: Tokens valid until natural expiration (30 minutes)

This is the **recommended solution** for your use case.
