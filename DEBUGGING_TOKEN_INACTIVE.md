# Debugging Token Introspection Issue

## Problem
Tokens are being marked as "inactive" by Keycloak immediately after working successfully:
- 13:22:00 - Token validates successfully (200)
- 13:22:02 - Same token marked inactive (401) - only 2 seconds later!

## Changes Made

Added detailed logging to trace token validation through the system:

### 1. Keycloak Provider (`server/providers/keycloak/keycloak.go`)
- Logs introspection request details:
  - URL being called
  - Client ID used for introspection
  - Token prefix/suffix (first 20 chars, last 10 chars)
  - Token length
- Logs the FULL response from Keycloak's introspection endpoint
- Logs detailed info when token is marked inactive

### 2. Auth Handler (`server/server.go`)
- Logs where token was extracted from (header vs query param)
- Logs token prefix/suffix and length
- Logs when Keycloak introspection is being used
- Logs successful introspection results (email, scopes, expiry)

## What to Look For in Logs

When you reproduce the issue, look for these patterns:

### 1. Token Consistency
Compare the working request vs failing request:
```
[Auth] Token extracted from Authorization header token_prefix="eyJhbGciOiJSUzI1NiIs" token_suffix="7WBOQfVRmw" token_length=2025
```
- Are the prefix, suffix, and length EXACTLY the same?
- If different, the token being sent is different

### 2. Client ID Used for Introspection
```
[Keycloak] Starting token introspection client_id="mcp-server"
```
- Confirm this matches the client_id that issued the token

### 3. Keycloak's Response
Look for the full introspection response:
```json
{
  "active": false,
  "exp": 1769003499,
  "iat": 1769001699,
  "sid": "de12c644-f2a9-4448-0b7a-a666ed15229f",
  ...
}
```

Key fields to check:
- `active`: Should be `true` for valid tokens
- `exp`: Expiration timestamp (should be in the future)
- `iat`: Issued at timestamp
- `sid`: Session ID - does this change between requests?
- Any error fields or additional context

### 4. Timing Pattern
Look at the timestamps:
- When was the token issued?
- When did the first successful validation occur?
- When did the failed validation occur?
- How much time between success and failure?

## Theories to Test

### Theory 1: Session Invalidation
If the `sid` (session ID) field changes or is missing in the failed request, the Keycloak session may have been invalidated.

### Theory 2: Multiple OAuth Flows
You mentioned "disconnect and reconnect in a different chat session". If your MCP client initiates multiple OAuth flows:
- Starting a new flow might invalidate the previous session
- Check Keycloak session settings: Admin Console → Realm Settings → Sessions
  - "SSO Session Idle"
  - "SSO Session Max"
  - Check if "Revoke Refresh Token" is enabled

### Theory 3: Token Type Mismatch
Keycloak might be expecting a refresh token but receiving an access token (or vice versa).

### Theory 4: Client Permissions
Even with matching client_id, check Keycloak client settings:
- Is the client configured as "confidential" or "public"?
- Does it have the right service account roles?
- Check: Clients → mcp-server → Settings → Access Type

## Next Steps

1. **Reproduce the issue** with the new logging enabled
2. **Capture the full logs** including:
   - Token issuance
   - First successful validation
   - Failed validation
3. **Compare**:
   - Token values (prefix/suffix/length)
   - Keycloak responses
   - Session IDs
4. **Check Keycloak Admin Console**:
   - Sessions tab - look for multiple active sessions for your user
   - Events tab - look for SESSION_LOGIN, SESSION_LOGOUT events around the failure time

## Keycloak Settings to Check

Navigate to Keycloak Admin Console → Realm (master) → Realm Settings → Sessions:

- **SSO Session Idle**: How long a session can be idle before expiring
- **SSO Session Max**: Maximum session lifetime regardless of activity
- **Client Session Idle**: Timeout for idle client sessions
- **Client Session Max**: Maximum client session lifetime

Also check: Realm Settings → Tokens:
- **Access Token Lifespan**: Should be 30 minutes (1800 seconds) based on your logs
- **Refresh Token Max Reuse**: Could cause issues if set to 0

## Expected vs Actual Behavior

### Expected:
A token valid for 30 minutes should remain active for its full lifetime.

### Actual:
Token works at T+20s but fails at T+22s (22 seconds after issuance).

### This suggests:
- Not a token expiration issue
- Not a client credentials issue (would fail immediately)
- Likely a session or state management issue
- Possibly related to starting multiple OAuth flows

## How to Rebuild and Run

```bash
# Build
go build -o mcpauth ./cmd/main.go

# Run (adjust environment variables as needed)
./mcpauth
```

The enhanced logging will automatically be included in your output.
