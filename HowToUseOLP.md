
# 🎟️ Using RSL Tokens with mcpgateway.online

This document explains how to obtain, introspect, and use **RSL tokens** with your own environment (`idp.mcpgateway.online`, `oauth.mcpgateway.online`, and `local-http.mcpgateway.online`). It also covers how license scopes affect what resources are permitted.

---

## 🔗 Key Endpoints

* **Authorization Server Metadata**
  [`https://idp.mcpgateway.online/.well-known/oauth-authorization-server`](https://idp.mcpgateway.online/.well-known/oauth-authorization-server)

  Which points to:

  * `authorization_endpoint`: `https://oauth.mcpgateway.online/authorize`
  * `token_endpoint`: `https://oauth.mcpgateway.online/token`
  * `introspect`: `https://oauth.mcpgateway.online/introspect`
  * `key`: `https://oauth.mcpgateway.online/key`

* **Protected Resource (your local service)**
  `https://local-http.mcpgateway.online/`

---

## 📜 License Format

Your **license.xml** currently allows usage at the **domain root**:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<rsl xmlns="https://rslstandard.org/rsl">
  <content url="https://local-http.mcpgateway.online/" server="https://idp.mcpgateway.online">
    <license>
      <permits type="usage">ai-train</permits>
      <payment type="royalty">
        <standard>https://rslcollective.org/license</standard>
      </payment>
    </license>
  </content>
</rsl>
```

This means *any path* under `https://local-http.mcpgateway.online/` is considered permitted.

---

## ⚙️ Step-by-Step Flow

### 1. Get a Token

```bash
RSL_TOKEN=$(curl -s -u "$CLIENT_ID:$CLIENT_SECRET" \
  -X POST "https://oauth.mcpgateway.online/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=rsl" \
  -d "resource=https://local-http.mcpgateway.online/" \
  --data-urlencode "license=$(cat license.xml)" \
  | jq -r .access_token)

echo "New RSL Token: $RSL_TOKEN"
```

✅ Returns an `rsl_xxx` access token bound to your license.

---

### 2. Introspect the Token (permitted resource)

```bash
curl -s -u "$CLIENT_ID:$CLIENT_SECRET" \
  -X POST "https://oauth.mcpgateway.online/introspect" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "token=$RSL_TOKEN" \
  --data-urlencode "resource=https://local-http.mcpgateway.online/" \
  | jq .
```

✅ Response:

```json
{
  "active": true,
  "permitted": true,
  "resource": "https://local-http.mcpgateway.online/",
  "token_type": "rsl",
  "license": "<xml content ...>"
}
```

---

### 3. Introspect the Token (unauthorized path)

```bash
curl -s -u "$CLIENT_ID:$CLIENT_SECRET" \
  -X POST "https://oauth.mcpgateway.online/introspect" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "token=$RSL_TOKEN" \
  --data-urlencode "resource=https://local-http.mcpgateway.online/unauthorized" \
  | jq .
```

❌ Currently still returns:

```json
"permitted": true,
"resource": "https://local-http.mcpgateway.online/"
```

Because the license covers the root URL.

---

### 4. Retrieve a Key for Encryption/Decryption

For the licensed resource:

```bash
curl -s -u "$CLIENT_ID:$CLIENT_SECRET" \
  -X POST "https://oauth.mcpgateway.online/key" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data-urlencode "token=$RSL_TOKEN" \
  --data-urlencode "resource=https://local-http.mcpgateway.online/" \
  | jq .
```

✅ Returns a JWK (JSON Web Key):

```json
{
  "key": {
    "alg": "A128CTR",
    "k": "IdMiLkBqczuuAS4DFHLH3A",
    "kid": "c2c76979-96b2-46f9-af89-edbcb0ffa190",
    "kty": "oct"
  },
  "resource": "https://local-http.mcpgateway.online/"
}
```

---

## 🚧 What’s Left To Do

1. **License Granularity**
   Right now, the license is bound to the *root URL*.

   * ✅ All paths under `/` are automatically permitted.
   * ❌ You can’t currently deny `/unauthorized` specifically.

   **Next step:** modify `license.xml` to specify multiple `<content>` entries for finer-grained path-level control. Example:

   ```xml
   <content url="https://local-http.mcpgateway.online/" server="https://idp.mcpgateway.online">
     <license>
       <permits type="usage">ai-train</permits>
     </license>
   </content>

   <content url="https://local-http.mcpgateway.online/unauthorized" server="https://idp.mcpgateway.online">
     <license>
       <permits type="usage">none</permits>
     </license>
   </content>
   ```

2. **Resource Server Enforcement**

   * You’ve proven that tokens + introspection work.
   * Now, your **resource server (`local-http`) must enforce** `"permitted": true` vs `"permitted": false`.
   * This typically means checking the token (via introspect) before granting access to a path.

3. **Optional: Automate Renewal**
   Tokens currently return `"expires_in": 0`. You may need a refresh or reissue mechanism for production.

---

## ✅ Summary

* You can mint RSL tokens from `oauth.mcpgateway.online/token`.
* Tokens introspect as valid for `https://local-http.mcpgateway.online/`.
* Since your license is at the domain root, all subpaths are treated as permitted.
* To restrict access by path, update `license.xml` with multiple `<content>` blocks.
* Next, wire up your resource server to enforce these permissions based on introspection results.

## Setting up the webserver for resource

add this to your compose file
```bash

  webserver:
    image: python:3.12.11-slim-bookworm
    volumes:
      - /root/Projects/webserver:/web
    working_dir: /web
    command: bash -c "python3 -m http.server 18000 2>&1"
```

in the /root/Projects/webserver place this file index.html
```
<html>
<head>
  <script type="application/rsl+xml">
    <rsl xmlns="https://rslstandard.org/rsl">
      <content url="" server="https://idp.mcpgateway.online">
        <license>
          <permits type="usage">ai-train</permits>
          <payment type="royalty">
            <standard>https://rslcollective.org/license</standard>
          </payment>
        </license>
      </content>
    </rsl>
  </script>
</head>
<body>
    Licensed content
</body>
</html>
```


# 🔑 How RSL Fits with OAuth

### 1. OAuth as the Framework

At its core, what you’re using is still **OAuth 2.0**.

* There’s an **Authorization Server (AS)**: `https://oauth.mcpgateway.online`
* There’s a **Token Endpoint**: `/token`
* There are **Introspection** and **Key** endpoints
* Your client (`CLIENT_ID` / `CLIENT_SECRET`) authenticates exactly the same way an OAuth client would

So all the transport, client auth, and token issuance machinery is pure OAuth.

---

### 2. Custom Grant Type: `grant_type=rsl`

Normally in OAuth you see:

* `grant_type=authorization_code` (web logins)
* `grant_type=client_credentials` (machine-to-machine)
* etc.

Here, the system defines a **custom grant**:

```
grant_type=rsl
```

That’s how you tell the AS: *“I don’t want a normal OAuth access token, I want an RSL-bound token”*.

This is still perfectly valid under the OAuth spec — custom grants are allowed.

---

### 3. RSL Token = Specialized OAuth Access Token

When you call `/token`, you still get back a token object:

```json
{
  "access_token": "rsl_ec88ac0e-f40f-433e-8060-aebc586f5999",
  "expires_in": 0,
  "token_type": "rsl"
}
```

That looks a lot like OAuth, except:

* The token type is `rsl` instead of `Bearer`.
* The license is embedded and tied to the token.

So from OAuth’s perspective, it just minted you an access token. From the RSL layer’s perspective, that token carries **usage rights**.

---

### 4. Introspection = Standard OAuth Endpoint

OAuth 2.0 defines [RFC 7662](https://datatracker.ietf.org/doc/html/rfc7662) — the Token Introspection spec.
That’s exactly what you’re hitting at `/introspect`.

Normally you’d get back claims like `active`, `scope`, `sub`.
In your case, you get back:

```json
{
  "active": true,
  "permitted": true,
  "resource": "https://local-http.mcpgateway.online/",
  "license": "<xml ...>"
}
```

That’s just a **customized introspection payload**. OAuth doesn’t care what’s inside; it only requires that the AS return token metadata. Here, the metadata happens to be RSL-specific.

---

### 5. Key Endpoint = OAuth Resource

The `/key` endpoint is an OAuth-protected resource itself.
You present:

* Your **client auth** (`-u CLIENT_ID:CLIENT_SECRET`)
* The **RSL token**

And it hands back the symmetric key bound to the resource.
That key is what lets the client and server enforce the licensed usage (e.g., decrypt data, encrypt communication, etc.).

---

### 6. The Resource Server Role

In OAuth language:

* `local-http.mcpgateway.online` is your **Resource Server (RS)**.
* Normally, an RS would check scopes (`scope=read:data`).
* In your case, it calls `/introspect` and checks the **RSL license permissions** (`permitted=true`, `<permits type="usage">ai-train</permits>`).

So instead of “OAuth scopes,” you’ve got “RSL usage rights.”

---

## 🔄 Putting It All Together

* **OAuth AS (Authorization Server)** issues the token.
* **RSL grant** defines how the token is minted (with license embedded).
* **OAuth Introspection** is used to validate the token and check usage rights.
* **Resource Server** enforces those rights.

From the outside world, this still *is* OAuth. You’re just using a **specialized token type (`rsl`)** instead of a generic bearer token.

---

✅ So: **OAuth is the transport and protocol framework.**
📜 **RSL is the semantics of what the token means.**

---

