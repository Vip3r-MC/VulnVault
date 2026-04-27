# Server-Side Request Forgery via Unvalidated URL Parameter

| Field    | Detail                                 |
|----------|----------------------------------------|
| Project  | Bulwark                                |
| Severity | 🟡 Medium                              |
| OWASP    | A10:2021 - Server-Side Request Forgery |
| Date     | 2026-04-27                             |

## Affected Files

- `lib/auth/verify-jmap-auth.ts`
- `app/api/auth/stalwart-context/route.ts`

## Description

The `/api/auth/stalwart-context` endpoint accepts a user-supplied `serverUrl` and uses it to perform outbound `fetch` requests without validating whether the target resolves to a private or internal IP address.

An attacker can supply a `serverUrl` pointing to internal infrastructure such as `localhost`, cloud metadata endpoints like `169.254.169.254`, or any RFC-1918 address. The server will make requests to those targets, allowing an attacker to probe and interact with services that should not be externally reachable.

## Proof of Concept

> **Warning:** For responsible disclosure purposes only. Do not use against systems you do not own.



https://github.com/user-attachments/assets/f0ecc159-a4f9-4fb1-ba44-605086c1c784



```http
POST /api/auth/stalwart-context HTTP/1.1
Content-Type: application/json{
"serverUrl": "http://169.254.169.254/latest/meta-data/",
"username": "any",
"authHeader": "Bearer any-token"
}
```

The server fetches the target URL and processes the response, leaking internal service data or enabling further chained attacks.

## Impact

- Enumeration of internal services and open ports on the host network
- Access to cloud provider metadata endpoints (AWS IMDSv1, GCP, Azure), potentially leaking IAM credentials
- Interaction with internal APIs, databases, or admin panels not exposed to the internet
- Foundation for the authentication bypass described in the related advisory

## Recommended Fix

In `lib/auth/verify-jmap-auth.ts`, resolve the hostname of any user-supplied URL before making a fetch request and reject it if it resolves to a private or loopback address. Reuse the existing DNS-resolution and blocklist logic already present in the `fetch-ical` endpoint.

```ts
import dns from 'dns/promises';
import { isPrivateIP } from './ip-utils';async function isSafeUrl(url: string): Promise<boolean> {
const { hostname } = new URL(url);
const { address } = await dns.lookup(hostname);
return !isPrivateIP(address);
}
```
Block the following ranges at minimum:

| Range            | Description       |
|------------------|-------------------|
| `127.0.0.0/8`    | Loopback          |
| `10.0.0.0/8`     | Private Class A   |
| `172.16.0.0/12`  | Private Class B   |
| `192.168.0.0/16` | Private Class C   |
| `169.254.0.0/16` | Link-local / IMDS |
| `::1`            | IPv6 loopback     |
| `fc00::/7`       | IPv6 ULA          |

Add integration tests confirming that requests to `localhost`, `127.0.0.1`, and RFC-1918 ranges are rejected with an appropriate error from all endpoints that accept user-supplied URLs.

## Credits

Discovered and reported by **Michael Chesang (Vip3r-MC)**.

## References

- [OWASP A10:2021 - Server-Side Request Forgery](https://owasp.org/Top10/A10_2021-Server-Side_Request_Forgery_%28SSRF%29/)
- [PortSwigger: SSRF Attacks](https://portswigger.net/web-security/ssrf)
- Related: [Admin Authentication Bypass via Attacker-Controlled JMAP Server](./priv-esc-bulwarkmail.md)
