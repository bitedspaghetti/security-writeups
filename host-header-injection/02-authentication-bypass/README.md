# Authentication Bypass via Host Header Injection

**Severity:** High<br>
**Class:** Host Header Injection -> Authentication Bypass

## Vulnerability Overview

The application relies on the client-supplied `Host` header to perform access control checks for sensitive endpoints, such as the administrative panel (`/admin`). 

When processing requests to administrative routes, the backend implicitly trusts the `Host` header value. If the header is set to `localhost` (or 127.0.0.1), the application assumes the request originated from the local loopback interface and bypasses authentication requirements.

An attacker can exploit this behavior by manually modifying the `Host` header in an HTTP request. This tricks the backend logic into treating external requests as internal traffic:

```python
# Simplified backend access control check
if request.headers.get('Host') == "localhost":
    return render_admin_panel()
else:
    return raise_401_unauthorized()
```

## Steps to reproduce

### 1. Intercept the GET request

Intercept the request using Burp Suite and inspect the HTTP headers.

The request contains a `Host` header identifying the target application:

```http
GET /admin HTTP/2
Host: ID.web-security-academy.net
Cookie: session=; _lab=...
```

Once the request is intercepted, send it to Burp Repeater. Here, we can inspect and modify the target Host header.

Send an initial GET request to /admin to observe the default response.
<img width="1217" height="703" alt="Send-Test-Poc-Request" src="https://github.com/user-attachments/assets/164b14b2-abee-4e19-b1d6-0b092676c786" />

The server returns a `401 Unauthorized` status code. Change the Host header value to localhost to observe the server's behavior.
<img width="1220" height="707" alt="Change-Header-On-localhost" src="https://github.com/user-attachments/assets/bb30352d-8094-486b-bbf4-52c901794765" />

The server responds with a 200 OK status code, confirming that access to /admin has been granted.

<img width="1219" height="664" alt="Analyze-Response" src="https://github.com/user-attachments/assets/cc29a108-2c92-42c2-aef5-dc7c5bc9884e" />
Analyze the response body for deletion endpoints, such as /admin/delete?username=wiener. Modify the request URL to target carlos: /admin/delete?username=carlos.
<img width="1217" height="705" alt="successful-request" src="https://github.com/user-attachments/assets/3f9024a9-5383-4339-87dd-3b9ce91e9313" />
The server responds with a `302 Found` redirection status code, indicating the deletion request was successfully processed.
<img width="980" height="194" alt="Solved-Lab" src="https://github.com/user-attachments/assets/87275428-d190-4d4b-bfec-7bf86bb2c278" />

## Root cause

The backend implicitly trusts the client-controlled `Host` header without
validation and uses its value as part of the access control decision for
administrative endpoints.

The application incorrectly treats `Host: localhost` as proof that the
request originated from the local machine, even though the `Host` header is
controlled by the client.

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to compromise the administrative panel.

* **Unauthorized Administrative Access:** Attackers gain unrestricted access to restricted functionality and internal backend features.
* **Arbitrary User Deletion / Management:** Attackers can invoke privileged actions, such as deleting user accounts, modifying application state, or accessing internal administrative data.
* **Security Control Subversion:** Relying on client-controlled HTTP headers invalidates perimeter security assumptions.

## Remediation

To resolve this issue and prevent Host Header Injection in access control logic:

* **Do Not Rely on Host Headers for Security:** Base access control decisions strictly on authenticated user sessions, roles, or verified server-side network attributes (e.g., actual client IP).
* **Restricted Network Interfaces:** Protect internal endpoints like `/admin` using network-level controls (e.g., firewall rules or internal-only binding) rather than application-level HTTP header inspection.
* **Host Header Whitelisting:** Validate incoming `Host` headers against a strict whitelist of legitimate domains if dynamic header parsing is required.
