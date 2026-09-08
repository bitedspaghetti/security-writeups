# Password Reset Poisoning

**Severity:** High<br>
**Class:** Host Header Injection -> Account Takeover

## Vulnerability overview

The password reset functionality trusted the client-controlled `Host` header
when generating password reset links.

Let's consider a simple example. When a user clicks "Forgot password", the
backend generates a password reset link using the host from the HTTP request:

`https://{Host}/reset?token=...`

In other words, the application takes the `Host` value directly from the
HTTP `Host` header and uses it to construct the reset URL.

Normally, this would look like:

`Host: vulnerable-site.com`

which results in:

`https://vulnerable-site.com/reset?token=...`

However, because the application does not validate the `Host` header, an
attacker can supply their own domain:

`Host: attacker.com`

The application will then generate:

`https://attacker.com/reset?token=...`

If the victim receives this poisoned password reset link and follows it, the
request containing the valid reset token is sent to the attacker-controlled
server. The token can then be obtained from the server's logs and used to
reset the victim's password, potentially resulting in account takeover.

## Steps to reproduce

### 1. Request a password reset

Navigate to the password reset functionality and submit a reset
request for the victim's account.

<img width="1100" height="500" alt="ksnip_20260908-202054" src="https://github.com/user-attachments/assets/33d2a4e6-9794-41b9-8aab-07935c9dcb90" />


### 2. Intercept the password reset request

Intercept the request using Burp Suite and inspect the HTTP headers.

The request contains a `Host` header identifying the target application:

```http
POST /forgot-password HTTP/2
Host: ID.web-security-academy.net
Cookie: session=; _lab=...
```

Once the request is intercepted, send it to Burp Repeater. Here, we can inspect and modify the target Host header.

<img width="1208" height="646" alt="ksnip_20260908-202849" src="https://github.com/user-attachments/assets/ac1afc1e-ac0f-4b48-b4e6-9a7de34d7acd" />

Send a test PoC request to observe the server's response code.

<img width="1207" height="654" alt="ksnip_20260908-203034" src="https://github.com/user-attachments/assets/49956d45-88ff-477b-b67c-b5f185af7c64" />

The server returns a 200 OK HTTP status code, confirming the application accepts the modified Host header without validation.


### 3. Exploitation of a vulnerability

Replace the legitimate host in the Host header with the domain of our exploit server.

<img width="1212" height="659" alt="ksnip_20260908-210901" src="https://github.com/user-attachments/assets/16d747dc-10fa-4bd5-957b-6c0de2d9940b" />


The server responds with a 200 OK status code again, indicating the reset email with the poisoned domain was dispatched.
Once the victim clicks the link, the request is routed to our exploit server, where we can view the access log containing the victim's password reset token.
<img width="1917" height="35" alt="ksnip_20260908-211226" src="https://github.com/user-attachments/assets/e01a4f82-c2b3-4400-9f9e-da8a4a061013" />


Obtain a valid password reset link and replace our token with the victim's token.

<img width="1384" height="29" alt="ksnip_20260908-211416" src="https://github.com/user-attachments/assets/b26aa9b5-1f4d-4528-986f-e969cb56cd39" />


Navigate to the reset page, set a new password for the account, and log in as the victim.

<img width="696" height="555" alt="ksnip_20260908-211501" src="https://github.com/user-attachments/assets/27a3590e-3e43-4dff-a227-69ace53ed2b9" />


After logging in, the lab is successfully completed.

<img width="749" height="577" alt="ksnip_20260908-211554" src="https://github.com/user-attachments/assets/6315e32b-5bbe-46d9-a70f-1ab10d4ad146" />

## Root cause

The backend implicitly trusts the user-supplied Host header without validation, using its value dynamically to construct absolute URLs (e.g password reset links).

## Impact

Successful exploitation of this vulnerability allows an unauthenticated attacker to compromise any user account on the system, including high-privileged administrator accounts.

* **Account Takeover (ATO):** An attacker can hijack target accounts without knowing the original password or possessing credentials.
* **Privilege Escalation:** If an administrative or internal staff account is targeted, the attacker gains full control over the application, administrative interfaces, and backend management functions.
* **Data Confidentiality & Integrity Breach:** Once inside, the attacker accesses sensitive user data, personally identifiable information (PII), and internal resources, with the ability to modify or delete data.
* **Loss of Account Control:** By changing the account's email and password post-compromise, the attacker permanently revokes access from the legitimate owner.

## Remediation — how the issue should actually be fixed

To mitigate Password Reset Poisoning and Host Header Injection, the application must avoid relying on client-controlled HTTP headers when constructing sensitive URLs.

* **Use a Hardcoded Domain Configuration:** Define the canonical base URL in the application’s backend configuration (e.g., `https://example.com` in environment variables) and use it exclusively for building absolute links in emails.
* **Use Server-Side Configuration for Dynamic Hosts:** If dynamic host selection is strictly required for multi-tenant architectures, rely on trusted server-side configuration or tenant-specific data rather than directly using the request's `Host` header.
* **Host Header Whitelisting:** Implement strict server-side validation against a static whitelist of allowed domains if incoming `Host` headers must be accepted.
* **Avoid `X-Forwarded-Host` Trust:** Ensure proxy/reverse-proxy configurations do not implicitly trust client-supplied `X-Forwarded-Host` headers. Only accept this header from trusted proxies and validate it before using it to construct URLs.
