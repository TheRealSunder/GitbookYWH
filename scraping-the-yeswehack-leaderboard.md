---
description: >-
  Reverse-engineering a JavaScript-rendered leaderboard into a four-step
  scraping pipeline that produces a structured hunter dataset.
icon: spider-web
---

# Scraping the YesWeHack Leaderboard

A pipeline that turns a JavaScript-rendered leaderboard page into a structured dataset of hunters, their stats, and their bug-disclosure history — plus a checker script that verifies the scrape actually completed.

***

## Finding the API

### The ranking and account pages — a shortcut, then a confirmation

`yeswehack.com/ranking` returns almost no HTML — a `<div id="app">`, a script bundle, nothing else. The leaderboard is drawn by JavaScript after the page loads, which means the data has to arrive over a separate request.

`api.<domain>.com` is a very common convention for splitting a JS frontend from the backend that actually serves data. Recognizing that convention and typing `api.yeswehack.com` directly into the URL bar in place of `yeswehack.com` is a reasonable first guess for a single-page app — and here, it happened to pay off immediately for two pages:

* `yeswehack.com/ranking` → `api.yeswehack.com/ranking?period=All&page=N` returns the raw JSON leaderboard.
* `yeswehack.com/hunters/{slug}` → `api.yeswehack.com/hunters/{slug}` returns the raw JSON hunter profile.

{% hint style="warning" %}
**The `api.` guess is a shortcut, not a method.** It only works because these two pages are top-level routes with a 1:1 mapping between the frontend page and a single backend resource — the URL structures happen to mirror each other. It is not something to rely on in general; it has to be verified, and it does not generalize to every endpoint (see below).
{% endhint %}

The guess was verified properly with DevTools, not left as an assumption:

{% stepper %}
{% step %}
### Open DevTools → Network, before loading the page

Filter to **Fetch/XHR** to drop images, fonts, and analytics noise.
{% endstep %}

{% step %}
### Interact with the page

Load `/ranking`, click a page number, open a hunter's profile. Each interaction fires a distinct request.
{% endstep %}

{% step %}
### Read the request URL, not the response

Version prefixes and endpoint shape are stated in the URL, never inferred.
{% endstep %}

{% step %}
### Confirm against the Response body

Check that the JSON payload actually contains what's rendered on screen (hunter names, points, ranks) before trusting the endpoint.
{% endstep %}
{% endstepper %}

That confirmation also had to filter out a lot of noise. A single page load fires requests to error monitoring (`sessions.bugsnag.com`), chat widgets (`api-iam.eu.intercom.io`), feature-flag services (`feature.yeswehack.com`), and generic account bootstrap calls that repeat on _every_ page regardless of what's on screen (`/user`, `/user/preferences/settings`, `/user/notifications/unread`, `/platform-settings`). None of those are the target — they're discarded by (a) not belonging to the site's own domain, or (b) firing identically on unrelated pages. What's left is checked against the Response body as the final tiebreaker.

### The only header needed

```python
headers = {"User-Agent": "Mozilla/5.0"}
```

No cookie, no bearer token, no CSRF header was required — the ranking and hunter endpoints are unauthenticated.

### Where the shortcut breaks: hacktivity

The hunter's bug-disclosure history ("hacktivity") is **not a page** — it's a widget embedded inside the profile page that lazy-loads its own data only when scrolled. There is no frontend URL for it, so there's nothing for the `api.` substitution to transform.

This endpoint was found the honest way: DevTools open, scroll the hacktivity feed on a profile page, and watch the request that fires at that moment — `api.yeswehack.com/v2/hacktivity/{slug}?page=1&resultsPerPage=10`. Confirmed, again, by checking the Response body against the entries rendered on screen.

{% hint style="info" %}
**Two different discovery methods, honestly attributed.** Ranking and hunter-profile were found by guessing the `api.` convention and then confirming via Network/Fetch. Hacktivity had no shortcut available and was found directly through Network/Fetch, with no guess involved.
{% endhint %}

***

## Step 1 · `name_parser.py` — enumerate the leaderboard

```
GET https://api.yeswehack.com/ranking?period=All&page=N
```

### Input — the raw `/ranking` response (`Codes/ranking.json`)

```json
{
  "pagination": { "page": 1, "nb_pages": 4, "results_per_page": 25, "nb_results": 100 },
  "items": [
    {
      "username": "rabhi",
      "slug": "rabhi",
      "hunter_profile": { "public": true },
      "hunter_nationality": null,
      "points": 84772,
      "rank": 1,
      "kyc_status": "V",
      "avatar": { "...": "..." }
    },
    {
      "username": "Rbcafe",
      "slug": "rbcafe",
      "hunter_profile": { "public": false },
      "points": 18156,
      "rank": 3
    }
  ]
}
```

Only `username`, `slug`, and `hunter_profile.public` are used — everything else in the item (`points`, `rank`, `avatar`, `kyc_status`) is discarded at this stage; points/rank are re-fetched per-hunter in Step 2 instead of trusted from this listing.

Page 1 is fetched first to read `pagination.nb_pages`, then every page from 1 to that total is looped:

```python
response = requests.get(f"{base_url}?period=All&page=1", headers=headers)
total_pages = response.json()["pagination"]["nb_pages"]

for page in range(1, total_pages + 1):
    data = requests.get(f"{base_url}?period=All&page={page}", headers=headers).json()
```

For each hunter in `items`, the script reads `hunter_profile.public` and, only if public, builds a profile link from the server-given `slug`:

```python
hunters.append({
    "username": item["username"],
    "public": item["hunter_profile"]["public"],
    "profile": (
        f"https://yeswehack.com/hunters/{item['slug']}"
        if item["hunter_profile"]["public"]
        else None
    )
})
```

{% hint style="warning" %}
**`username` ≠ `slug`.** `username` is the display name; `slug` is the URL-safe key the server generates (lowercased, de-duplicated on collision — `st0rm_` → `st0rm-1`). The `slug` is used here only to build the `profile` URL string — it is not stored as its own field in the output. Using `item['slug']` rather than `username.lower()` avoids a silent 404 on any hunter whose slug doesn't match a naive lowercase of their username.
{% endhint %}

`public: false` hunters get `profile: None` and are permanently excluded from every downstream step — that flag is the platform's own record of what a user consented to expose.

### Output — `names.json`

```json
[
  { "username": "rabhi",  "public": true,  "profile": "https://yeswehack.com/hunters/rabhi" },
  { "username": "st0rm_", "public": true,  "profile": "https://yeswehack.com/hunters/st0rm-1" },
  { "username": "Rbcafe", "public": false, "profile": null }
]
```

This file is the worklist for `statparse.py`.

***

## Step 2 · `statparse.py` — enrich each hunter

```
GET https://api.yeswehack.com/hunters/{slug}
```

### Input — the raw `/hunters/{slug}` response (`Codes/hunter_account.json`)

```json
{
  "username": "SecurityReapers",
  "slug": "securityreapers",
  "public_firstname": "Muhammad",
  "public_lastname": "Usman",
  "hunter_profile": { "public": true, "...": "..." },
  "points": 7350,
  "nb_reports": 490,
  "rank": 25,
  "impact": "18.42",
  "kyc_status": "V",
  "avatar": { "...": "..." },
  "gpg_key": null,
  "track_records": [ { "...": "..." } ],
  "joined_on": "2023",
  "nationality": "PK"
}
```

`track_records` (linked platforms like HackerOne/Bugcrowd), `gpg_key`, `kyc_status`, and `avatar` are all present in the raw response and all discarded — only the eight fields below are kept.

The current version of this script reads the `profile` field from `names.json` — not the `username` — and derives the API URL by substituting the subdomain directly:

```python
def profile_to_api_url(profile: str) -> str:
    """https://yeswehack.com/hunters/x -> https://api.yeswehack.com/hunters/x"""
    return profile.replace("://yeswehack.com/", "://api.yeswehack.com/", 1)
```

Hunters with `profile: null` are skipped before any request is made:

```python
profile = hunter.get("profile")
if profile is None:
    skipped += 1
    continue
```

### Retry behaviour

Requests use a shared `Session`, and 429 responses are retried up to 5 times, honouring the server's own `Retry-After` header when present (falling back to 2 seconds if it's missing):

```python
for _ in range(max_retries):
    response = session.get(url, timeout=30)
    if response.status_code == 429:
        wait = int(response.headers.get("Retry-After", 2))
        time.sleep(wait)
        continue
    response.raise_for_status()
    break
else:
    raise RuntimeError(f"Gave up on {url} after {max_retries} retries (429).")
```

If retries are exhausted, that hunter is skipped (caught and logged in `main`) rather than crashing the whole run.

### Narrowing the response

```python
return {
    "username": data["username"],
    "name":     name,          # "First Last", or fallback to username if both are blank
    "joined":   data.get("joined_on"),
    "impact":   float(data.get("impact", 0)),   # API sends this as a STRING
    "reports":  data.get("nb_reports", 0),
    "points":   data.get("points", 0),
    "rank":     data.get("rank", 0),
    "country":  data.get("nationality"),
}
```

{% hint style="danger" %}
**`"impact": "18.42"` is a string in the raw response.** Strings sort lexicographically — `"9.5" > "18.42"` — which would silently corrupt any downstream ranking or aggregation. It's cast to `float` once, at ingestion, so every consumer downstream can trust the type.
{% endhint %}

`name` falls back through `public_firstname`/`public_lastname`, then to `username` if both are blank — guaranteeing the field is never empty, so downstream code never has to null-check it.

### The hunter folder structure

```python
hunter_dir = base_dir / username
hunter_dir.mkdir(exist_ok=True)
(hunter_dir / "stats.json").write_text(json.dumps(stats, indent=2, ensure_ascii=False))
```

```
hunters/
├── rabhi/
│   └── stats.json
├── SecurityReapers/
│   └── stats.json
└── ...
```

{% hint style="info" %}
The folder is named by **`username`**, not `slug` — `slug` is only ever used transiently, inside the `profile` → API URL substitution. This directory layout is the entire input to Step 3: `parse_hacktivity.py` reads folder names directly and needs nothing else from `names.json` or the ranking API.
{% endhint %}

### Output — `hunters/SecurityReapers/stats.json`

```json
{
  "username": "SecurityReapers",
  "name": "Muhammad Usman",
  "joined": "2023",
  "impact": 18.42,
  "reports": 490,
  "points": 7350,
  "rank": 25,
  "country": "PK"
}
```

***

## Step 3 · `parse_hacktivity.py` — pull the bug history

```
GET https://api.yeswehack.com/v2/hacktivity/{username}?page=N&resultsPerPage=50
```

### Input — the raw `/v2/hacktivity/{username}` response (`Codes/hunter_hacktivity.json`)

```json
{
  "pagination": { "page": 1, "nb_pages": 293, "results_per_page": 50, "nb_results": 14608 },
  "items": [
    {
      "date": "2026-07-24",
      "status": "resolved",
      "bug_type": {
        "name": "Insecure Direct Object Reference (IDOR) (CWE-639)",
        "slug": "insecure-direct-object-reference-idor-cwe-639",
        "description": "...",
        "link": "https://cwe.mitre.org/data/definitions/639.html",
        "remediation_link": "..."
      },
      "hunter": {
        "username": "rabhi",
        "slug": "rabhi",
        "kyc_status": "V",
        "hunter_profile": { "public": true },
        "avatar": { "...": "..." }
      }
    }
  ]
}
```

`bug_type.description`, `bug_type.link`, `bug_type.remediation_link`, and the entire nested `hunter` object are discarded — the `hunter` block is redundant here since this endpoint is already scoped to one username, and the CWE remediation text isn't part of the dataset this pipeline builds.

### The worklist is the filesystem

```python
hunter_dirs = [p for p in sorted(hunters_root.iterdir()) if p.is_dir()]
for hunter_dir in hunter_dirs:
    username = hunter_dir.name
```

This stage knows nothing about `names.json`, the `public` flag, or the ranking API — it only needs the set of folders Step 2 already created.

### Pagination bound is re-read every page

```json
{ "pagination": { "page": 1, "nb_pages": 293, "results_per_page": 50, "nb_results": 14608 } }
```

A single hunter can have thousands of entries, and `nb_pages` can genuinely shift mid-scrape if a new report lands, so the loop re-reads the bound from every response instead of using a fixed `range`:

```python
while True:
    data = session.get(url).json()
    ...
    if page >= data["pagination"]["nb_pages"]:
        break
    page += 1
```

`resultsPerPage=50` is used instead of the browser's own `10` — nothing forces a scraper to match the UI's page size, and 50 cuts round trips fivefold.

### Splitting the CWE off the bug name

```python
_CWE_RE = re.compile(r"\s*\((CWE-\d+)\)\s*$", re.IGNORECASE)

def _split_bug_type(raw):
    m = _CWE_RE.search(raw)
    if not m:
        return raw, None
    return raw[:m.start()].strip(), m.group(1).upper()
```

{% hint style="warning" %}
Anchoring the pattern to end-of-string (`$`) matters because bug names are full of unrelated parentheses (`(XSS)`, `(IDOR)`). The regex only ever treats a trailing `(CWE-nnn)` as the tag; everything before it is the name, whatever it contains. A row with no CWE returns `None` rather than a fabricated `"CWE-0"`.
{% endhint %}

### Raw and parsed forms are both kept

```python
@dataclass
class Entry:
    date: str
    date_raw: str
    bug_name: str
    cwe: str | None
    bug_type_raw: str
    status: str
```

Preserving `bug_type_raw` and `date_raw` means a parsing bug can be fixed by reparsing the stored raw text, without re-crawling the API.

### Output — `hunters/rabhi/hacktivities.json`

```json
[
  {
    "date": "2026-07-24",
    "date_raw": "2026-07-24",
    "bug_name": "Insecure Direct Object Reference (IDOR)",
    "cwe": "CWE-639",
    "bug_type_raw": "Insecure Direct Object Reference (IDOR) (CWE-639)",
    "status": "Resolved"
  },
  {
    "date": "2026-07-24",
    "date_raw": "2026-07-24",
    "bug_name": "Cross-site Scripting (XSS) - Reflected",
    "cwe": "CWE-79",
    "bug_type_raw": "Cross-site Scripting (XSS) - Reflected (CWE-79)",
    "status": "Closed"
  }
]
```

***

## `hunter_probe.py` — checking that the scrape actually completed

`parse_hacktivity.py` writes only the parsed `Entry` list to `hacktivities.json` — it never persists the `pagination` object. That means once the file exists, there is no way to tell whether the scrape genuinely finished or was silently truncated partway through; a truncated output file looks exactly as valid as a complete one.

`hunter_probe.py` exists to close that gap for a single hunter at a time. It reuses the endpoint and retry logic from `parse_hacktivity.py`, but caches the **raw page blobs**, pagination included, instead of discarding them:

```python
API = "https://api.yeswehack.com/v2/hacktivity/{username}"
...
path.write_text(json.dumps(pages), encoding="utf-8")   # raw pages, pagination included
```

### GATE — is the scrape complete?

```python
if feed.declared is None:
    verdict = "UNKNOWN (no pagination metadata)"
elif n == feed.declared:
    verdict = "PASS"
else:
    verdict = f"FAIL -- {feed.declared - n} rows short"
```

`declared` is `pagination.nb_results` — the server's own stated total across every page. `n` is the actual count of rows collected. If they don't match, the tool says so explicitly and stops there: nothing else is worth reading if the scrape was truncated.

One extra check rides along with a `PASS`: if `declared` lands on a suspiciously round number (100, 500, 1000, 2000, 5000...), it's flagged as a possible server-side cap on the feed rather than a true total — a complete scrape of a capped feed would look identical to a complete scrape of an uncapped one.

### COUNT — how many reports are visible, and how many are missing

```python
n_new = sum(1 for r in rows if r.status == "new")
```

Every report is assumed to enter the feed exactly once via a `new` event, so `n_new` is the estimate of distinct visible reports. If `--official <n>` is supplied (the hunter's officially stated report count), the tool also prints the exact gap:

```python
gap = official - n_new
```

This is where investigation stops being automated and becomes a manual, per-hunter check.

{% hint style="info" %}
**Everything past GATE and COUNT was intentionally removed.** Earlier versions of this script also binned the feed by chronological position and applied an arbitrary statistical threshold (a 15% deviation cutoff, 10 bins by default) to guess whether a report-count gap was caused by left-censoring (old reports whose `new` event fell outside the feed) versus reports that were simply never public. Both the bin count and the 15% threshold were undocumented, arbitrary constants with no principled derivation — not something that holds up if asked "why 15%, why not any other number." That entire hypothesis-testing layer, along with the duplicate-cluster, yearly-density, and status-vocabulary checks, was removed in favor of manual review of the hunters with the largest gaps. `hunter_probe.py` is now strictly a completeness checker for `parse_hacktivity.py`'s output, not a statistical inference tool.
{% endhint %}

### What the manual review found

The ten hunters with the largest `official - n_new` gap were checked individually: for each, the oldest rows of their hacktivity feed were inspected for `resolved`, `closed`, or `accepted` entries that had no matching `new` row anywhere in the feed — the pattern that would indicate a report whose submission event fell outside the scraped history.

**None of the ten hunters showed this pattern.** Every report visible in their feeds, including the oldest ones, had a matching `new` entry. Since the missing reports don't show up anywhere in the feed — not even as an orphaned terminal status — the most consistent explanation is that the gap between the official report count and the visible `new` count is made up of **private submissions**: reports that count toward the hunter's official total but were never made public in the hacktivity feed at all, rather than reports that are public but whose earliest event was cut off by the feed's visible window.

{% hint style="warning" %}
**Open question.** This conclusion rests on ten manually-inspected hunters, not the full dataset. It would be worth confirming whether YesWeHack's hunter-stats page distinguishes public vs. private report counts anywhere directly, which would turn this from an inferred explanation into a verified one.
{% endhint %}

***

## The Result

```
names.json
hunters/
├── rabhi/
│   ├── stats.json
│   └── hacktivities.json
├── SecurityReapers/
│   ├── stats.json
│   └── hacktivities.json
└── ...
```

Every hunter's `stats.json` is also flattened into one CSV (`Codes/hunter_stats.csv`):

```csv
username,joined,impact,reports,points,rank,country
0xd0m7,2019,19.38,180,3233,82,ES
0xsnpaii,2023,13.57,436,5448,45,NG
adibou,2017,23.38,360,7438,24,FR
```

***

## The Reusable Method

{% stepper %}
{% step %}
### Empty HTML source?

The data is arriving over a separate request. Find it.
{% endstep %}

{% step %}
### Try the `api.` convention, but verify it

It's a common shortcut for top-level pages, never a substitute for checking Network/Fetch.
{% endstep %}

{% step %}
### Widgets need their own discovery

A component that lazy-loads on interaction (scroll, click) has no page URL to transform — it has to be caught firing on the wire.
{% endstep %}

{% step %}
### Self-describing pagination? Use the total, re-read every page

Totals can drift mid-scrape; don't assume a fixed range stays valid.
{% endstep %}

{% step %}
### Use server-supplied identifiers verbatim

`slug`, never `username.lower()`.
{% endstep %}

{% step %}
### Honour visibility flags

`public: false` is a consent signal, not an obstacle.
{% endstep %}

{% step %}
### Normalise types and store raw beside parsed

Do it once, at the ingestion boundary.
{% endstep %}

{% step %}
### Let the filesystem be the interface between stages
{% endstep %}

{% step %}
### Preserve whatever metadata lets you check completeness later

A parser that discards its own pagination totals cannot be audited after the fact.
{% endstep %}

{% step %}
### Prefer an exact, falsifiable check over a tuned statistical threshold

An arbitrary percentage cutoff is hard to defend under a follow-up question; a direct count or date comparison isn't.
{% endstep %}
{% endstepper %}
