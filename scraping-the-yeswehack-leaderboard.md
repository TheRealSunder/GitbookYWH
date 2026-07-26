---
description: >-
  How the YesWeHack all-time leaderboard, hunter profiles, and public hacktivity
  feeds were collected and validated.
hidden: true
icon: spider-web
---

# Scraping the YesWeHack Leaderboard

This page documents the YesWeHack all-time leaderboard collection pipeline. It covers leaderboard enumeration, profile statistics, public hacktivity feeds, and completeness checks.

***

## 1. Enumerate the leaderboard

The pipeline uses the all-time leaderboard. DevTools identified the request that returns leaderboard JSON:

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

The pipeline retains only `username`, `slug`, and `hunter_profile.public`. It discards `points`, `rank`, `avatar`, and `kyc_status`. It fetches points and rank again for each hunter in the next stage.

The pipeline fetches page 1 to read `pagination.nb_pages`. It then fetches every page through that total:

```python
response = requests.get(f"{base_url}?period=All&page=1", headers=headers)
total_pages = response.json()["pagination"]["nb_pages"]

for page in range(1, total_pages + 1):
    data = requests.get(f"{base_url}?period=All&page={page}", headers=headers).json()
```

For each item, the script reads `hunter_profile.public`. It builds a profile URL from the server-provided `slug` only for public hunters:

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

Hunters with `public: false` receive `profile: None`. The pipeline excludes them from all later stages.

### Output — `names.json`

```json
[
  { "username": "rabhi",  "public": true,  "profile": "https://yeswehack.com/hunters/rabhi" },
  { "username": "st0rm_", "public": true,  "profile": "https://yeswehack.com/hunters/st0rm-1" },
  { "username": "Rbcafe", "public": false, "profile": null }
]
```

`names.json` is the worklist for `statparse.py`.

***

## 2. Collect individual hunter statistics

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

The response includes `track_records`, `gpg_key`, `kyc_status`, and `avatar`. The pipeline discards those fields and retains the eight fields below.

The script reads `profile` from `names.json`. It derives the API URL by replacing the subdomain:

```python
def profile_to_api_url(profile: str) -> str:
    """https://yeswehack.com/hunters/x -> https://api.yeswehack.com/hunters/x"""
    return profile.replace("://yeswehack.com/", "://api.yeswehack.com/", 1)
```

The script skips hunters with `profile: null` before making a request.

### Handle rate-limit responses

Requests share a `Session`. The script retries HTTP 429 responses up to five times. It uses the `Retry-After` header when available, or waits two seconds otherwise:

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

If retries are exhausted, `main` logs and skips that hunter. The remaining collection continues.

### Retain profile fields

```python
return {
    "username": data["username"],
    "name":     name,     
    "joined":   data.get("joined_on"),
    "impact":   float(data.get("impact", 0)),
    "reports":  data.get("nb_reports", 0),
    "points":   data.get("points", 0),
    "rank":     data.get("rank", 0),
    "country":  data.get("nationality"),
}
```

`name` uses `public_firstname` and `public_lastname` when present. It falls back to `username` when both fields are blank. This keeps `name` non-empty for downstream processing.

### Store profile statistics

The pipeline creates one directory per hunter. Each directory uses the hunter's `username` and stores profile statistics in JSON:

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

## 3. Parse public hacktivity

```
GET https://api.yeswehack.com/v2/hacktivity/{username}?page=N&resultsPerPage=50
```

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

The pipeline discards `bug_type.description`, `bug_type.link`, `bug_type.remediation_link`, and the nested `hunter` object.

### Use the filesystem as the worklist

```python
hunter_dirs = [p for p in sorted(hunters_root.iterdir()) if p.is_dir()]
for hunter_dir in hunter_dirs:
    username = hunter_dir.name
```

The pipeline uses each hunter directory name to request that hunter's hacktivity feed.

### Separate the CWE from the bug name

```python
_CWE_RE = re.compile(r"\s*\((CWE-\d+)\)\s*$", re.IGNORECASE)

def _split_bug_type(raw):
    m = _CWE_RE.search(raw)
    if not m:
        return raw, None
    return raw[:m.start()].strip(), m.group(1).upper()
```

### Retain raw and parsed values

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

`bug_type_raw` and `date_raw` preserve the source values. A parsing defect can therefore be fixed without collecting the API again.

### Output — `hunters/rabhi/hacktivities.json`

The pipeline stores each hunter's output as `hacktivities.json` in their directory:

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

## 4. Reconcile profile and hacktivity report counts

{% hint style="info" %}
This reconciliation was added during data preprocessing.
{% endhint %}

Profile statistics and hacktivity feeds report different totals. The following checks determine whether incomplete pagination caused the difference.

### Check pagination completeness

The original `parse_hacktivity.py` writes only parsed `Entry` records to `hacktivities.json`. It does not retain the `pagination` object. A truncated file therefore looks the same as a complete file.

`hunter_probe.py` addresses this limitation for one hunter at a time. It reuses the endpoint and retry logic from `parse_hacktivity.py`, but retains pagination metadata:

```python
API = "https://api.yeswehack.com/v2/hacktivity/{username}"
...
path.write_text(json.dumps(pages), encoding="utf-8")   # raw pages, pagination included
```

#### Determine whether a scrape completed

```python
if feed.declared is None:
    verdict = "UNKNOWN (no pagination metadata)"
elif n == feed.declared:
    verdict = "PASS"
else:
    verdict = f"FAIL -- {feed.declared - n} rows short"
```

`declared` is `pagination.nb_results`, the server's total across all pages. `n` is the number of collected rows. The script compares the two values.

The probe ran for every hunter with mismatched profile and hacktivity totals. Every probe passed the row-count check.

### Test the visible-history hypothesis

The remaining discrepancy suggested a possible visible-history cutoff. Some hunters joined in 2023, but their earliest visible report is from 2025. Under this hypothesis, older `new` events might be absent while later `resolved`, `closed`, or `accepted` events remain.

<figure><img src=".gitbook/assets/Screenshot 2026-07-26 000326.png" alt="A hunter&#x27;s oldest hacktivity rows, where every status transition has a matching new entry."><figcaption><p>Every status transition in this hunter's oldest hacktivity rows has a matching new entry</p></figcaption></figure>

<figure><img src=".gitbook/assets/Screenshot 2026-07-26 000721.png" alt="A hypothetical hacktivity row with accepted and closed statuses but no matching new entry."><figcaption><p>A hypothetical edited row: accepted and closed statuses appear with no matching new entry anywhere in the feed</p></figcaption></figure>

#### Review high-discrepancy hunters

The ten hunters with the largest discrepancies were reviewed individually. For each hunter, the oldest rows were checked for `resolved`, `closed`, or `accepted` entries without a matching `new` event. That pattern would indicate a submission outside the visible history.

**None of the ten hunters showed this pattern.** Every visible report, including the oldest rows, had a matching `new` event. The missing reports do not appear as orphaned terminal-status events.

* truff
* wlayzz
* kuromatae
* Al7eX
* Icare
* Sicarius
* Vozec
* Lodeus
* effrite
* Edra

### Likely explanation

The evidence supports private submissions as the most likely explanation. These reports count toward the official profile total but never appear in the public hacktivity feed. The data does not support a visible-history cutoff.

***

## 5. Result

The collection pipeline produces a public-hunter worklist and per-hunter profile and hacktivity files:

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
