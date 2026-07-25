---
icon: spider-web
---

# Copy of Scraping the YesWeHack Leaderboard

This section describes the YesWeHack all-time leaderboard scraping pipeline. It collects each hunter's statistics and hacktivities and performs diagnostic checks for missing data.

***

## Enumerating the leaderboard

The all-time leaderboard was selected for scraping. DevTools and the Network tab showed how it loaded data. Each request was inspected to identify the JSON response. The following endpoint returned leaderboard data: [https://api.yeswehack.com/ranking?period=All\&page=1.](https://api.yeswehack.com/ranking?period=All\&page=1.) A Python script uses the `requests` library to send a `GET` request to this endpoint.

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

Only `username`, `slug`, and `hunter_profile.public` are used. The script discards `points`, `rank`, `avatar`, and `kyc_status` at this stage.

The script fetches page one to read `pagination.nb_pages`. It then loops through every page:

```python
response = requests.get(f"{base_url}?period=All&page=1", headers=headers)
total_pages = response.json()["pagination"]["nb_pages"]

for page in range(1, total_pages + 1):
    data = requests.get(f"{base_url}?period=All&page={page}", headers=headers).json()
```

For each hunter in `items`, the script reads `hunter_profile.public`. For public profiles, it builds a profile link from the server-provided `slug`:

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

Hunters with `public: false` receive `profile: None`. The pipeline excludes them from all downstream steps.

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

## Getting individual hunter statistics

```
GET https://api.yeswehack.com/hunters/{slug}
```

To get the individual stats of hunters, a script called `statparse.py` was made.

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

The raw response includes `track_records`, `gpg_key`, `kyc_status`, and `avatar`. The script discards these fields. It keeps only the eight fields below.

The script reads `profile` from `names.json`. It derives the API URL by replacing the subdomain:

```python
def profile_to_api_url(profile: str) -> str:
    """https://yeswehack.com/hunters/x -> https://api.yeswehack.com/hunters/x"""
    return profile.replace("://yeswehack.com/", "://api.yeswehack.com/", 1)
```

The script skips hunters with `profile: null` before making a request.

### Avoiding API rate-limiting error

Requests use a shared `Session`. The script retries 429 responses up to five times. It uses the `Retry-After` header when available. Otherwise, it waits two seconds:

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

If retries are exhausted, `main` catches and logs the error. The pipeline skips that hunter and continues.

### Narrowing the response

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

`name` uses `public_firstname` and `public_lastname` when available. If both are blank, it uses `username`. This ensures the field is never empty and removes downstream null checks.

### The hunter folder structure

Each hunter has a directory named after their `username`. The directory stores their statistics in a JSON file.

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

## Parsing the hunter's hacktivity

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

`bug_type.description`, `bug_type.link`, `bug_type.remediation_link`, and the entire nested `hunter` object are discarded.

### The worklist is the filesystem

```python
hunter_dirs = [p for p in sorted(hunters_root.iterdir()) if p.is_dir()]
for hunter_dir in hunter_dirs:
    username = hunter_dir.name
```

The script uses each hunter directory name to parse that hunter's hacktivity.

### Splitting the CWE off the bug name

```python
_CWE_RE = re.compile(r"\s*\((CWE-\d+)\)\s*$", re.IGNORECASE)

def _split_bug_type(raw):
    m = _CWE_RE.search(raw)
    if not m:
        return raw, None
    return raw[:m.start()].strip(), m.group(1).upper()
```

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

The pipeline preserves `bug_type_raw` and `date_raw`. It can fix parsing errors by reparsing stored raw text. It does not need to re-crawl the API.

### Output — `hunters/<hunter_name>/hacktivities.json`

The pipeline stores the output in `hacktivities.json` within each hunter directory.

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

## Confounding report count from stats vs hacktivities

{% hint style="info" %}
This section was added during data preprocessing.
{% endhint %}

During preprocessing, many reports were missing from hacktivities. Account statistics did not match hacktivity report counts.

## Checking for pagination issues

`parse_hacktivity.py` writes only parsed `Entry` values to `hacktivities.json`. It does not store the `pagination` object. A saved file cannot show whether scraping completed or stopped early. A truncated file looks valid.

`hunter_probe.py` closes this gap for one hunter at a time. It reuses the endpoint and retry logic from `parse_hacktivity.py`  while storing pagination:

```python
API = "https://api.yeswehack.com/v2/hacktivity/{username}"
...
path.write_text(json.dumps(pages), encoding="utf-8") 
```

### Checking if the scrape was completed

```python
if feed.declared is None:
    verdict = "UNKNOWN (no pagination metadata)"
elif n == feed.declared:
    verdict = "PASS"
else:
    verdict = f"FAIL -- {feed.declared - n} rows short"
```

`declared` is `pagination.nb_results`, the server's total across all pages. `n` is the collected row count. The script compares these values.

The script ran for every hunter with mismatched statistics and hacktivity counts. No hunter failed the row-count check.

## Missing window for hacktivities

Many reports remained missing. One hypothesis was a hacktivity cutoff window. Some hunters joined in 2023 but had their first visible report in 2025. Their `new` events may have been cut off while `resolved`, `closed`, or `accepted` events remained.

<figure><img src=".gitbook/assets/Screenshot 2026-07-26 000326.png" alt="Oldest hacktivity rows show each status transition paired with a new entry."><figcaption><p>Every status transition in this hunter's oldest hacktivity rows has a matching new entry.</p></figcaption></figure>

<figure><img src=".gitbook/assets/Screenshot 2026-07-26 000721.png" alt="Example of accepted and closed statuses without a matching new entry."><figcaption><p>A hypothetical edited row: accepted and closed statuses have no matching new entry in the feed.</p></figcaption></figure>

### Manual review of hunters

The ten hunters with the largest gaps were checked individually. Their oldest hacktivity rows were inspected for `resolved`, `closed`, or `accepted` entries without a matching `new` row. This pattern would indicate a submission outside the scraped history.

**None of the ten hunters showed this pattern.** Every visible report, including the oldest, had a matching `new` entry. The missing reports do not appear anywhere in the feed. This includes orphaned terminal statuses.

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

### Possible explanation for the confounding report count

The most consistent explanation is private submissions. These reports count toward the official total but never appear in the public hacktivity feed. The gap likely does not result from public reports outside the visible window.

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
