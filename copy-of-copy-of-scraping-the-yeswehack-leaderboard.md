---
icon: spider-web
---

# Copy of Copy of Scraping the YesWeHack Leaderboard

This section describes the pipeline for scraping the all-time leaderboard on YesWeHack. Getting the individual stats from each hunter and their hacktivities. As well as the diagnostics and checking for missing data.

***

## Enumerating the leaderboard

The all-time leaderboard was selected for scraping. To find how it loaded data, DevTools was opened, and the Network tab was checked. Each request was manually inspected to identify which one returned JSON. One of them, https://api.yeswehack.com/ranking?period=All\&page=1, returned the leaderboard data in the following format: \[snippet]. From there, a Python script using the requests library was built to send a GET request to that same URL."

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

Only `username`, `slug`, and `hunter_profile.public` are used. Everything else in the item (`points`, `rank`, `avatar`, `kyc_status`) is discarded at this stage; points/rank are re-fetched per-hunter in Step 2 instead of trusted from this listing.

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

`public: false` hunters get `profile: None` and are permanently excluded from every downstream step.

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

The script reads the `profile` field from `names.json` and derives the API URL by substituting the subdomain directly:

```python
def profile_to_api_url(profile: str) -> str:
    """https://yeswehack.com/hunters/x -> https://api.yeswehack.com/hunters/x"""
    return profile.replace("://yeswehack.com/", "://api.yeswehack.com/", 1)
```

Hunters with `profile: null` are skipped before any request is made:

### Avoiding API rate-limiting error

Requests use a shared `Session`, and 429 responses are retried up to 5 times, using `Retry-After` header when present (falling back to 2 seconds if it's missing):

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
    "name":     name,     
    "joined":   data.get("joined_on"),
    "impact":   float(data.get("impact", 0)),
    "reports":  data.get("nb_reports", 0),
    "points":   data.get("points", 0),
    "rank":     data.get("rank", 0),
    "country":  data.get("nationality"),
}
```

`name` falls back through `public_firstname`/`public_lastname`, then to `username` if both are blank — guaranteeing the field is never empty, so downstream code never has to null-check it.

### The hunter folder structure

A hunter directory is made consisting of the hunter `username` as folder names and their stats inside JSON files.

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

The hunter's name in the created hunter directory filesystem is used to parse each hunter's hacktivity.

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

Preserving `bug_type_raw` and `date_raw` means a parsing bug can be fixed by reparsing the stored raw text, without re-crawling the API.

### Output — `hunters/rabhi/hacktivities.json`

The output is stored inside each hunter's folder. In a JSON file called hacktivities.json

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
This section was added while data preprocessing was being completed
{% endhint %}

During the preprocessing phase, there is a noticeable number of reports that were missing from hacktivities. There was a mismatch with regard to both stats reports from accounts and reports from hacktivities.

## Checking for pagination issues

When `parse_hacktivity.py` was initially created, it writes only the parsed `Entry` list to `hacktivities.json` . It never persists the `pagination` object. That means once the file exists, there is no way to tell whether the scrape genuinely finished or was silently truncated partway through; a truncated output file looks exactly as valid as a complete one.

`hunter_probe.py` exists to close that gap for a single hunter at a time. It reuses the endpoint and retry logic from `parse_hacktivity.py`, but includes pagination, instead of being discarded

```python
API = "https://api.yeswehack.com/v2/hacktivity/{username}"
...
path.write_text(json.dumps(pages), encoding="utf-8")   # raw pages, pagination included
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

`declared` is `pagination.nb_results` — the server's own stated total across every page. `n` is the actual count of rows collected. The script checks if both the row and nb\_results match.

The script was run for each hunter with a mismatch in the stat report and hacktivity report. However, no hunter failed the actual count.

## Missing window for hacktivities

Given that there was still a large amount of missing reports, another hypothesis was that there is a cutoff window for the hacktivities. This was observed when some of the hunters joined in 2023, but their first report was in 2025. Under this hypothesis, it might be possible that some of the reports with a new status have been cut off, but their resolved, closed, or accepted status persisted.

<figure><img src=".gitbook/assets/Screenshot 2026-07-26 000326.png" alt=""><figcaption><p>Every status transition in this hunter's oldest hacktivity rows has a matching new entry</p></figcaption></figure>

<figure><img src=".gitbook/assets/Screenshot 2026-07-26 000721.png" alt=""><figcaption><p>A hypothetical edited row: accepted and closed statuses appear with no matching new entry anywhere in the feed </p></figcaption></figure>

### Manual review of hunters

The ten hunters with the largest error gap were checked individually: for each, the oldest rows of their hacktivity feed were inspected for `resolved`, `closed`, or `accepted` entries that had no matching `new` row anywhere in the feed — the pattern that would indicate a report whose submission event fell outside the scraped history.

**None of the ten hunters showed this pattern.** Every report visible in their feeds, including the oldest ones, had a matching `new` entry. Since the missing reports don't show up anywhere in the feed — not even as an orphaned terminal status.

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

The most consistent explanation is that the gap between the official report count and the visible new count is made up of private submissions: reports that count toward the hunter's official total but were never made public in the hacktivity feed at all, rather than reports that are public but whose earliest event was cut off by the feed's visible window.

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
