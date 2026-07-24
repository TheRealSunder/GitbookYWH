# Source Scripts

## Overview

This page holds the current Python scripts behind each stage of the analysis — parsing, preprocessing, statistical inference, reports-to-points, and Shannon entropy. Expand a script below to read its full source and a short description of what it does.

## Parsing

<details>

<summary>name_parser.py — enumerate the leaderboard</summary>

Pages through `GET /ranking?period=All&page=N`, recording each hunter's username, public/private profile flag, and profile URL. Writes the result to `names.json` — the worklist every later stage consumes.

```python
import json
from pathlib import Path

import requests

headers = {
    "User-Agent": "Mozilla/5.0"
}

base_url = "https://api.yeswehack.com/ranking"

hunters = []

# Get the first page to determine the total number of pages
response = requests.get(
    f"{base_url}?period=All&page=1",
    headers=headers
)

response.raise_for_status()
data = response.json()

total_pages = data["pagination"]["nb_pages"]

print(f"Found {total_pages} pages.")

# Loop through every page
for page in range(1, total_pages + 1):
    print(f"Fetching page {page}/{total_pages}...")

    response = requests.get(
        f"{base_url}?period=All&page={page}",
        headers=headers
    )

    response.raise_for_status()
    data = response.json()

    for item in data["items"]:
        hunters.append({
            "username": item["username"],
            "public": item["hunter_profile"]["public"],
            "profile": (
                f"https://yeswehack.com/hunters/{item['slug']}"
                if item["hunter_profile"]["public"]
                else None
            )
        })

print(f"\nCollected {len(hunters)} hunters.\n")

output_path = Path(__file__).resolve().parent / "names.json"
output_path.write_text(json.dumps(hunters, indent=2, ensure_ascii=False), encoding="utf-8")

print(f"Saved {output_path}")

for hunter in hunters:
    print(hunter)
```

</details>

<details>

<summary>statparse.py — enrich each hunter's profile</summary>

For every public hunter in `names.json`, fetches `GET /hunters/{username}`, narrows the raw profile into a stable record (name, joined date, impact cast to float, reports, points, rank, country), and writes it to `hunters/<username>/stats.json`. Skips private profiles and retries on HTTP 429.

```python
#!/usr/bin/env python3

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

import requests


def fetch_hunter(username: str) -> dict:
    url = f"https://api.yeswehack.com/hunters/{username}"

    while True:
        response = requests.get(
            url,
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=30,
        )

        if response.status_code == 429:
            print(f"  Rate limited for {username}; waiting 2 seconds before retrying...")
            time.sleep(2)
            continue

        response.raise_for_status()
        break

    data = response.json()

    first = data.get("public_firstname") or ""
    last = data.get("public_lastname") or ""

    name = f"{first} {last}".strip()
    if not name:
        name = data["username"]

    return {
        "username": data["username"],
        "name": name,
        "joined": data.get("joined_on"),
        "impact": float(data.get("impact", 0)),
        "reports": data.get("nb_reports", 0),
        "points": data.get("points", 0),
        "rank": data.get("rank", 0),
        "country": data.get("nationality"),
    }


def main():

    parser = argparse.ArgumentParser(
        description="Download hunter statistics from a ranking JSON."
    )

    parser.add_argument(
        "json_file",
        help="Path to the ranking JSON.",
    )

    args = parser.parse_args()

    with open(args.json_file, "r", encoding="utf-8") as f:
        hunters = json.load(f)

    base_dir = Path("hunters")
    base_dir.mkdir(exist_ok=True)

    total = len(hunters)
    downloaded = 0
    skipped = 0

    for hunter in hunters:

        if hunter["profile"] is None:
            skipped += 1
            continue

        username = hunter["username"]

        print(f"Fetching {username}...")

        try:
            stats = fetch_hunter(username)
        except requests.HTTPError as e:
            print(f"  Failed ({e})")
            continue

        hunter_dir = base_dir / username
        hunter_dir.mkdir(exist_ok=True)

        output_file = hunter_dir / "stats.json"

        output_file.write_text(
            json.dumps(stats, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )

        downloaded += 1

    print()
    print(f"Processed : {total}")
    print(f"Downloaded: {downloaded}")
    print(f"Skipped   : {skipped}")


if __name__ == "__main__":
    main()
```

</details>

<details>

<summary>parse_hacktivity.py — pull each hunter's bug-disclosure history</summary>

Walks every hunter folder created by `statparse.py` and pages through `GET /v2/hacktivity/{username}`, splitting the trailing `(CWE-nnn)` off the bug-type name and normalizing status casing, then writes the full history to `hacktivities.json`. Re-reads `nb_pages` from every response since the total can shift mid-crawl.

```python
#!/usr/bin/env python3

from __future__ import annotations
"""
Parse YesWeHack hunter hacktivity feeds for every username folder in hunters/.

Usage: python parse_hacktivity.py
"""


import argparse
import csv
import json
import re
import time
from dataclasses import dataclass, asdict
from pathlib import Path

import requests


# --- data model ------------------------------------------------------------

@dataclass
class Entry:
    date: str            # normalized ISO 'YYYY-MM-DD' if parseable, else the raw text
    date_raw: str        # exactly as shown, e.g. 'Fri, 17 Jul 2026'
    bug_name: str        # e.g. 'Cross-site Scripting (XSS) - Reflected'
    cwe: str | None      # e.g. 'CWE-79'  (None if the row has no CWE)
    bug_type_raw: str    # full cell text, e.g. 'Cross-site Scripting (XSS) - Reflected (CWE-79)'
    status: str          # 'Accepted' / 'Resolved' / 'Closed' / ...


def fetch_all_pages_api(
    username: str,
    *,
    delay: float = 2.0,
) -> list[Entry]:
    page = 1
    entries: list[Entry] = []
    session = requests.Session()

    while True:

        url = (
            f"https://api.yeswehack.com/v2/hacktivity/"
            f"{username}"
            f"?page={page}&resultsPerPage=10"
        )

        attempt = 0
        while True:
            r = session.get(url, timeout=30)

            if r.status_code != 429:
                r.raise_for_status()
                break

            retry_after = r.headers.get("Retry-After")
            wait_seconds = delay * (2 ** attempt)

            if retry_after:
                try:
                    wait_seconds = max(wait_seconds, float(retry_after))
                except ValueError:
                    pass

            wait_seconds = max(wait_seconds, 1.0)
            print(
                f"Rate limited on page {page}; retrying in "
                f"{wait_seconds:.1f}s"
            )
            time.sleep(wait_seconds)
            attempt += 1

        data = r.json()

        pagination = data["pagination"]
        items = data["items"]

        print(
            f"Fetching page {pagination['page']} "
            f"of {pagination['nb_pages']}"
        )

        for item in items:

            bug_raw = item["bug_type"]["name"]

            bug_name, cwe = _split_bug_type(bug_raw)

            entries.append(
                Entry(
                    date=item["date"],
                    date_raw=item["date"],
                    bug_name=bug_name,
                    cwe=cwe,
                    bug_type_raw=bug_raw,
                    status=item["status"].capitalize(),
                )
            )

        if page >= pagination["nb_pages"]:
            break

        page += 1
        time.sleep(delay)

    return entries
_CWE_RE = re.compile(r"\s*\((CWE-\d+)\)\s*$", re.IGNORECASE)


def _split_bug_type(raw: str) -> tuple[str, str | None]:
    m = _CWE_RE.search(raw)
    if not m:
        return raw, None
    cwe = m.group(1).upper()
    bug_name = raw[: m.start()].strip()
    return bug_name, cwe


# --- CLI -------------------------------------------------------------------

def _print_table(entries: list[Entry]) -> None:
    if not entries:
        print("No rows parsed. Did you save the *rendered* DOM (not view-source)?")
        return
    w_date = max(len(e.date) for e in entries)
    w_stat = max(len(e.status) for e in entries)
    for e in entries:
        cwe = e.cwe or "-"
        print(f"{e.date:<{w_date}}  {e.status:<{w_stat}}  {cwe:<8}  {e.bug_name}")
    print(f"\nParsed {len(entries)} entr{'y' if len(entries) == 1 else 'ies'}.")


def main() -> None:
    ap = argparse.ArgumentParser(
        description="Parse YesWeHack hacktivities for every folder in hunters/."
    )
    ap.add_argument(
        "hunters_dir",
        nargs="?",
        default="hunters",
        help="Folder that contains one subfolder per username.",
    )
    ap.add_argument(
        "--delay",
        type=float,
        default=2.0,
        help="Seconds between page requests (default 2.0)",
    )
    args = ap.parse_args()

    hunters_root = Path(args.hunters_dir).resolve()

    if not hunters_root.exists() or not hunters_root.is_dir():
        raise SystemExit(f"Hunters folder not found: {hunters_root}")

    hunter_dirs = [path for path in sorted(hunters_root.iterdir()) if path.is_dir()]

    if not hunter_dirs:
        raise SystemExit(f"No hunter folders found in: {hunters_root}")

    for hunter_dir in hunter_dirs:
        username = hunter_dir.name
        print(f"Processing {username}...")

        entries = fetch_all_pages_api(username, delay=args.delay)

        output_file = hunter_dir / f"hacktivities.json"
        output_file.write_text(
            json.dumps([asdict(e) for e in entries], indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        print(f"Wrote {output_file}")

        _print_table(entries)


if __name__ == "__main__":
    main()
```

</details>

## Preprocessing

<details>

<summary>CWEchecker.py — CWE / bug_name class mapper</summary>

Walks every `hunters/<hunter_name>/hacktivities.json` file and builds a mapping of `CWE-XX -> { bug_name variants seen under that CWE }`, along with occurrence counts per (CWE, bug\_name) pair. Prints a readable CWE tree to the console and saves the structured result as `Outputs/cwe_class_map.json` — the raw input needed later for Shannon entropy calculations.

```python
"""
parse_cwe_classes.py

Walks ../hunters/<hunter_name>/hacktivities.json (relative to this script's
location in src/), and builds a mapping of:

    CWE-XX -> { bug_name variants seen under that CWE }

Also tracks occurrence counts per (cwe, bug_name) pair, since that's the
raw input you'll need later for Shannon entropy at either granularity.

Assumed directory layout:

    project_root/
    ├── src/
    │   └── parse_cwe_classes.py   <- this file
    └── hunters/
        ├── rabhi/
        │   └── hacktivities.json
        ├── some_other_hunter/
        │   └── hacktivities.json
        └── ...
"""
import json
from pathlib import Path
from collections import defaultdict, Counter

# --- Path setup -------------------------------------------------------
SCRIPT_DIR  = Path(__file__).resolve().parent   # Codes/
HUNTERS_DIR = SCRIPT_DIR / "hunters"            # Codes/hunters/
OUTPUT_DIR  = SCRIPT_DIR.parent / "Outputs"     # Outputs/


def load_all_hacktivities(hunters_dir: Path):
    """
    Yields (hunter_name, list_of_report_dicts) for every hunter folder
    that contains a hacktivities.json.
    """
    if not hunters_dir.exists():
        raise FileNotFoundError(f"Expected hunters directory at {hunters_dir}, not found.")

    for hunter_folder in sorted(hunters_dir.iterdir()):
        if not hunter_folder.is_dir():
            continue

        json_path = hunter_folder / "hacktivities.json"
        if not json_path.exists():
            print(f"  [skip] no hacktivities.json for '{hunter_folder.name}'")
            continue

        try:
            with open(json_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as e:
            print(f"  [error] malformed JSON for '{hunter_folder.name}': {e}")
            continue

        yield hunter_folder.name, data


def build_cwe_class_map(hunters_dir: Path):
    """
    Returns:
        cwe_to_bugnames: dict[str, set[str]]        -> CWE-79: {"Reflected XSS", "Stored XSS", ...}
        cwe_bugname_counts: dict[str, Counter]       -> CWE-79: Counter({"Reflected XSS": 42, ...})
        total_reports_scanned: int
        hunters_scanned: int
    """
    cwe_to_bugnames = defaultdict(set)
    cwe_bugname_counts = defaultdict(Counter)
    total_reports_scanned = 0
    hunters_scanned = 0

    for hunter_name, reports in load_all_hacktivities(hunters_dir):
        hunters_scanned += 1
        for report in reports:
            cwe = report.get("cwe")
            bug_name = report.get("bug_name")

            if not cwe or not bug_name:
                # Missing field -- skip but don't crash the whole run
                continue

            cwe_to_bugnames[cwe].add(bug_name)
            cwe_bugname_counts[cwe][bug_name] += 1
            total_reports_scanned += 1

    return cwe_to_bugnames, cwe_bugname_counts, total_reports_scanned, hunters_scanned


def print_cwe_tree(cwe_to_bugnames, cwe_bugname_counts):
    """
    Prints the CWE -> sub-technique tree, e.g.:

    CWE-79 (3 sub-types, 128 total reports)
      L Cross-site Scripting (XSS) - Reflected        (85)
      L Cross-site Scripting (XSS) - Stored            (30)
      L Cross-site Scripting (XSS) - DOM-based          (13)
    """
    for cwe in sorted(cwe_to_bugnames.keys()):
        bug_names = cwe_to_bugnames[cwe]
        counts = cwe_bugname_counts[cwe]
        total = sum(counts.values())

        print(f"{cwe} ({len(bug_names)} sub-types, {total} total reports)")

        # Sort sub-types by frequency, descending
        for bug_name, count in counts.most_common():
            print(f"  L {bug_name:<50} ({count})")
        print()


def save_json(cwe_to_bugnames, cwe_bugname_counts, out_path: Path):
    """
    Serializes results to JSON for downstream entropy calculations.
    Sets aren't JSON-serializable, so convert to sorted lists.
    """
    serializable = {
        cwe: {
            "sub_types": sorted(bug_names),
            "counts": dict(cwe_bugname_counts[cwe]),
        }
        for cwe, bug_names in cwe_to_bugnames.items()
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(serializable, f, indent=2)

    print(f"Saved structured output to {out_path}")


if __name__ == "__main__":
    print(f"Scanning: {HUNTERS_DIR}\n")

    cwe_to_bugnames, cwe_bugname_counts, total_reports, hunters_scanned = build_cwe_class_map(HUNTERS_DIR)

    print(f"Scanned {hunters_scanned} hunters, {total_reports} reports, "
          f"{len(cwe_to_bugnames)} distinct CWE categories.\n")

    print_cwe_tree(cwe_to_bugnames, cwe_bugname_counts)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = OUTPUT_DIR / "cwe_class_map.json"
    save_json(cwe_to_bugnames, cwe_bugname_counts, out_path)
```

</details>

<details>

<summary>hunter_hacktivity_per_hunter.py — count "New" reports per hunter</summary>

Counts the number of `"New"`-status hacktivity reports for each hunter and writes a sorted CSV (`hunter_hacktivity_report_counts.csv`), used later to reconcile against each hunter's official profile totals.

```python
#!/usr/bin/env python3
"""
Count the number of "New" hacktivity reports for each hunter
and save the results to a CSV file.
"""

from pathlib import Path
import csv
import json


def main():
    # src/code.py -> root/
    root =  Path(__file__).resolve().parent
    hunters_dir = root / "hunters"

    output_file = root / "hunter_hacktivity_report_counts.csv"

    rows = []
    total_hunters = 0
    total_reports = 0

    for hunter_dir in sorted(hunters_dir.iterdir()):
        if not hunter_dir.is_dir():
            continue

        hacktivities_file = hunter_dir / "hacktivities.json"

        if not hacktivities_file.exists():
            continue

        total_hunters += 1

        try:
            with hacktivities_file.open("r", encoding="utf-8") as f:
                hacktivities = json.load(f)

            # Count only reports whose status is "New"
            report_count = sum(
                1 for report in hacktivities
                if report.get("status") == "New"
            )

            rows.append({
                "hunter": hunter_dir.name,
                "hacktivity_report_count": report_count
            })

            total_reports += report_count

        except Exception as e:
            print(f"Failed to parse {hacktivities_file}: {e}")

    # Sort by report count (highest first)
    rows.sort(key=lambda x: x["hacktivity_report_count"], reverse=True)

    # Write CSV
    with output_file.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["hunter", "hacktivity_report_count"]
        )
        writer.writeheader()
        writer.writerows(rows)

    print(f"Processed {total_hunters} hunters")
    print(f"Total 'New' reports counted: {total_reports}")
    print(f"CSV written to: {output_file}")


if __name__ == "__main__":
    main()
```

</details>

<details>

<summary>normalize_hacktivity.py — collapse legacy labels to canonical CWEs</summary>

Reduces every legacy OWASP-era bug-type label to a normalized comparison key, maps it to a canonical name and CWE via a lookup table, deletes non-applicable records, and rewrites each hunter's `hacktivities.json` in place. Prints a full rewritten / inferred / already-canonical / deleted / unknown breakdown per run.

```python
#!/usr/bin/env python3
"""
normalize_hacktivities.py

Normalizes legacy bug-type labels in hunters/<name>/hacktivities.json to
canonical labels with CWE identifiers.

Non-applicable records ("Not Applicable (CWE-NULL)", "None Applicable") are
retained untouched and reported — deletion deferred by decision.

Usage (from repo root):
    python src/normalize_hacktivities.py
    python src/normalize_hacktivities.py --root path/to/hunters
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

_SCRIPT_DIR  = Path(__file__).resolve().parent   # Codes/
_HUNTERS_DIR = _SCRIPT_DIR / "hunters"           # Codes/hunters/

# --------------------------------------------------------------------------
# 1. Key normalization
# --------------------------------------------------------------------------
_TRAILING_CWE = re.compile(r"\s*\(CWE-[\w\d]+\)\s*$", re.IGNORECASE)
_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def strip_cwe_suffix(label: str) -> str:
    return _TRAILING_CWE.sub("", label).strip()


def normalize_key(label: str) -> str:
    return _NON_ALNUM.sub(" ", strip_cwe_suffix(label).lower()).strip()


# --------------------------------------------------------------------------
# 2. Canonical targets
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Canonical:
    name: str
    cwe: str


XSS        = Canonical("Cross-site Scripting (XSS) - Generic", "CWE-79")
MISCONFIG  = Canonical("Server Misconfiguration", "CWE-16")
CMD_INJ    = Canonical("Command Injection - Generic", "CWE-77")
AUTHN      = Canonical("Improper Authentication - Generic", "CWE-287")
ACCESS_CTL = Canonical("Improper Access Control - Generic", "CWE-284")
IDOR       = Canonical("Insecure Direct Object Reference (IDOR)", "CWE-639")
CSRF       = Canonical("Cross-Site Request Forgery (CSRF)", "CWE-352")
INFO_DISC  = Canonical("Information Disclosure", "CWE-200")
OPEN_REDIR = Canonical("Open Redirect", "CWE-601")
XXE        = Canonical("XML External Entity (XXE)", "CWE-611")
VULN_COMP    = Canonical("Use of Vulnerable Third-Party Component", "CWE-1104")
INSUFF_LOG   = Canonical("Insufficient Logging", "CWE-778")

# --------------------------------------------------------------------------
# 3. Legacy -> canonical map
# --------------------------------------------------------------------------

CANONICAL_MAP: dict[str, Canonical] = {}
INFERRED_KEYS: set[str] = set()


def register(canon: Canonical, *labels: str, inferred: bool = False) -> None:
    for label in labels:
        key = normalize_key(label)
        CANONICAL_MAP[key] = canon
        if inferred:
            INFERRED_KEYS.add(key)


register(XSS,
         "OWASP-A7-XSS",
         "OWASP-A7-Cross-Site Scripting (XSS)",
         "OWASP-2013-A3-XSS",
         "OWASP-2013-A3-Cross-Site Scripting (XSS)",
         "Cross-site Scripting (XSS) - Generic")

register(MISCONFIG,
         "OWASP-A6-Security Misconfiguration",
         "OWASP-2013-A5",
         "OWASP-2013-A5-Security Misconfiguration",
         "Server Misconfiguration")

register(CMD_INJ,
         "OWASP-A1-Injection",
         "OWASP-2013-A1-Injection",
         inferred=True)
register(CMD_INJ, "Command Injection - Generic")

register(AUTHN,
         "OWASP-A2-Broken Authentication",
         "OWASP-2013-A2-Broken Authentication and Session Management",
         "OWASP-2013-A2-Broken Auth & Session Mgmt",
         "Improper Authentication - Generic")

register(ACCESS_CTL,
         "OWASP-A5-Broken Access Control",
         "OWASP-2013-A7-Missing Function Level Access Control",
         "Improper Access Control - Generic")

register(IDOR,
         "OWASP-2013-A4-Insecure Direct Object References",
         "Insecure Direct Object Reference (IDOR)")

register(CSRF,
         "OWASP-2013-A8-CSRF",
         "OWASP-2013-A8-Cross-Site Request Forgery (CSRF)",
         "Cross-Site Request Forgery (CSRF)")

register(INFO_DISC,
         "OWASP-A3-Sensitive Data Exposure",
         "OWASP-2013-A6",
         "OWASP-2013-A6-Sensitive Data Exposure",
         "Information Disclosure")

register(OPEN_REDIR,
         "OWASP-2013-A10-Unvalidated Redirects and Forwards",
         "Open Redirect")

register(XXE,
         "OWASP-A4-XXE",
         "OWASP-A4-XML External Entities (XXE)",
         "XML External Entity (XXE)")

register(VULN_COMP,
         "OWASP-A9",
         "OWASP-A9-Using Components with Known Vulnerabilities",
         "OWASP-2013-A9",
         "OWASP-2013-A9-Using Components with Known Vulnerabilities",
         "Dependency on Vulnerable Third-Party Component",
         "Use of Unmaintained Third Party Components",
         "Use of Vulnerable Third-Party Component")

register(INSUFF_LOG,
         "OWASP-A10-Insufficient Logging&Monitoring",
         "OWASP-A10-Insufficient Logging & Monitoring",
         "Insufficient Logging")

DELETE_KEYS: set[str] = {
    normalize_key("Not Applicable (CWE-NULL)"),
    normalize_key("Not Applicable"),
    normalize_key("None Applicable"),
}

# --------------------------------------------------------------------------
# 4. Record handling
# --------------------------------------------------------------------------

@dataclass
class Outcome:
    action: str   # rewritten | inferred | already_canonical | deleted | unknown | error
    original: str


def resolve_label(record: dict) -> str:
    return (record.get("bug_type_raw") or record.get("bug_name") or "").strip()


def classify(record: dict) -> Outcome:
    original = resolve_label(record)
    if not original:
        return Outcome("error", "<empty>")

    key = normalize_key(original)

    if key in DELETE_KEYS:
        return Outcome("deleted", original)

    canon = CANONICAL_MAP.get(key)
    if canon is None:
        return Outcome("unknown", original)

    expected_raw = f"{canon.name} ({canon.cwe})"
    already = (
        record.get("bug_name") == canon.name
        and record.get("cwe") == canon.cwe
        and record.get("bug_type_raw") == expected_raw
    )

    record["bug_name"] = canon.name
    record["cwe"] = canon.cwe
    record["bug_type_raw"] = expected_raw

    if already:
        return Outcome("already_canonical", original)
    return Outcome("inferred" if key in INFERRED_KEYS else "rewritten", original)


# --------------------------------------------------------------------------
# 5. File walking
# --------------------------------------------------------------------------

def process_file(path: Path):
    actions: Counter = Counter()
    unknown: Counter = Counter()
    inferred: Counter = Counter()

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"  !! skipped {path}: {exc}", file=sys.stderr)
        actions["error"] += 1
        return actions, unknown, inferred, 0

    if not isinstance(data, list):
        print(f"  !! skipped {path}: expected a JSON array", file=sys.stderr)
        actions["error"] += 1
        return actions, unknown, inferred, 0

    changed = False

    kept = []
    for record in data:
        if not isinstance(record, dict):
            actions["error"] += 1
            continue

        outcome = classify(record)
        actions[outcome.action] += 1

        if outcome.action == "deleted":
            changed = True
            continue
        kept.append(record)

        if outcome.action in ("rewritten", "inferred"):
            changed = True
        if outcome.action == "inferred":
            inferred[outcome.original] += 1
        elif outcome.action == "unknown":
            unknown[outcome.original] += 1

    if changed:
        path.write_text(
            json.dumps(kept, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )

    return actions, unknown, inferred, actions["deleted"]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=_HUNTERS_DIR,
                        help="Directory containing per-hunter folders (default: Codes/hunters)")
    args = parser.parse_args()

    root: Path = args.root
    if not root.is_dir():
        print(f"error: {root} is not a directory", file=sys.stderr)
        return 1

    files = sorted(root.glob("*/hacktivities.json"))
    if not files:
        print(f"error: no hacktivities.json found under {root}", file=sys.stderr)
        return 1

    totals: Counter = Counter()
    all_unknown: Counter = Counter()
    all_inferred: Counter = Counter()

    for path in files:
        actions, unknown, inferred, _ = process_file(path)
        totals.update(actions)
        all_unknown.update(unknown)
        all_inferred.update(inferred)

    print(f"\n=== DONE — {len(files)} file(s) processed ===")
    for action in ("rewritten", "inferred", "already_canonical",
                   "deleted", "unknown", "error"):
        if totals[action]:
            print(f"  {action:<20} {totals[action]:>6}")

    if all_inferred:
        print("\n--- Inferred root cause (category-level legacy labels) ---")
        for label, count in all_inferred.most_common():
            print(f"  {count:>5}x  {label}")

    if all_unknown:
        print(f"\n--- Unmapped labels ({len(all_unknown)} distinct) ---")
        for label, count in all_unknown.most_common():
            print(f"  {count:>5}x  {label}")
        print("\nAdd confident ones via register() and re-run.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

</details>

<details>

<summary>parse_stats.py — flatten hunter profiles into a CSV</summary>

Reads `stats.json` from every hunter folder and writes a single CSV to `Outputs/hunter_stats.csv` with columns: `username, joined, impact, reports, points, rank, country`.

```python
#!/usr/bin/env python3
"""
parse_stats.py

Reads stats.json from every hunter folder under Codes/hunters/ and writes
a single CSV to Outputs/hunter_stats.csv with columns:
    username, joined, impact, reports, points, rank, country
"""

import csv
import json
import sys
from pathlib import Path

_SCRIPT_DIR  = Path(__file__).resolve().parent   # Codes/
_HUNTERS_DIR = _SCRIPT_DIR / "hunters"           # Codes/hunters/
_OUTPUT_DIR  = _SCRIPT_DIR.parent / "Outputs"    # Outputs/

COLUMNS = ["username", "joined", "impact", "reports", "points", "rank", "country"]


def main() -> int:
    if not _HUNTERS_DIR.is_dir():
        print(f"error: hunters directory not found at {_HUNTERS_DIR}", file=sys.stderr)
        return 1

    rows = []
    skipped = []

    for hunter_dir in sorted(_HUNTERS_DIR.iterdir()):
        if not hunter_dir.is_dir():
            continue

        stats_file = hunter_dir / "stats.json"
        if not stats_file.exists():
            skipped.append(f"  [skip] no stats.json in '{hunter_dir.name}'")
            continue

        try:
            data = json.loads(stats_file.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            skipped.append(f"  [error] {hunter_dir.name}: {exc}")
            continue

        rows.append({col: data.get(col, "") for col in COLUMNS})

    if not rows:
        print("error: no stats.json files found", file=sys.stderr)
        return 1

    _OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out_path = _OUTPUT_DIR / "hunter_stats.csv"

    with out_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Written {len(rows)} rows to {out_path}")

    for msg in skipped:
        print(msg)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

</details>

<details>

<summary>stat_checker.py — baseline / verification frequency counts</summary>

Counts `bug_name` and `cwe` occurrences across every `"New"`-status report, prints frequency tables to the console, and writes them to `Outputs/stat_checker_output.txt`. Run once before normalization for a baseline and once after to verify the transformation.

```python
#!/usr/bin/env python3
"""
Count bug types and CWEs from hunters' hacktivities,
counting only reports whose status is "new".
"""

from pathlib import Path
from collections import Counter
import json

_SCRIPT_DIR  = Path(__file__).resolve().parent   # Codes/
_HUNTERS_DIR = _SCRIPT_DIR / "hunters"           # Codes/hunters/
_OUTPUT_DIR  = _SCRIPT_DIR.parent / "Outputs"    # Outputs/


def main():
    hunters_dir = _HUNTERS_DIR
    output_dir  = _OUTPUT_DIR

    bug_counter = Counter()
    cwe_counter = Counter()

    total_hunters = 0
    new_bug_reports = 0
    new_cwe_reports = 0

    for hunter_dir in hunters_dir.iterdir():
        if not hunter_dir.is_dir():
            continue

        hacktivities_file = hunter_dir / "hacktivities.json"

        if not hacktivities_file.exists():
            continue

        total_hunters += 1

        try:
            with hacktivities_file.open("r", encoding="utf-8") as f:
                hacktivities = json.load(f)

            for report in hacktivities:
                # Only count reports with status == "new"
                if report.get("status") != "New":
                    continue

                bug_name = report.get("bug_name")
                cwe = report.get("cwe")

                if bug_name:
                    bug_counter[bug_name] += 1
                    new_bug_reports += 1

                if cwe:
                    cwe_counter[cwe] += 1
                    new_cwe_reports += 1

        except Exception as e:
            print(f"Failed to parse {hacktivities_file}: {e}")

    print(f"Processed {total_hunters} hunters")
    print(f"New reports with bug_name: {new_bug_reports}")
    print(f"New reports with CWE:      {new_cwe_reports}")

    print("\n=== Bug Types (status = new) ===")
    for bug, count in bug_counter.most_common():
        print(f"{count:5}  {bug}")

    print("\n=== CWEs (status = new) ===")
    for cwe, count in cwe_counter.most_common():
        print(f"{count:5}  {cwe}")

    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / "stat_checker_output.txt"
    with out_path.open("w", encoding="utf-8") as f:
        f.write(f"Processed {total_hunters} hunters\n")
        f.write(f"New reports with bug_name: {new_bug_reports}\n")
        f.write(f"New reports with CWE:      {new_cwe_reports}\n")
        f.write("\n=== Bug Types (status = new) ===\n")
        for bug, count in bug_counter.most_common():
            f.write(f"{count:5}  {bug}\n")
        f.write("\n=== CWEs (status = new) ===\n")
        for cwe, count in cwe_counter.most_common():
            f.write(f"{count:5}  {cwe}\n")
    print(f"\nSaved output to {out_path}")


if __name__ == "__main__":
    main()
```

</details>

## Statistical Inference

<details>

<summary>EDA.py — exploratory data analysis on hunter CSV exports</summary>

Loads `hunter_stats.csv`, `hunter_hacktivity_report_counts.csv`, and `Stats.txt`; plots the country distribution pie chart and top-20 bug-name/CWE bar charts; prints numeric summaries (mean, std, skew, IQR) and histograms for impact, reports, and points using Freedman-Diaconis binning; then reconciles official vs. hacktivity report counts and writes the worst 20 mismatches to `worst_20_hunters.txt`.

```python
"""
Exploratory data analysis for the hunter CSV exports.

Inputs:
    - hunter_stats.csv
    - hunter_hacktivity_report_counts.csv
    - Stats.txt (for bug type and CWE counts; those categories are not in the CSVs)

Usage:
    python EDA.py [--stats-csv PATH] [--hacktivity-csv PATH] [--stats-txt PATH] [--out-dir PATH]
"""

import argparse
import re
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


def load_csv(path: Path, label: str) -> pd.DataFrame:
    if not path.exists():
        raise SystemExit(f"Missing {label}: {path}")
    df = pd.read_csv(path)
    print(f"[info] loaded {label}: {len(df)} rows from {path}")
    return df


def clean_stats(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = [column.strip() for column in df.columns]

    rename_map = {
        "hunter": "name",
        "username": "name",
    }
    df = df.rename(columns={k: v for k, v in rename_map.items() if k in df.columns})

    for column in ("impact", "reports", "points", "rank", "joined"):
        if column in df.columns:
            df[column] = pd.to_numeric(df[column], errors="coerce")

    if "country" in df.columns:
        df["country"] = (
            df["country"].astype("string").str.strip().str.upper().replace("", pd.NA)
        )

    if "name" in df.columns:
        df["name"] = df["name"].astype("string").str.strip()

    missing_cols = [col for col in ("name", "rank", "country", "impact", "reports", "points") if col in df.columns]
    print("[info] missing values in hunter_stats.csv:")
    print(df[missing_cols].isna().sum().to_string())
    return df


def clean_hacktivity(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df.columns = [column.strip() for column in df.columns]

    rename_map = {
        "hunter": "name",
        "hacktivity_report_count": "hacktivity_reports",
    }
    df = df.rename(columns={k: v for k, v in rename_map.items() if k in df.columns})

    if "name" in df.columns:
        df["name"] = df["name"].astype("string").str.strip()
    if "hacktivity_reports" in df.columns:
        df["hacktivity_reports"] = pd.to_numeric(df["hacktivity_reports"], errors="coerce")

    print("[info] missing values in hunter_hacktivity_report_counts.csv:")
    print(df[[col for col in ("name", "hacktivity_reports") if col in df.columns]].isna().sum().to_string())
    return df


def parse_count_sections(stats_txt: Path) -> pd.DataFrame:
    if not stats_txt.exists():
        raise SystemExit(f"Missing Stats.txt source: {stats_txt}")

    section_header = re.compile(r"^===\s*(?P<title>.+?)\s*===\s*$")
    count_line = re.compile(r"^\s*(?P<count>\d+)\s+(?P<label>.+?)\s*$")

    section = None
    rows = []
    with stats_txt.open(encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.rstrip("\n")
            header = section_header.match(line)
            if header:
                section = header.group("title")
                continue

            if section not in {"Bug Types (status = new)", "CWEs (status = new)"}:
                continue

            match = count_line.match(line)
            if not match:
                continue

            rows.append(
                {
                    "section": "bug_name" if section.startswith("Bug Types") else "CWE",
                    "label": match.group("label"),
                    "count": int(match.group("count")),
                }
            )

    if not rows:
        raise SystemExit(f"Could not parse bug/CWE counts from {stats_txt}")

    df = pd.DataFrame(rows)
    print(f"[info] parsed {len(df)} count rows from {stats_txt}")
    return df


def plot_country_pie(df: pd.DataFrame, out_dir: Path) -> pd.Series:
    counts = df["country"].value_counts(dropna=True).sort_values(ascending=False)
    fig, ax = plt.subplots(figsize=(11, 8))

    def format_autopct(pct: float) -> str:
        return f"{pct:.1f}%" if pct >= 2 else ""

    wedges, _, autotexts = ax.pie(
        counts.values,
        startangle=90,
        counterclock=False,
        autopct=format_autopct,
        pctdistance=0.78,
        wedgeprops={"linewidth": 1, "edgecolor": "white"},
        textprops={"fontsize": 9},
    )
    for autotext in autotexts:
        autotext.set_color("white")
        autotext.set_fontweight("bold")

    ax.set_title("Hunters by country")
    legend_labels = [f"{country} ({count}, {count / counts.sum():.1%})" for country, count in counts.items()]
    ax.legend(wedges, legend_labels, title="Country", loc="center left", bbox_to_anchor=(1.02, 0.5))
    ax.set_aspect("equal")

    fig.tight_layout()
    fig.savefig(out_dir / "country_by_country_pie.png", dpi=160, bbox_inches="tight")
    plt.close(fig)

    print("\n[country] hunter counts by country:")
    print(counts.to_string())
    return counts


def plot_top_counts(df: pd.DataFrame, section: str, out_dir: Path, filename: str) -> None:
    top = df[df["section"] == section].nlargest(20, "count").copy()
    if top.empty:
        print(f"[warn] no rows found for {section}")
        return

    top = top.sort_values("count", ascending=True)
    fig, ax = plt.subplots(figsize=(12, 8))
    ax.barh(top["label"], top["count"], color="#4C72B0")
    ax.set_title(f"Top 20 {section} counts")
    ax.set_xlabel("Count")
    ax.set_ylabel(section)
    ax.grid(axis="x", alpha=0.25)

    fig.tight_layout()
    fig.savefig(out_dir / filename, dpi=160, bbox_inches="tight")
    plt.close(fig)

    print(f"\n[top 20 {section}]")
    print(top.sort_values("count", ascending=False)[["label", "count"]].to_string(index=False))


def choose_histogram_bins(series: pd.Series) -> tuple[np.ndarray, str]:
    data = series.dropna().astype(float)
    if data.empty:
        return np.array([0.0, 1.0]), "no-data fallback"

    if data.nunique() == 1:
        value = float(data.iloc[0])
        span = 0.5 if value == 0 else max(abs(value) * 0.05, 0.5)
        return np.array([value - span, value + span]), "single-value fallback (1 bin)"

    edges = np.histogram_bin_edges(data, bins="fd")
    if len(edges) < 2:
        edges = np.histogram_bin_edges(data, bins="sturges")

    width = float(edges[1] - edges[0]) if len(edges) > 1 else 0.0
    spec = f"Freedman-Diaconis rule via numpy.histogram_bin_edges: {len(edges) - 1} bins, width={width:.4g}"
    return edges, spec


def print_numeric_summary(df: pd.DataFrame, column: str, out_dir: Path, lines: list[str]) -> None:
    data = df[["name", "rank", column]].dropna(subset=[column]).copy()
    if data.empty:
        print(f"[warn] no data for {column}, skipping")
        lines.append(f"[{column}] no data")
        return

    series = data[column].astype(float)
    min_row = data.loc[series.idxmin()]
    max_row = data.loc[series.idxmax()]
    q1 = float(series.quantile(0.25))
    q3 = float(series.quantile(0.75))
    iqr = q3 - q1
    skew = float(series.skew())
    mean = float(series.mean())
    std = float(series.std())

    print(f"\n[{column}]")
    print(f"  mean                {mean:.4f}")
    print(f"  std                 {std:.4f}")
    print(f"  min                 {float(min_row[column]):.4f}  (name={min_row['name']}, rank={min_row['rank']})")
    print(f"  max                 {float(max_row[column]):.4f}  (name={max_row['name']}, rank={max_row['rank']})")
    print(f"  skew                {skew:.4f}")
    print(f"  IQR                 {iqr:.4f}")

    bins, spec = choose_histogram_bins(series)
    print(f"  histogram bins      {spec}")

    lines.extend(
        [
            f"[{column}]",
            f"mean                {mean:.4f}",
            f"std                 {std:.4f}",
            f"min                 {float(min_row[column]):.4f}  (name={min_row['name']}, rank={min_row['rank']})",
            f"max                 {float(max_row[column]):.4f}  (name={max_row['name']}, rank={max_row['rank']})",
            f"skew                {skew:.4f}",
            f"IQR                 {iqr:.4f}",
            f"histogram bins      {spec}",
            "",
        ]
    )

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.hist(series, bins=bins, color="#55A868", edgecolor="white")
    ax.set_title(f"{column.title()} histogram")
    ax.set_xlabel(column.title())
    ax.set_ylabel("Number of hunters")
    ax.grid(axis="y", alpha=0.2)
    fig.tight_layout()
    fig.savefig(out_dir / f"{column}_histogram.png", dpi=160, bbox_inches="tight")
    plt.close(fig)


def compare_report_counts(stats_df: pd.DataFrame, hacktivity_df: pd.DataFrame, out_dir: Path) -> pd.DataFrame:
    hacktivity_lookup = hacktivity_df.set_index("name")["hacktivity_reports"]
    comparison = stats_df[["name", "rank", "reports"]].copy()
    comparison = comparison.rename(columns={"reports": "official_reports"})
    comparison["hacktivity_reports"] = comparison["name"].map(hacktivity_lookup)
    comparison["error"] = comparison["official_reports"] - comparison["hacktivity_reports"]

    matched = comparison[comparison["hacktivity_reports"].notna()].copy()
    missing_hacktivity = int(comparison["hacktivity_reports"].isna().sum())
    extra_hacktivity = int((~hacktivity_df["name"].isin(stats_df["name"])).sum())

    print("\n[report count reconciliation]")
    print(f"  official hunters          {len(stats_df)}")
    print(f"  matched hunters           {len(matched)}")
    print(f"  missing in hacktivity     {missing_hacktivity}")
    print(f"  extra in hacktivity       {extra_hacktivity}")

    if matched.empty:
        print("[warn] no overlapping hunter names found between the two CSVs")
        return comparison

    worst = matched.loc[matched["error"].abs().sort_values(ascending=False).head(20).index]
    print("\nWorst 20 hunters by absolute report-count error:")
    print(
        worst[["name", "rank", "official_reports", "hacktivity_reports", "error"]]
        .to_string(index=False)
    )

    print("\nAverage report-count error:")
    print(f"  mean signed error         {matched['error'].mean():.4f}")

    worst_lines = [
        "Worst 20 hunters by absolute report-count error",
        "name, rank, official_reports, hacktivity_reports, error",
    ]
    worst_lines.extend(
        f"{row.name}, {row.rank}, {int(row.official_reports)}, {int(row.hacktivity_reports)}, {float(row.error):.0f}"
        for row in worst.itertuples(index=False)
    )
    (out_dir / "worst_20_hunters.txt").write_text("\n".join(worst_lines) + "\n", encoding="utf-8")

    return comparison


def write_numeric_summary_file(lines: list[str], out_dir: Path) -> None:
    (out_dir / "numeric_summary.txt").write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--stats-csv",
        type=Path,
        default=Path(__file__).resolve().parent / "hunter_stats.csv",
    )
    parser.add_argument(
        "--hacktivity-csv",
        type=Path,
        default=Path(__file__).resolve().parent / "hunter_hacktivity_report_counts.csv",
    )
    parser.add_argument(
        "--stats-txt",
        type=Path,
        default=Path(__file__).resolve().parent / "Stats.txt",
    )
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "Outputs" / "eda",
    )
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)

    stats_df = clean_stats(load_csv(args.stats_csv, "hunter_stats.csv"))
    hacktivity_df = clean_hacktivity(load_csv(args.hacktivity_csv, "hunter_hacktivity_report_counts.csv"))
    counts_df = parse_count_sections(args.stats_txt)

    plot_country_pie(stats_df, args.out_dir)
    plot_top_counts(counts_df, "bug_name", args.out_dir, "top_bug_names.png")
    plot_top_counts(counts_df, "CWE", args.out_dir, "top_cwe.png")

    numeric_summary_lines: list[str] = []
    for column in ("impact", "reports", "points"):
        if column in stats_df.columns:
            print_numeric_summary(stats_df, column, args.out_dir, numeric_summary_lines)
        else:
            print(f"[warn] column {column} not found in hunter_stats.csv")

    write_numeric_summary_file(numeric_summary_lines, args.out_dir)

    compare_report_counts(stats_df, hacktivity_df, args.out_dir)

    print(f"\n[done] plots and comparison files written to {args.out_dir}")


if __name__ == "__main__":
    main()
```

</details>

## Reports to Points

<details>

<summary>reports_to_points.py — reports vs. points scatter, Spearman correlation, CSV export</summary>

Loads every hunter's `stats.json` into a DataFrame, plots a side-by-side linear and log-log scatter of reports vs. points with a median-points-per-report reference line, computes Spearman's rho for reports-vs-points and points-vs-rank (a structural sanity check), and exports a per-hunter summary to `hunter_points_reports.csv`.

```python
"""
Reports vs. points: scatter plot, Spearman correlation, and CSV export.

Expected layout (script lives in Codes/):
    root/
      Codes/reports_to_points.py
      Codes/hunters/<hunter_name>/stats.json
      Outputs/
"""

import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
from scipy import stats as sps


# --------------------------------------------------------------------------
# Loading
# --------------------------------------------------------------------------

def load_stats(hunters_dir: Path) -> pd.DataFrame:
    """Read every hunters/<name>/stats.json into a single DataFrame."""
    records, skipped = [], []

    for stats_path in sorted(hunters_dir.glob("*/stats.json")):
        try:
            with stats_path.open(encoding="utf-8") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            skipped.append((stats_path.parent.name, str(exc)))
            continue
        data["_folder"] = stats_path.parent.name
        records.append(data)

    if skipped:
        print(f"[warn] skipped {len(skipped)} unreadable stats.json:")
        for name, err in skipped[:10]:
            print(f"        {name}: {err}")

    if not records:
        raise SystemExit(f"No stats.json found under {hunters_dir}")

    df = pd.DataFrame(records)
    print(f"[info] loaded {len(df)} hunters")
    return df


def clean(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    for col in ("points", "reports", "rank", "impact"):
        if col in df:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    # Prefer the profile name; fall back to username, then folder name.
    for src in ("name", "username", "_folder"):
        if src in df.columns:
            if "hunter" not in df.columns:
                df["hunter"] = df[src]
            else:
                df["hunter"] = df["hunter"].fillna(df[src])
    return df


# --------------------------------------------------------------------------
# Correlation
# --------------------------------------------------------------------------

def spearman(df: pd.DataFrame, x: str, y: str) -> None:
    """Spearman rho between two columns, with the caveats printed.

    Spearman correlates the *ranks* of the values, not the values
    themselves. That makes it robust to the heavy right tail these
    leaderboard fields tend to have, and it detects any monotone
    relationship rather than only a straight-line one.
    """
    pair = df[[x, y]].dropna()
    n = len(pair)
    if n < 3:
        print(f"[warn] only {n} complete pairs for {x} vs {y}; skipping")
        return

    sp_result = sps.spearmanr(pair[x], pair[y])
    rho, p = sp_result.correlation, sp_result.pvalue
    pear_result = sps.pearsonr(pair[x], pair[y])
    pear, pear_p = pear_result.statistic, pear_result.pvalue

    print(f"\n[correlation] {x} vs {y}  (n={n})")
    print(f"  Spearman rho   {rho:.4f}   (p = {p:.3g})")
    print(f"  Pearson  r     {pear:.4f}   (p = {pear_p:.3g})   [for contrast only]")

    # Ties deflate Spearman. Worth knowing how many you have.
    ties_x = n - pair[x].nunique()
    ties_y = n - pair[y].nunique()
    if ties_x or ties_y:
        print(f"  tied values    {x}: {ties_x}, {y}: {ties_y} "
              f"(scipy uses average ranks)")

    # A big Spearman/Pearson gap is itself a finding: it means the
    # relationship is monotone but not linear -- e.g. points growing
    # faster than reports at the top end.
    if abs(rho - pear) > 0.10:
        print(f"  note: rho and r differ by {abs(rho - pear):.2f} — "
              f"the relationship is monotone but not linear.")


# --------------------------------------------------------------------------
# Scatter
# --------------------------------------------------------------------------

def plot_scatter(df: pd.DataFrame, out_dir: Path) -> None:
    pair = df[["reports", "points"]].dropna()
    if pair.empty:
        print("[warn] no complete reports/points pairs; skipping scatter")
        return

    rho, _ = sps.spearmanr(pair["reports"], pair["points"])

    fig, (ax_lin, ax_log) = plt.subplots(1, 2, figsize=(14, 6))

    for ax, logscale in ((ax_lin, False), (ax_log, True)):
        ax.scatter(pair["reports"], pair["points"],
                   s=28, alpha=0.6, color="#4C72B0", edgecolor="none")
        ax.set_xlabel("Reports")
        ax.set_ylabel("Points")
        if logscale:
            ax.set_xscale("log")
            ax.set_yscale("log")
            ax.set_title("log–log")
        else:
            ax.set_title(f"linear  (Spearman rho = {rho:.3f}, n={len(pair)})")
        ax.grid(alpha=0.25)

    # Reference line through the origin at the median points-per-report.
    # Points above it earn more per report than the typical hunter;
    # points below it earn less. This makes the quality-vs-volume split
    # visible without fitting a model.
    ppr_median = (pair["points"] / pair["reports"].replace(0, pd.NA)).median()
    if pd.notna(ppr_median):
        x_min = max(pair["reports"].min(), 1e-9)  # guard against 0 on log axis
        xs = [x_min, pair["reports"].max()]
        for ax in (ax_lin, ax_log):
            ax.plot(xs, [x * ppr_median for x in xs],
                    ls="--", lw=1, color="#C44E52",
                    label=f"median {ppr_median:.2f} pts/report")
            ax.legend(fontsize=9)

    fig.suptitle("Reports vs. points per hunter")
    fig.tight_layout()
    fig.savefig(out_dir / "reports_vs_points.png", dpi=150)
    plt.close(fig)
    print(f"[info] scatter written to {out_dir / 'reports_vs_points.png'}")


# --------------------------------------------------------------------------
# CSV export
# --------------------------------------------------------------------------

def export_csv(df: pd.DataFrame, out_dir: Path) -> Path:
    """Write name / reports / points / rank for external verification.

    points_per_report is included because it is the derived quantity the
    scatter is really about; recompute it yourself to check the export.
    """
    out = pd.DataFrame({
        "name":    df["hunter"] if "hunter" in df.columns else pd.NA,
        "reports": df["reports"] if "reports" in df.columns else pd.NA,
        "points":  df["points"] if "points" in df.columns else pd.NA,
        "rank":    df["rank"] if "rank" in df.columns else pd.NA,
    })
    out["points_per_report"] = (
        out["points"] / out["reports"].replace(0, pd.NA)
    ).round(4)

    out = out.sort_values("rank", na_position="last")
    path = out_dir / "hunter_points_reports.csv"
    out.to_csv(path, index=False, encoding="utf-8")
    print(f"[info] CSV written to {path}  ({len(out)} rows)")
    return path


# --------------------------------------------------------------------------

# Hardcoded paths relative to this script's location.
_SCRIPT_DIR = Path(__file__).resolve().parent
HUNTERS_DIR = _SCRIPT_DIR / "hunters"
OUT_DIR = _SCRIPT_DIR.parent / "Outputs"


def main() -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    df = clean(load_stats(HUNTERS_DIR))

    plot_scatter(df, OUT_DIR)

    # Guard: only run correlations if both columns exist.
    if "reports" in df.columns and "points" in df.columns:
        spearman(df, "reports", "points")
    else:
        print("[warn] skipping reports/points correlation: column(s) missing")

    # Sanity check, not a finding: if rank is derived from points, this
    # will come back near -1.00 and tells you nothing about hunter
    # behaviour -- only that you have correctly identified the platform's
    # ranking key. Treat a near-perfect value as confirmation, not signal.
    if "points" in df.columns and "rank" in df.columns:
        spearman(df, "points", "rank")
    else:
        print("[warn] skipping points/rank correlation: column(s) missing")

    export_csv(df, OUT_DIR)


if __name__ == "__main__":
    main()
```

</details>

## Shannon

<details>

<summary>ShannonEntropy.py — compute per-hunter Shannon entropy</summary>

Reads each hunter's `stats.json` and `hacktivities.json`, counts `"New"`-status reports by `bug_name`, computes Shannon entropy in bits, and writes `hunter_entropy.csv` (rank, username, country, new\_reports, distinct\_types, entropy\_bits).

```python
#!/usr/bin/env python3
"""
Shannon entropy of each hunter's bug-type distribution.

Reads from: hunters/<hunter_name>/{stats.json,hacktivities.json}
Writes to:  hunter_entropy.csv
"""

from __future__ import annotations

import csv
import json
import math
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
HUNTERS_DIR = HERE.parent / "Codes" / "hunters"
OUTPUT_CSV = HERE / "hunter_entropy.csv"


def load_json(path: Path):
    try:
        with path.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, json.JSONDecodeError, OSError) as exc:
        print(f"[warn] {path}: {exc}")
        return None


def shannon_entropy(counts: Counter) -> float:
    """H = -sum(p * log2 p), in bits. 0.0 for empty or single-category data."""
    total = sum(counts.values())
    if total == 0:
        return 0.0
    h = -sum(
        (c / total) * math.log2(c / total)
        for c in counts.values()
        if c > 0
    )
    return h if h > 0 else 0.0


def count_bug_types(hacktivities) -> Counter:
    if not isinstance(hacktivities, list):
        return Counter()
    return Counter(
        item.get("bug_name", "UNKNOWN")
        for item in hacktivities
        if isinstance(item, dict) and item.get("status") == "New"
    )


def build_report() -> list[dict]:
    rows = []
    for d in sorted(p for p in HUNTERS_DIR.iterdir() if p.is_dir()):
        stats = load_json(d / "stats.json") or {}
        counts = count_bug_types(load_json(d / "hacktivities.json"))
        rows.append({
            "username": stats.get("username", d.name),
            "rank": stats.get("rank", math.inf),
            "country": stats.get("country", "--"),
            "counts": counts,
            "total_new": sum(counts.values()),
            "entropy": shannon_entropy(counts),
        })
    rows.sort(key=lambda r: (r["rank"], r["username"].lower()))
    return rows


FIELDS = ["rank", "username", "country", "new_reports", "distinct_types", "entropy_bits"]


def write_csv(rows: list[dict]) -> None:
    with OUTPUT_CSV.open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({
                "rank": "" if r["rank"] == math.inf else r["rank"],
                "username": r["username"],
                "country": r["country"],
                "new_reports": r["total_new"],
                "distinct_types": len(r["counts"]),
                "entropy_bits": round(r["entropy"], 4),
            })


if __name__ == "__main__":
    if not HUNTERS_DIR.is_dir():
        raise SystemExit(f"hunters directory not found: {HUNTERS_DIR}")

    rows = build_report()
    write_csv(rows)

    print(f"[ok] {len(rows)} hunters written -> {OUTPUT_CSV}")
```

</details>

<details>

<summary>SpearmanCorrelation.py — rank vs. entropy_bits correlation and scatter</summary>

Loads `hunter_entropy.csv`, computes Spearman's rho between `rank` and `entropy_bits`, prints the significance verdict at α = 0.05, and saves an annotated scatter plot to `spearman_entropy_plot.png`.

```python
import pandas as pd
from typing import cast
from scipy.stats import spearmanr
import matplotlib.pyplot as plt

# Load data
df = pd.read_csv("hunter_entropy.csv")

# Compute Spearman correlation between rank and entropy_bits
rho, pvalue = cast(tuple[float, float], spearmanr(df["rank"], df["entropy_bits"]))

# Console output
print("Spearman Correlation (rank vs entropy_bits)")
print(f"  rho      : {rho:.4f}")
print(f"  p-value  : {pvalue:.4f}")
if pvalue < 0.05:
    print("  -> Statistically significant (p < 0.05)")
else:
    print("  -> Not statistically significant (p >= 0.05)")

# Scatter plot
fig, ax = plt.subplots(figsize=(8, 5))
ax.scatter(df["rank"], df["entropy_bits"], color="#3b82d4", alpha=0.7, edgecolors="white", linewidths=0.5)
ax.set_xlabel("Rank")
ax.set_ylabel("Entropy Bits")
ax.set_title("Spearman Correlation: Rank vs Entropy Bits")
ax.annotate(f"rho = {rho:.4f}  |  p = {pvalue:.4f}", xy=(0.05, 0.92), xycoords="axes fraction", fontsize=10, color="#57606a")
plt.tight_layout()
plt.savefig("spearman_entropy_plot.png", dpi=150)
print("\nPlot saved -> spearman_entropy_plot.png")
```

</details>

<details>

<summary>descriptive_stats.py — descriptive statistics for entropy metrics</summary>

Reads `hunter_entropy.csv` and prints descriptive statistics (count, mean, std, variance, quartiles) for `new_reports`, `distinct_types`, and `entropy_bits`, then lists the 10 most specialized (lowest entropy) and 10 most generalized (highest entropy) hunters.

```python
#!/usr/bin/env python3

import pandas as pd

CSV_FILE = "hunter_entropy.csv"


def main():
    df = pd.read_csv(CSV_FILE)

    numeric_cols = [
        "new_reports",
        "distinct_types",
        "entropy_bits",
    ]

    print("=" * 70)
    print("DESCRIPTIVE STATISTICS")
    print("=" * 70)

    stats = df[numeric_cols].describe().T

    # Add variance
    stats["variance"] = df[numeric_cols].var()

    # Reorder columns
    stats = stats[
        [
            "count",
            "mean",
            "std",
            "variance",
            "min",
            "25%",
            "50%",
            "75%",
            "max",
        ]
    ]

    stats = stats.round(4)
    print(stats)

    print("\n" + "=" * 70)
    print("TOP 10 BY LOWEST ENTROPY (Most Specialized)")
    print("=" * 70)
    print(
        df.sort_values("entropy_bits")
        [["username", "entropy_bits", "new_reports"]]
        .head(10)
        .to_string(index=False)
    )

    print("\n" + "=" * 70)
    print("TOP 10 BY HIGHEST ENTROPY (Most Generalized)")
    print("=" * 70)
    print(
        df.sort_values("entropy_bits", ascending=False)
        [["username", "entropy_bits", "new_reports"]]
        .head(10)
        .to_string(index=False)
    )


if __name__ == "__main__":
    main()
```

</details>
