# Source Scripts

## Overview

The `src/` folder holds the Python scripts used throughout this analysis, from scraping and CWE classification to entropy statistics and correlation testing. Expand a script below to read its full source and a short description of what it does.

<details>

<summary>CWEchecker.py — CWE / bug_name class mapper</summary>

Walks every `hunters/<hunter_name>/hacktivities.json` file and builds a mapping of `CWE-XX -> { bug_name variants seen under that CWE }`, along with occurrence counts per (CWE, bug\_name) pair. Prints a readable CWE tree to the console and saves the structured result as `cwe_class_map.json` — the raw input needed later for Shannon entropy calculations.

```python
"""
parse_cwe_classes.py

Walks ../hunters/<hunter_name>/hacktivities.json (relative to this script's
location in src/), and builds a mapping of:

    CWE-XX -> { bug_name variants seen under that CWE }

Also tracks occurrence counts per (cwe, bug_name) pair, since that's the
raw input you'll need later for Shannon entropy at either granularity.
"""
import json
from pathlib import Path
from collections import defaultdict, Counter

SCRIPT_DIR = Path(__file__).resolve().parent
HUNTERS_DIR = SCRIPT_DIR.parent / "hunters"


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
                continue

            cwe_to_bugnames[cwe].add(bug_name)
            cwe_bugname_counts[cwe][bug_name] += 1
            total_reports_scanned += 1

    return cwe_to_bugnames, cwe_bugname_counts, total_reports_scanned, hunters_scanned


def print_cwe_tree(cwe_to_bugnames, cwe_bugname_counts):
    for cwe in sorted(cwe_to_bugnames.keys()):
        bug_names = cwe_to_bugnames[cwe]
        counts = cwe_bugname_counts[cwe]
        total = sum(counts.values())

        print(f"{cwe} ({len(bug_names)} sub-types, {total} total reports)")

        for bug_name, count in counts.most_common():
            print(f"  L {bug_name:<50} ({count})")
        print()


def save_json(cwe_to_bugnames, cwe_bugname_counts, out_path: Path):
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

    out_path = SCRIPT_DIR / "cwe_class_map.json"
    save_json(cwe_to_bugnames, cwe_bugname_counts, out_path)
```

</details>

<details>

<summary>EDA.py — exploratory data analysis on hunter stats</summary>

Loads every `hunters/<name>/stats.json` into a single DataFrame, coercing numeric fields and normalizing country codes while reporting missingness explicitly rather than silently imputing it. Generates a country distribution + Pareto chart, a join-year histogram, and linear/log-scaled histograms for points and reports, printing quartiles, skew, and outlier counts for each.

```python
"""
Exploratory data analysis of hunter stats.json files.

Usage:
    python eda_stats.py [--hunters-dir PATH] [--out-dir PATH]
"""

import argparse
import json
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd


def load_stats(hunters_dir: Path) -> pd.DataFrame:
    """Read every hunters/<name>/stats.json into a single DataFrame.

    Deliberately tolerant: a malformed or missing file is reported and
    skipped rather than aborting the run.
    """
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
    print(f"[info] loaded {len(df)} hunters from {hunters_dir}")
    return df


def clean(df: pd.DataFrame) -> pd.DataFrame:
    """Coerce types and surface missingness explicitly."""
    df = df.copy()

    for col in ("points", "reports", "impact", "rank"):
        if col in df:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    if "joined" in df:
        df["joined_year"] = pd.to_numeric(df["joined"], errors="coerce").astype("Int64")

    if "country" in df:
        df["country"] = (
            df["country"].astype("string").str.strip().str.upper().replace("", pd.NA)
        )

    cols = [c for c in ("country", "joined_year", "points", "reports") if c in df]
    print("[info] missing values per field:")
    print(df[cols].isna().sum().to_string())

    return df


def plot_country(df: pd.DataFrame, out_dir: Path, top_n: int = 20) -> pd.Series:
    counts = df["country"].value_counts(dropna=True)

    fig, (ax_bar, ax_pareto) = plt.subplots(1, 2, figsize=(15, 5.5))

    shown = counts.head(top_n)
    ax_bar.bar(shown.index.astype(str), shown.values, color="#4C72B0")
    ax_bar.set_title(f"Hunters by country (top {min(top_n, len(counts))} of {len(counts)})")
    ax_bar.set_xlabel("Country")
    ax_bar.set_ylabel("Number of hunters")
    ax_bar.tick_params(axis="x", rotation=45)

    cum_share = counts.cumsum() / counts.sum()
    ax_pareto.plot(range(1, len(cum_share) + 1), cum_share.values,
                   marker="o", markersize=3, color="#C44E52")
    ax_pareto.axhline(0.8, ls="--", lw=1, color="grey")
    ax_pareto.set_ylim(0, 1.02)
    ax_pareto.set_title("Cumulative share of hunters by country rank")
    ax_pareto.set_xlabel("Country rank (most hunters first)")
    ax_pareto.set_ylabel("Cumulative share")
    ax_pareto.text(len(cum_share) * 0.6, 0.82, "80%", color="grey", fontsize=9)

    fig.tight_layout()
    fig.savefig(out_dir / "country_distribution.png", dpi=150)
    plt.close(fig)

    n_for_80 = int((cum_share < 0.8).sum()) + 1
    print(f"\n[country] {len(counts)} distinct countries; "
          f"top {n_for_80} account for ~80% of hunters")
    print(counts.head(10).to_string())
    return counts


def plot_hist(series: pd.Series, label: str, out_dir: Path,
              filename: str, bins="auto", log_x: bool = False) -> None:
    """Histogram for one numeric field, plus a summary printed to stdout."""
    data = series.dropna()
    if data.empty:
        print(f"[warn] no data for {label}, skipping")
        return

    fig, ax = plt.subplots(figsize=(8, 5))
    ax.hist(data, bins=bins, color="#55A868", edgecolor="white")
    ax.set_title(f"{label} — histogram (n={len(data)})")
    ax.set_xlabel(f"{label} (log scale)" if log_x else label)
    ax.set_ylabel("Number of hunters")
    if log_x:
        ax.set_xscale("log")

    fig.tight_layout()
    fig.savefig(out_dir / filename, dpi=150)
    plt.close(fig)

    q1, q3 = data.quantile(0.25), data.quantile(0.75)
    iqr = q3 - q1
    outliers = data[(data < q1 - 1.5 * iqr) | (data > q3 + 1.5 * iqr)]

    print(f"\n[{label}]")
    print(data.describe().to_string())
    print(f"  IQR                 {iqr:.2f}")
    print(f"  skew                {data.skew():.2f}")
    print(f"  beyond 1.5*IQR      {len(outliers)} "
          f"({len(outliers) / len(data):.1%})")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--hunters-dir", type=Path,
                        default=Path(__file__).resolve().parent.parent / "hunters")
    parser.add_argument("--out-dir", type=Path,
                        default=Path(__file__).resolve().parent / "eda_output")
    args = parser.parse_args()

    args.out_dir.mkdir(parents=True, exist_ok=True)

    df = clean(load_stats(args.hunters_dir))

    plot_country(df, args.out_dir)

    years = df["joined_year"].dropna().astype(int)
    if not years.empty:
        year_bins = [b - 0.5 for b in range(years.min(), years.max() + 2)]
        plot_hist(years, "Join year", args.out_dir,
                  "joined_distribution.png", bins=year_bins)
        print("\n[join year] counts:")
        print(years.value_counts().sort_index().to_string())

    for col, label, stem in (("points", "Points", "points"),
                             ("reports", "Reports", "reports")):
        if col not in df:
            print(f"[warn] column '{col}' absent, skipping")
            continue
        plot_hist(df[col], label, args.out_dir, f"{stem}_distribution.png", bins=30)
        plot_hist(df[col], label, args.out_dir, f"{stem}_distribution_log.png",
                  bins=30, log_x=True)

    print(f"\n[done] plots written to {args.out_dir}")


if __name__ == "__main__":
    main()
```

</details>

<details>

<summary>descriptive_stats.py — descriptive stats + rank vs. entropy plot</summary>

Reads `hunter_entropy.csv` and prints descriptive statistics (count, mean, std, variance, quartiles) for rank and entropy metrics, plus a country breakdown. Lists the 10 most specialized (lowest normalized entropy) and 10 most generalized (highest normalized entropy) hunters, then plots rank vs. normalized entropy with a LOWESS trend line and reports the Spearman correlation.

```python
#!/usr/bin/env python3

import pandas as pd
import matplotlib.pyplot as plt
from statsmodels.nonparametric.smoothers_lowess import lowess
from scipy.stats import spearmanr

CSV_FILE = "hunter_entropy.csv"


def main():
    df = pd.read_csv(CSV_FILE)

    numeric_cols = [
        "rank",
        "new_reports",
        "distinct_types",
        "entropy_bits",
        "entropy_max",
        "entropy_norm",
    ]

    print("=" * 70)
    print("DESCRIPTIVE STATISTICS")
    print("=" * 70)

    stats = df[numeric_cols].describe().T
    stats["variance"] = df[numeric_cols].var()
    stats = stats[["count", "mean", "std", "variance", "min", "25%", "50%", "75%", "max"]]
    stats = stats.round(4)

    print(stats)

    print("\n" + "=" * 70)
    print("COUNTRY DISTRIBUTION")
    print("=" * 70)
    print(df["country"].value_counts())

    print("\n" + "=" * 70)
    print("TOP 10 BY LOWEST ENTROPY (Most Specialized)")
    print("=" * 70)
    print(
        df.sort_values("entropy_norm")
        [["rank", "username", "entropy_norm", "new_reports"]]
        .head(10)
        .to_string(index=False)
    )

    print("\n" + "=" * 70)
    print("TOP 10 BY HIGHEST ENTROPY (Most Generalized)")
    print("=" * 70)
    print(
        df.sort_values("entropy_norm", ascending=False)
        [["rank", "username", "entropy_norm", "new_reports"]]
        .head(10)
        .to_string(index=False)
    )

    rho, p = spearmanr(df["rank"], df["entropy_norm"])

    smoothed = lowess(
        endog=df["entropy_norm"],
        exog=df["rank"],
        frac=0.3
    )

    plt.figure(figsize=(8, 5))
    plt.scatter(df["rank"], df["entropy_norm"], alpha=0.7, label="Hunters")
    plt.plot(smoothed[:, 0], smoothed[:, 1], color="red", linewidth=2, label="LOWESS Trend")
    plt.xlabel("Rank")
    plt.ylabel("Normalized Entropy")
    plt.title(f"Rank vs Normalized Entropy\nSpearman ρ = {rho:.3f}, p = {p:.4f}")
    plt.grid(True, linestyle="--", alpha=0.4)
    plt.legend()
    plt.tight_layout()
    plt.show()

    print("=" * 60)
    print("Spearman Rank Correlation")
    print("=" * 60)
    print(f"Correlation coefficient (ρ): {rho:.4f}")
    print(f"P-value: {p:.6f}")

    alpha = 0.05
    if p < alpha:
        print("Result: Statistically significant (reject H0)")
    else:
        print("Result: Not statistically significant (fail to reject H0)")


if __name__ == "__main__":
    main()
```

</details>

<details>

<summary>hunter_probe.py — single-hunter feed completeness &#x26; censoring diagnostic</summary>

Fetches one hunter's full hacktivity feed from the YesWeHack API (with pagination and 429 retry/backoff handling) and diagnoses it in stages: checks whether the collected row count matches the API's declared `nb_results` (the completeness gate); tests whether `new`-status density is depressed in the oldest slice of the feed, distinguishing left-censoring from reports that were simply never public; flags same-day duplicate event clusters that could inflate counts; and prints yearly density plus data-quality issues like unknown status values.

```python
#!/usr/bin/env python3
"""
hunter_probe.py

Fetch and diagnose ONE hunter's YesWeHack hacktivity feed.

What this tests, in priority order:

  GATE (H0)  collected rows == pagination.nb_results ?
             Until this passes nothing below is interpretable, because a
             truncated scrape mimics exactly the effect being measured.

  POSITION   Is 'new' density depressed in the OLDEST slice of the feed?
             Reports submitted before the feed window contribute terminal
             events inside it but their 'new' falls outside -> left-censoring
             (H1, bounded). Flat density instead means the missing reports were
             never in the public feed at all (H2).

Usage:
    python hunter_probe.py Geluchat
    python hunter_probe.py Geluchat --official 358
    python hunter_probe.py Geluchat --refetch --per-page 100
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

import requests

API = "https://api.yeswehack.com/v2/hacktivity/{username}"

KNOWN_STATUSES = {
    "new", "under review", "need more info", "accepted", "resolved", "closed",
    "duplicate", "not applicable", "invalid", "out of scope", "spam", "rtfs",
    "informative", "wont fix", "won't fix", "not valid",
}


def fetch_pages(username: str, per_page: int = 10, delay: float = 2.0) -> list[dict]:
    """Walk every page, returning the raw page blobs including pagination."""
    session = requests.Session()
    pages: list[dict] = []
    page = 1
    first_total: int | None = None

    while True:
        url = f"{API.format(username=username)}?page={page}&resultsPerPage={per_page}"

        attempt = 0
        while True:
            r = session.get(url, timeout=30)
            if r.status_code != 429:
                r.raise_for_status()
                break
            wait = max(delay * (2 ** attempt), 1.0)
            retry_after = r.headers.get("Retry-After")
            if retry_after:
                try:
                    wait = max(wait, float(retry_after))
                except ValueError:
                    pass
            print(f"    rate limited on page {page}; waiting {wait:.1f}s")
            time.sleep(wait)
            attempt += 1

        blob = r.json()
        pages.append(blob)

        pg = blob["pagination"]
        total = pg.get("nb_results")
        if first_total is None:
            first_total = total
        elif total != first_total:
            print(f"    ! nb_results drifted {first_total} -> {total} at page {page}",
                  file=sys.stderr)

        print(f"    page {pg['page']}/{pg['nb_pages']} "
              f"({len(blob.get('items', []))} items)")

        if page >= pg["nb_pages"]:
            break
        page += 1
        time.sleep(delay)

    return pages


@dataclass
class Row:
    date: str
    status: str
    slug: str
    name: str
    cwe: str | None


@dataclass
class Feed:
    handle: str
    rows: list[Row] = field(default_factory=list)
    declared: int | None = None
    nb_pages: int | None = None
    per_page: int | None = None


def split_cwe(raw_name: str) -> tuple[str, str | None]:
    """CWE is embedded in the display name as a trailing '(CWE-nnn)'."""
    if raw_name.endswith(")") and "(CWE-" in raw_name:
        head, _, tail = raw_name.rpartition("(CWE-")
        digits = "".join(c for c in tail if c.isdigit())
        if digits:
            return head.strip(), f"CWE-{digits}"
    return raw_name, None


def build_feed(handle: str, pages: list[dict]) -> Feed:
    feed = Feed(handle)
    for p in pages:
        pg = p.get("pagination") or {}
        feed.declared = pg.get("nb_results", feed.declared)
        feed.nb_pages = pg.get("nb_pages", feed.nb_pages)
        feed.per_page = pg.get("results_per_page", feed.per_page)
        for item in p.get("items", []):
            bt = item.get("bug_type") or {}
            name, cwe = split_cwe(bt.get("name") or "")
            feed.rows.append(Row(
                date=(item.get("date") or "")[:10],
                status=(item.get("status") or "").strip().lower(),
                slug=bt.get("slug") or "<no-slug>",
                name=name or "<no-name>",
                cwe=cwe,
            ))

    feed.rows.reverse()
    return feed


def bar(share: float, width: int = 22) -> str:
    n = int(round(share * width))
    return "#" * n + "." * (width - n)


def analyse(feed: Feed, official: int | None, bins: int = 10) -> bool:
    rows = feed.rows
    n = len(rows)
    print("=" * 72)
    print(f"HUNTER: {feed.handle}")
    print("=" * 72)

    print("\n[GATE] SCRAPE COMPLETENESS")
    print(f"    collected     : {n}")
    print(f"    declared      : {feed.declared}")
    print(f"    pages x size  : {feed.nb_pages} x {feed.per_page}")
    if feed.declared is None:
        print("    verdict       : UNKNOWN (no pagination metadata)")
        gate = False
    elif n == feed.declared:
        print("    verdict       : PASS")
        gate = True
        if feed.declared in (100, 200, 250, 500, 1000, 2000, 5000):
            print(f"    ! declared is a suspiciously round {feed.declared} "
                  f"-- possible server-side cap, not a true total")
    else:
        print(f"    verdict       : FAIL -- {feed.declared - n} rows short")
        print("    Fix the scraper before reading anything below.")
        gate = False

    if not n:
        return gate

    n_new = sum(1 for r in rows if r.status == "new")
    print("\n[1] COUNT")
    print(f"    new-rows      : {n_new}    <- the estimator")
    print(f"    total rows    : {n}")
    if n_new:
        print(f"    rows per new  : {n / n_new:.2f}   <- events per report")
    if official:
        gap = official - n_new
        print(f"    official      : {official}")
        print(f"    gap           : {gap} ({gap / official:.1%})")

        if gap > 0 and n_new:
            h1_ratio = n / official
            h2_ratio = n / n_new
            print(f"\n    events-per-report under each hypothesis:")
            print(f"      H1 censoring (rows/official) : {h1_ratio:.2f}")
            print(f"      H2 never-public (rows/new)   : {h2_ratio:.2f}")
            missing_rows = gap * h2_ratio
            print(f"    If H2: ~{missing_rows:.0f} rows absent "
                  f"({n + missing_rows:.0f} expected vs {n} present)")

    size = max(1, n // bins)
    print("\n[2] POSITION TEST (oldest -> newest)   <- H1 vs H2")
    print(f"    {'bin':>4} {'rows':>6} {'new':>6} {'share':>7}  window")
    shares = []
    for b in range(bins):
        lo = b * size
        hi = n if b == bins - 1 else (b + 1) * size
        chunk = rows[lo:hi]
        if not chunk:
            continue
        k = sum(1 for r in chunk if r.status == "new")
        share = k / len(chunk)
        shares.append(share)
        print(f"    {b+1:>4} {len(chunk):>6} {k:>6} {share:>6.1%}  "
              f"{chunk[0].date}..{chunk[-1].date}  {bar(share)}")
    if len(shares) > 2:
        oldest = shares[0]
        newest = shares[-1]
        middle = sum(shares[1:-1]) / max(1, len(shares) - 2)
        print(f"\n    oldest bin {oldest:.1%} | middle mean {middle:.1%} "
              f"| newest bin {newest:.1%}")

        if middle and oldest < middle * 0.85:
            print("    VERDICT: oldest depressed -> H1 left-censoring (bounded)")
        elif middle and oldest > middle * 1.15:
            print("    VERDICT: oldest ELEVATED -> not censoring. Feed likely")
            print("             starts at this hunter's first submission.")
        else:
            print("    VERDICT: flat -> no censoring. Any gap is H2 "
                  "(reports never public).")
        if middle and newest < middle * 0.85:
            print("    (newest bin depressed: in-flight reports, benign)")

    clusters = Counter((r.date, r.slug, r.status) for r in rows)
    dup_rows = sum(c - 1 for c in clusters.values() if c > 1)
    print("\n[3] IDENTICAL (date, type, status) CLUSTERS")
    print(f"    rows in clusters of >1 : {dup_rows} ({dup_rows / n:.1%})")
    for (d, slug, st), c in clusters.most_common(5):
        if c > 1:
            print(f"      x{c:<3} {d}  {st:<10} {slug[:40]}")
    dup_new = sum(c - 1 for (d, s, st), c in clusters.items()
                  if st == "new" and c > 1)
    print(f"    of which status='new'  : {dup_new}")
    print("    ^ if this is large, count('new') may be inflated")

    per_year: dict[str, Counter] = defaultdict(Counter)
    for r in rows:
        y = r.date[:4] or "????"
        per_year[y]["rows"] += 1
        per_year[y]["new"] += 1 if r.status == "new" else 0
        per_year[y]["nocwe"] += 1 if r.cwe is None else 0
    print("\n[4] YEARLY DENSITY")
    print(f"    {'year':>6} {'rows':>6} {'new':>6} {'no-cwe':>7} {'rate':>7}")
    for y in sorted(per_year):
        c = per_year[y]
        print(f"    {y:>6} {c['rows']:>6} {c['new']:>6} {c['nocwe']:>7} "
              f"{c['nocwe'] / c['rows']:>6.1%}")

    statuses = Counter(r.status for r in rows)
    unknown = {s: c for s, c in statuses.items() if s not in KNOWN_STATUSES}
    nocwe = sum(1 for r in rows if r.cwe is None)
    print("\n[5] DATA QUALITY")
    for s, c in statuses.most_common():
        print(f"    {s:<22} {c:>6}")
    print(f"    rows without CWE     : {nocwe} ({nocwe / n:.1%})")
    print(f"    unknown statuses     : {unknown or 'none'}")
    if unknown:
        print("    ^ the 4-value vocabulary is a normalisation artifact")

    acc = statuses.get("accepted", 0)
    clo = statuses.get("closed", 0)
    if acc + clo > n_new:
        print(f"\n    NOTE: accepted+closed ({acc + clo}) > new ({n_new}).")
        print("    Either reports are missing their 'new', or a report can be")
        print("    both accepted and later closed. Check [3] before concluding.")
    print()
    return gate


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("handle")
    ap.add_argument("--official", type=int, default=None,
                    help="official report count from the hunter's stats")
    ap.add_argument("--cache", type=Path, default=Path("feeds"))
    ap.add_argument("--refetch", action="store_true")
    ap.add_argument("--per-page", type=int, default=10,
                    help="try 100; verify pagination.results_per_page honours it")
    ap.add_argument("--delay", type=float, default=2.0)
    args = ap.parse_args()

    args.cache.mkdir(parents=True, exist_ok=True)
    path = args.cache / f"{args.handle}.json"

    if path.exists() and not args.refetch:
        print(f"using cached {path}")
        pages = json.loads(path.read_text(encoding="utf-8"))
    else:
        print(f"fetching {args.handle} ...")
        try:
            pages = fetch_pages(args.handle, args.per_page, args.delay)
        except requests.RequestException as exc:
            print(f"fetch failed: {exc}", file=sys.stderr)
            return 1
        path.write_text(json.dumps(pages), encoding="utf-8")
        print(f"cached -> {path}")

    feed = build_feed(args.handle, pages)
    return 0 if analyse(feed, args.official) else 2


if __name__ == "__main__":
    raise SystemExit(main())
```

</details>

<details>

<summary>manualspearman.py — quick Spearman correlation (rank vs. entropy_bits)</summary>

Minimal script that loads `hunter_entropy.csv` and computes the Spearman rank correlation between `rank` and `entropy_bits`, printing N, rho, degrees of freedom, and p-value.

```python
from pathlib import Path

import pandas as pd
from scipy.stats import spearmanr

df = pd.read_csv("hunter_entropy.csv")

rank = df["rank"]
entropy = df["entropy_bits"]

rho, p_value = spearmanr(rank, entropy)

n = len(df)
dfree = n - 2

print("Spearman Correlation")
print("--------------------")
print(f"N            : {n}")
print(f"rho          : {rho:.3f}")
print(f"df           : {dfree}")
print(f"p-value      : {p_value:.3g}")
```

</details>
