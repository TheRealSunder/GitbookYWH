---
description: >-
  How the raw hacktivity export for 81 hunters is cleaned, normalized, and
  verified before any entropy or correlation analysis.
icon: broom
---

# Data Preprocessing

## Overview

The raw hacktivity export cannot be analysed as-is. Three problems make the raw label field unusable as a categorical variable:

1. **Multiple naming schemes.** The same vulnerability family appears under canonical HackerOne labels, OWASP Top 10 (2017) labels, and OWASP Top 10 (2013) labels.
2. **Records with no vulnerability.** Rows marked `Not Applicable (CWE-NULL)` or `None Applicable` carry no CWE and describe no finding.
3. **Missing CWE fields.** Legacy-labelled records were never assigned a CWE identifier, so any CWE-keyed aggregation silently dropped them.

{% hint style="info" %}
**Counting rule.** Only reports with `status == "New"` are counted throughout this page. The full resolution chain (`accepted → resolved → closed`) was considered and rejected: status history is inconsistent across submissions — some reports jump straight from `new` to `closed`, others cycle through intermediate states. Counting `new` gives exactly one stable, non-duplicated observation per report.
{% endhint %}

***

## Method: The Preprocessing Pipeline

Three scripts run in sequence to clean the label field; two more are independent supporting scripts.

| Order | Script                    | Role                                                                               |
| :---: | ------------------------- | ---------------------------------------------------------------------------------- |
|   1   | `stat_checker.py`         | Baseline count of `bug_name` and `cwe` over `status == "New"` reports              |
|   2   | `normalize_hacktivity.py` | Collapse legacy labels to canonical names, attach CWEs, delete non-applicable rows |
|   3   | `stat_checker.py`         | Re-count after normalization, to verify the transformation                         |

| Supporting script                 | Role                                                                       |
| --------------------------------- | -------------------------------------------------------------------------- |
| `CWEchecker.py`                   | Builds the CWE → sub-type tree (`cwe_class_map.json`)                      |
| `parse_stats.py`                  | Flattens per-hunter profile metadata into `hunter_stats.csv`               |
| `hunter_hacktivity_per_hunter.py` | Counts `New` reports per hunter, for cross-checking against profile totals |

Each script below shows the **input** it reads, the **exact code** that turns that input into output, and the **output format** it produces.

### `stat_checker.py` — baseline and verification count

{% tabs %}
{% tab title="Input" %}
`Codes/hunters/<hunter>/hacktivities.json` for every hunter folder — one JSON array of report objects per hunter, each carrying at least `status`, `bug_name`, and `cwe`. The script is run twice against this same input: once before `normalize_hacktivity.py` touches the files (baseline), and once after (verification).
{% endtab %}

{% tab title="Transform" %}
```python
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
```

Two `Counter` objects accumulate frequencies across every hunter folder; nothing is written back to the source files — this script only reads and tallies.
{% endtab %}

{% tab title="Output" %}
Plain text, printed to stdout and written to `Outputs/stat_checker_output.txt`:

```
Processed 81 hunters
New reports with bug_name: 33804
New reports with CWE:      32830

=== Bug Types (status = new) ===
 5267  Cross-site Scripting (XSS) - Reflected
 5118  Improper Access Control - Generic
 ...

=== CWEs (status = new) ===
 8787  CWE-79
 5118  CWE-284
 ...
```
{% endtab %}
{% endtabs %}

### `normalize_hacktivity.py` — label normalization

{% tabs %}
{% tab title="Input" %}
The same `Codes/hunters/<hunter>/hacktivities.json` files — but this run **mutates them in place**. Every record is read and reclassified regardless of `status` (a legacy label needs fixing whether the report is new or closed), and the file is rewritten if anything changed.

Labels are matched by a normalized key, not by literal string match, so punctuation and casing drift in the export don't cause misses:

```python
_TRAILING_CWE = re.compile(r"\s*\(CWE-[\w\d]+\)\s*$", re.IGNORECASE)
_NON_ALNUM    = re.compile(r"[^a-z0-9]+")

def normalize_key(label: str) -> str:
    return _NON_ALNUM.sub(" ", strip_cwe_suffix(label).lower()).strip()
```

`OWASP-A7-XSS`, `owasp a7 xss`, and `OWASP-A7-XSS (CWE-79)` all reduce to the same key, `owasp a7 xss`.
{% endtab %}

{% tab title="Transform" %}
```python
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
```

Records classified `deleted` are dropped from the array before the file is written back; everything else is kept with `bug_name` / `cwe` / `bug_type_raw` overwritten to the canonical form.
{% endtab %}

{% tab title="Output" %}
The source JSON files are rewritten on disk, and a run summary is captured to `Outputs/normalize_hacktivity.txt`:

```
=== DONE — 81 file(s) processed ===
  rewritten              1961
  inferred                140
  already_canonical     38284
  deleted                 397
  unknown               43290

--- Inferred root cause (category-level legacy labels) ---
     72x  OWASP-A1-Injection
     68x  OWASP-2013-A1-Injection
```

{% hint style="info" %}
These action counts are taken over **every** record regardless of status, which is why they don't match the `New`-only totals elsewhere on this page — `normalize_hacktivity.py` doesn't filter by status, since a legacy label needs fixing no matter what state the report is in.
{% endhint %}
{% endtab %}
{% endtabs %}

### `CWEchecker.py` — CWE → sub-type tree

{% tabs %}
{% tab title="Input" %}
`Codes/hunters/<hunter>/hacktivities.json`, read after `normalize_hacktivity.py` has already run — so the sub-type tree reflects canonical labels wherever normalization succeeded. Every `status` is included, not just `New`.
{% endtab %}

{% tab title="Transform" %}
```python
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
```
{% endtab %}

{% tab title="Output" %}
A tree printed to stdout, and the same structure serialized to `Outputs/cwe_class_map.json`:

```json
{
  "CWE-1104": {
    "sub_types": ["Use of Vulnerable Third-Party Component"],
    "counts": { "Use of Vulnerable Third-Party Component": 90 }
  }
}
```

Current run: 81 hunters scanned, 83,675 records (all statuses), 90 distinct CWE keys.
{% endtab %}
{% endtabs %}

### `parse_stats.py` — per-hunter profile metadata

{% tabs %}
{% tab title="Input" %}
`Codes/hunters/<hunter>/stats.json` — one profile summary object per hunter.
{% endtab %}

{% tab title="Transform" %}
```python
COLUMNS = ["username", "joined", "impact", "reports", "points", "rank", "country"]
...
rows.append({col: data.get(col, "") for col in COLUMNS})
```

Each hunter's profile JSON is reduced to exactly these seven fields, with missing fields defaulting to an empty string rather than raising.
{% endtab %}

{% tab title="Output" %}
`Outputs/hunter_stats.csv`, header + one row per hunter (81 rows currently):

```
username,joined,impact,reports,points,rank,country
0xd0m7,2019,19.38,180,3233,82,ES
0xsnpaii,2023,13.57,436,5448,45,NG
```
{% endtab %}
{% endtabs %}

### `hunter_hacktivity_per_hunter.py` — per-hunter `New`-report counts

{% tabs %}
{% tab title="Input" %}
`Codes/hunters/<hunter>/hacktivities.json` for every hunter folder.
{% endtab %}

{% tab title="Transform" %}
```python
report_count = sum(
    1 for report in hacktivities
    if report.get("status") == "New"
)
```
{% endtab %}

{% tab title="Output" %}
A CSV sorted by count descending, `hunter,hacktivity_report_count`:

```
hunter,hacktivity_report_count
rabhi,5610
Xiety,1520
drak3hft7,1211
```
{% endtab %}
{% endtabs %}

***

## Result

### Baseline (before normalization)

| Measure                                   |   Count |
| ----------------------------------------- | ------: |
| Hunters processed                         |      81 |
| New reports carrying a `bug_name`         |  33,804 |
| New reports carrying a `cwe`              |  32,830 |
| **Gap (records with a label but no CWE)** | **974** |
| Distinct `bug_name` labels                |     117 |
| Distinct CWE identifiers                  |      90 |

### Legacy → Canonical Mapping

Each legacy label is mapped to the canonical name and CWE that already describes the same weakness elsewhere in the dataset, so OWASP 2013/2017 phrasing and the modern label collapse into one identifier instead of being counted as separate outcomes. Where a legacy category has no precise one-to-one CWE of its own — `OWASP-2013-A9-Using Components with Known Vulnerabilities` nominally corresponds to `CWE-937`, which is a non-specific MITRE _category_ rather than an actual weakness — the closest concrete, mapping-eligible weakness describing the same risk is used instead (`CWE-1104`), so the resulting CWE stays a real, lookup-able identifier rather than a placeholder. One mapping, `OWASP-A1-Injection` → `CWE-77`, is explicitly flagged as **inferred** rather than a direct rename, since that legacy label names an entire category of injection without stating which sub-type actually occurred.

{% tabs %}
{% tab title="Part 1 of 2" %}
| Legacy label(s)                                                                                                                            | Canonical name                          | CWE       |
| ------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------- | --------- |
| `OWASP-A7-XSS`, `OWASP-A7-Cross-Site Scripting (XSS)`, `OWASP-2013-A3-XSS`, `OWASP-2013-A3-Cross-Site Scripting (XSS)`                     | Cross-site Scripting (XSS) - Generic    | `CWE-79`  |
| `OWASP-A6-Security Misconfiguration`, `OWASP-2013-A5`, `OWASP-2013-A5-Security Misconfiguration`                                           | Server Misconfiguration                 | `CWE-16`  |
| `OWASP-A1-Injection`, `OWASP-2013-A1-Injection` <sup>†</sup>                                                                               | Command Injection - Generic             | `CWE-77`  |
| `OWASP-A2-Broken Authentication`, `OWASP-2013-A2-Broken Authentication and Session Management`, `OWASP-2013-A2-Broken Auth & Session Mgmt` | Improper Authentication - Generic       | `CWE-287` |
| `OWASP-A5-Broken Access Control`, `OWASP-2013-A7-Missing Function Level Access Control`                                                    | Improper Access Control - Generic       | `CWE-284` |
| `OWASP-2013-A4-Insecure Direct Object References`                                                                                          | Insecure Direct Object Reference (IDOR) | `CWE-639` |
{% endtab %}

{% tab title="Part 2 of 2" %}
| Legacy label(s)                                                                                                                                                                                                                                  | Canonical name                          | CWE        |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------- | ---------- |
| `OWASP-2013-A8-CSRF`, `OWASP-2013-A8-Cross-Site Request Forgery (CSRF)`                                                                                                                                                                          | Cross-Site Request Forgery (CSRF)       | `CWE-352`  |
| `OWASP-A3-Sensitive Data Exposure`, `OWASP-2013-A6`, `OWASP-2013-A6-Sensitive Data Exposure`                                                                                                                                                     | Information Disclosure                  | `CWE-200`  |
| `OWASP-2013-A10-Unvalidated Redirects and Forwards`                                                                                                                                                                                              | Open Redirect                           | `CWE-601`  |
| `OWASP-A4-XXE`, `OWASP-A4-XML External Entities (XXE)`                                                                                                                                                                                           | XML External Entity (XXE)               | `CWE-611`  |
| `OWASP-A9`, `OWASP-A9-Using Components with Known Vulnerabilities`, `OWASP-2013-A9`, `OWASP-2013-A9-Using Components with Known Vulnerabilities`, `Dependency on Vulnerable Third-Party Component`, `Use of Unmaintained Third Party Components` | Use of Vulnerable Third-Party Component | `CWE-1104` |
| `OWASP-A10-Insufficient Logging&Monitoring`, `OWASP-A10-Insufficient Logging & Monitoring`                                                                                                                                                       | Insufficient Logging                    | `CWE-778`  |
{% endtab %}
{% endtabs %}

{% hint style="warning" %}
<sup>†</sup> **Inferred mapping.** `OWASP-A1-Injection` is a _category_ label — it does not state which injection sub-type occurred. It is mapped to `Command Injection - Generic (CWE-77)` as an inferred root cause and tagged `inferred` in the normalization report so the assumption stays visible downstream. 140 records (all statuses) carry this inferred label; 54 of those are `status == "New"`. Confidence in this specific mapping is **low**; every other mapping in the table is a one-to-one rename and is **high** confidence.
{% endhint %}

### Deleted Records

Records flagged as not applicable carry no exploitable finding and no usable CWE. They are removed from the JSON rather than retained with a null, so downstream code never has to special-case an empty category.

| Deleted label               | New-status records removed |
| --------------------------- | -------------------------: |
| `Not Applicable (CWE-NULL)` |                        110 |
| `None Applicable`           |                         45 |
| **Total**                   |                    **155** |

### After Normalization

| Measure                     |  Count |
| --------------------------- | -----: |
| New reports with `bug_name` | 33,649 |
| New reports with `cwe`      | 33,649 |
| Gap (`bug_name` − `cwe`)    |      0 |
| Distinct `bug_name` labels  |     98 |
| Distinct CWE identifiers    |     90 |

* `bug_name` fell by exactly 155 — the deletions above, nothing else.
* `cwe` rose by 819 (32,830 → 33,649). The 974-record gap resolves as `155 deleted + 819 relabelled = 974`.
* Distinct labels fell from 117 to 98: 23 legacy labels went to zero, 4 canonical labels appeared for the first time (`Server Misconfiguration`, `Use of Vulnerable Third-Party Component`, `XML External Entity (XXE)`, `Insufficient Logging`).
* Distinct CWE count is unchanged at 90, but membership shifted: `CWE-1395` (6 pre-existing records) was absorbed into `CWE-1104`, and `CWE-778` entered the set for the first time.

***

## Bug-Name Frequency (Post-Normalization)

33,649 labelled reports across 98 distinct `bug_name` values. Split at 50 reports for readability.

{% tabs %}
{% tab title="High-frequency (≥ 50) — 43 labels" %}
| Count | Bug name                                                                    |  Share |
| ----: | --------------------------------------------------------------------------- | -----: |
| 5,267 | Cross-site Scripting (XSS) - Reflected                                      | 15.65% |
| 5,176 | Improper Access Control - Generic                                           | 15.38% |
| 4,519 | Insecure Direct Object Reference (IDOR)                                     | 13.43% |
| 2,057 | Business Logic Errors                                                       |  6.11% |
| 1,940 | Information Disclosure                                                      |  5.77% |
| 1,651 | Cross-site Scripting (XSS) - Stored                                         |  4.91% |
| 1,595 | Open Redirect                                                               |  4.74% |
| 1,131 | Violation of Secure Design Principles                                       |  3.36% |
| 1,029 | Cross-site Scripting (XSS) - Generic                                        |  3.06% |
|   909 | SQL Injection                                                               |  2.70% |
|   845 | Cross-Site Request Forgery (CSRF)                                           |  2.51% |
|   681 | Improper Authentication - Generic                                           |  2.02% |
|   583 | Cross-site Scripting (XSS) - DOM                                            |  1.73% |
|   560 | Server-Side Request Forgery (SSRF)                                          |  1.66% |
|   472 | Code Injection                                                              |  1.40% |
|   470 | HTML Injection                                                              |  1.40% |
|   429 | Server Misconfiguration - Subdomain Takeover                                |  1.27% |
|   357 | Acceptance of Extraneous Untrusted Data With Trusted Data - Cache Poisoning |  1.06% |
|   346 | Path Traversal                                                              |  1.03% |
|   326 | OS Command Injection                                                        |  0.97% |
|   240 | Resource Injection                                                          |  0.71% |
|   234 | Denial of Service                                                           |  0.70% |
|   210 | Server Misconfiguration                                                     |  0.62% |
|   181 | Brute Force                                                                 |  0.54% |
|   155 | Use of Hard-coded Credentials                                               |  0.46% |
|   136 | Insufficient Session Expiration                                             |  0.40% |
|   133 | Cleartext Storage of Sensitive Information                                  |  0.40% |
|   122 | Command Injection - Generic                                                 |  0.36% |
|   104 | Direct Request                                                              |  0.31% |
|   100 | Insecure Storage of Sensitive Information                                   |  0.30% |
|    99 | Unrestricted Upload of File with Dangerous Type                             |  0.29% |
|    99 | Information Exposure Through Debug Information                              |  0.29% |
|    98 | Use of Weak Credentials                                                     |  0.29% |
|    85 | Race Condition                                                              |  0.25% |
|    74 | Cleartext Transmission of Sensitive Information                             |  0.22% |
|    74 | Improper Neutralization of Input Used for LLM Prompting                     |  0.22% |
|    68 | Information Exposure Through an Error Message                               |  0.20% |
|    66 | XML External Entities (XXE)                                                 |  0.20% |
|    64 | Privacy Violation                                                           |  0.19% |
|    63 | Deserialization of Untrusted Data                                           |  0.19% |
|    54 | Information Exposure Through Directory Listing                              |  0.16% |
|    52 | Use of Default Credentials                                                  |  0.15% |
|    50 | Weak Password Mechanism for Forgotten Password                              |  0.15% |
{% endtab %}

{% tab title="Long-tail (< 50) — 55 labels" %}
| Count | Bug name                                                                     |
| ----: | ---------------------------------------------------------------------------- |
|    45 | Use of Cache Containing Sensitive Information - Cache Deception              |
|    43 | Inadequate Encryption Strength                                               |
|    42 | Cryptographic Issues - Generic                                               |
|    41 | Improper Neutralization of Special Elements Used in a Template Engine - SSTI |
|    40 | Use of Vulnerable Third-Party Component                                      |
|    37 | Use of Hard-coded Cryptographic Key                                          |
|    36 | Insufficiently Protected Credentials                                         |
|    35 | HTTP Request Smuggling                                                       |
|    32 | Permissive Cross-domain Policy with Untrusted Domains (CORS)                 |
|    28 | Remote File Inclusion                                                        |
|    25 | Unprotected Transport of Credentials                                         |
|    22 | CRLF Injection                                                               |
|    21 | Use of Hard-coded Password                                                   |
|    20 | Use of Externally-Controlled Format String                                   |
|    19 | Password in Configuration File                                               |
|    18 | Improper Neutralization of Special Elements Used in a Template Engine - CSTI |
|    18 | LDAP Injection                                                               |
|    17 | Clickjacking                                                                 |
|    17 | Weak Cryptography for Passwords                                              |
|    17 | Unverified Password Change                                                   |
|    14 | Plaintext Storage of a Password                                              |
|    14 | Improper Handling of Extra Parameters                                        |
|    14 | Server Misconfiguration - DNS Zone Takeover                                  |
|    12 | Use of Insufficiently Random Values                                          |
|    12 | Missing Authorization                                                        |
|    10 | Improper Authorization                                                       |
|    10 | Use of Web Link to Untrusted Target with window.opener Access                |
|    10 | Improper Neutralization of HTTP Headers for Scripting Syntax                 |
|     9 | HTTP Response Splitting                                                      |
|     7 | Use of a Broken or Risky Cryptographic Algorithm                             |
|     7 | Improper Certificate Validation                                              |
|     6 | XML Injection                                                                |
|     6 | Storing Passwords in a Recoverable Format                                    |
|     5 | Missing Encryption of Sensitive Data                                         |
|     5 | Man-in-the-Middle                                                            |
|     4 | Use of a Key Past its Expiration Date                                        |
|     3 | Integer Overflow                                                             |
|     2 | Reusing a Nonce, Key Pair in Encryption                                      |
|     2 | Missing Required Cryptographic Step                                          |
|     2 | Out-of-bounds Read                                                           |
|     2 | Heap Overflow                                                                |
|     2 | Authentication Bypass Using an Alternate Path or Channel                     |
|     2 | Insertion of Sensitive Information into Log File                             |
|     1 | Buffer Over-read                                                             |
|     1 | Allocation of Resources Without Limits or Throttling                         |
|     1 | XML External Entity (XXE)                                                    |
|     1 | Improper Input Validation                                                    |
|     1 | Improper Privilege Management                                                |
|     1 | Insufficient Logging                                                         |
|     1 | Incorrect Calculation of Buffer Size                                         |
|     1 | Double Free                                                                  |
|     1 | Use After Free                                                               |
|     1 | Type Confusion                                                               |
|     1 | Use of Cryptographically Weak PRNG                                           |
|     1 | Off-by-one Error                                                             |
{% endtab %}
{% endtabs %}

***

## CWE Frequency (Post-Normalization)

33,649 labelled reports across 90 distinct CWEs. The split threshold is 100 reports.

| Group                  | CWEs | Reports |  Share |
| ---------------------- | ---: | ------: | -----: |
| High-frequency (≥ 100) |   25 |  31,972 | 95.02% |
| Long tail (< 100)      |   65 |   1,677 |  4.98% |

The top three CWEs alone (`CWE-79`, `CWE-284`, `CWE-639`) account for 18,695 reports — 55.56% of the corpus.

{% tabs %}
{% tab title="High-frequency (≥ 100) — 25 CWEs" %}
| CWE       | Family                                | Count |  Share |
| --------- | ------------------------------------- | ----: | -----: |
| `CWE-79`  | Cross-site Scripting                  | 9,000 | 26.75% |
| `CWE-284` | Improper Access Control               | 5,176 | 15.38% |
| `CWE-639` | Insecure Direct Object Reference      | 4,519 | 13.43% |
| `CWE-840` | Business Logic Errors                 | 2,057 |  6.11% |
| `CWE-200` | Information Disclosure                | 1,940 |  5.77% |
| `CWE-601` | Open Redirect                         | 1,595 |  4.74% |
| `CWE-657` | Violation of Secure Design Principles | 1,131 |  3.36% |
| `CWE-89`  | SQL Injection                         |   909 |  2.70% |
| `CWE-352` | Cross-Site Request Forgery            |   845 |  2.51% |
| `CWE-287` | Improper Authentication               |   681 |  2.02% |
| `CWE-16`  | Server Misconfiguration               |   653 |  1.94% |
| `CWE-918` | Server-Side Request Forgery           |   560 |  1.66% |
| `CWE-94`  | Code Injection                        |   472 |  1.40% |
| `CWE-349` | Cache Poisoning                       |   357 |  1.06% |
| `CWE-22`  | Path Traversal                        |   346 |  1.03% |
| `CWE-78`  | OS Command Injection                  |   326 |  0.97% |
| `CWE-99`  | Resource Injection                    |   240 |  0.71% |
| `CWE-400` | Denial of Service                     |   234 |  0.70% |
| `CWE-307` | Brute Force                           |   181 |  0.54% |
| `CWE-798` | Hard-coded Credentials                |   155 |  0.46% |
| `CWE-613` | Insufficient Session Expiration       |   136 |  0.40% |
| `CWE-312` | Cleartext Storage of Sensitive Info   |   133 |  0.40% |
| `CWE-77`  | Command Injection                     |   122 |  0.36% |
| `CWE-425` | Direct Request                        |   104 |  0.31% |
| `CWE-922` | Insecure Storage of Sensitive Info    |   100 |  0.30% |
{% endtab %}

{% tab title="Long-tail (< 100) — 65 CWEs" %}
| CWE        | Family                                 | Count |
| ---------- | -------------------------------------- | ----: |
| `CWE-434`  | Unrestricted File Upload               |    99 |
| `CWE-215`  | Debug Information Exposure             |    99 |
| `CWE-1391` | Weak Credentials                       |    98 |
| `CWE-364`  | Race Condition                         |    85 |
| `CWE-319`  | Cleartext Transmission                 |    74 |
| `CWE-1427` | LLM Prompt Injection                   |    74 |
| `CWE-209`  | Error-Message Exposure                 |    68 |
| `CWE-611`  | XML External Entity                    |    67 |
| `CWE-359`  | Privacy Violation                      |    64 |
| `CWE-502`  | Insecure Deserialization               |    63 |
| `CWE-1336` | Template Engine Injection (SSTI/CSTI)  |    59 |
| `CWE-548`  | Directory Listing                      |    54 |
| `CWE-1392` | Default Credentials                    |    52 |
| `CWE-640`  | Weak Password Recovery                 |    50 |
| `CWE-524`  | Cache Deception                        |    45 |
| `CWE-326`  | Inadequate Encryption Strength         |    43 |
| `CWE-310`  | Cryptographic Issues                   |    42 |
| `CWE-1104` | Vulnerable Third-Party Component       |    40 |
| `CWE-321`  | Hard-coded Crypto Key                  |    37 |
| `CWE-522`  | Insufficiently Protected Credentials   |    36 |
| `CWE-444`  | HTTP Request Smuggling                 |    35 |
| `CWE-942`  | Permissive CORS Policy                 |    32 |
| `CWE-98`   | Remote File Inclusion                  |    28 |
| `CWE-523`  | Unprotected Credential Transport       |    25 |
| `CWE-93`   | CRLF Injection                         |    22 |
| `CWE-259`  | Hard-coded Password                    |    21 |
| `CWE-134`  | Format String                          |    20 |
| `CWE-260`  | Password in Config File                |    19 |
| `CWE-90`   | LDAP Injection                         |    18 |
| `CWE-1021` | Clickjacking                           |    17 |
| `CWE-261`  | Weak Password Cryptography             |    17 |
| `CWE-620`  | Unverified Password Change             |    17 |
| `CWE-256`  | Plaintext Password Storage             |    14 |
| `CWE-235`  | Improper Handling of Extra Parameters  |    14 |
| `CWE-330`  | Insufficient Randomness                |    12 |
| `CWE-862`  | Missing Authorization                  |    12 |
| `CWE-285`  | Improper Authorization                 |    10 |
| `CWE-1022` | Untrusted Link Target (tabnabbing)     |    10 |
| `CWE-644`  | HTTP Header Injection                  |    10 |
| `CWE-113`  | HTTP Response Splitting                |     9 |
| `CWE-327`  | Broken Crypto Algorithm                |     7 |
| `CWE-295`  | Improper Certificate Validation        |     7 |
| `CWE-91`   | XML Injection                          |     6 |
| `CWE-257`  | Recoverable Password Storage           |     6 |
| `CWE-311`  | Missing Encryption                     |     5 |
| `CWE-300`  | Man-in-the-Middle                      |     5 |
| `CWE-324`  | Expired Key Use                        |     4 |
| `CWE-190`  | Integer Overflow                       |     3 |
| `CWE-323`  | Nonce/Key Reuse                        |     2 |
| `CWE-325`  | Missing Cryptographic Step             |     2 |
| `CWE-125`  | Out-of-bounds Read                     |     2 |
| `CWE-122`  | Heap Overflow                          |     2 |
| `CWE-288`  | Authentication Bypass (alternate path) |     2 |
| `CWE-532`  | Sensitive Info in Logs                 |     2 |
| `CWE-126`  | Buffer Over-read                       |     1 |
| `CWE-770`  | Unthrottled Resource Allocation        |     1 |
| `CWE-20`   | Improper Input Validation              |     1 |
| `CWE-269`  | Improper Privilege Management          |     1 |
| `CWE-778`  | Insufficient Logging                   |     1 |
| `CWE-131`  | Incorrect Buffer Size Calculation      |     1 |
| `CWE-415`  | Double Free                            |     1 |
| `CWE-416`  | Use After Free                         |     1 |
| `CWE-843`  | Type Confusion                         |     1 |
| `CWE-338`  | Weak PRNG                              |     1 |
| `CWE-193`  | Off-by-one Error                       |     1 |
{% endtab %}
{% endtabs %}

***

## Open Issue: Hunter Total Discrepancy

Per-hunter profile metadata (`hunter_stats.csv`, from `parse_stats.py`) reports a `reports` figure for each of the 81 hunters. Summing that column and comparing against the hacktivity-derived count:

| Source                                                                     |   Reports |
| -------------------------------------------------------------------------- | --------: |
| Sum of `reports` column, `hunter_stats.csv` (self-reported profile totals) |    36,662 |
| `status == "New"` reports after normalization                              |    33,649 |
| **Discrepancy**                                                            | **3,013** |

Two candidate explanations, neither confirmed:

1. **Definitional.** The profile `reports` counter may include submissions in states this pipeline deliberately excludes (duplicates, informative, not-applicable, spam), or reports on programs whose hacktivity is not publicly disclosed.
2. **Pagination.** The scraper may have truncated hacktivity pulls for high-volume hunters, in which case the gap is real data loss, not uniformly distributed.

These predict different signatures: under (1) the shortfall should scale roughly with each hunter's total; under (2) it should cluster in a small number of high-volume hunters. A per-hunter delta table sorted by absolute shortfall — not yet built — would discriminate between the two.

{% hint style="warning" %}
Until this is resolved, treat the 81-hunter corpus as **representative but not exhaustive**. Any per-hunter rate metric (reports per year active, impact per report) inherits this uncertainty and should carry the caveat.
{% endhint %}

***

## Note on `cwe_class_map.json`

`cwe_class_map.json`, produced by `CWEchecker.py`, maps each CWE to the set of `bug_name` sub-types observed under it. Two properties matter when reading it:

* **It counts all statuses**, not just `New`. Its total of 83,675 records is therefore not comparable to the 33,649 figure used throughout this page.
* **It reflects the current, post-normalization state of the hunter files** — this run was executed after `normalize_hacktivity.py`, so the map already shows `CWE-1104` (not `CWE-1395`) and `CWE-778`.

***

## Summary

|                      | Before normalization | After normalization |
| -------------------- | -------------------: | ------------------: |
| Hunters processed    |                   81 |                  81 |
| Labelled reports     |               33,804 |              33,649 |
| CWE-labelled reports |               32,830 |              33,649 |
| Label/CWE gap        |                  974 |                   0 |
| Distinct labels      |                  117 |                  98 |
| Distinct CWEs        |                   90 |                  90 |

The dataset is single-vocabulary and fully CWE-labelled after this run, with one open caveat: the 3,013-report hunter discrepancy above remains unexplained.
