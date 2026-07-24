---
description: >-
  How the raw HackerOne hacktivity export was cleaned, normalized, and verified
  before any entropy or correlation analysis.
icon: broom
---

# Data Preprocessing

## Overview

The raw hacktivity export cannot be analysed as-is. Three problems make the raw label field unusable as a categorical variable:

1. **Multiple naming schemes.** The same vulnerability family appears under canonical HackerOne labels, OWASP Top 10 (2017) labels, and OWASP Top 10 (2013) labels.
2. **Records with no vulnerability.** Rows marked `Not Applicable (CWE-NULL)` or `None Applicable` carry no CWE and describe no finding.
3. **Missing CWE fields.** Legacy-labelled records were never assigned a CWE identifier, so any CWE-keyed aggregation silently dropped them.

Preprocessing resolves all three. The pipeline is three scripts run in sequence:

| Order | Script                    | Role                                                                               |
| :---: | ------------------------- | ---------------------------------------------------------------------------------- |
|   1   | `stat_checker.py`         | Baseline count of `bug_name` and `cwe` over `status == "New"` reports              |
|   2   | `normalize_hacktivity.py` | Collapse legacy labels to canonical names, attach CWEs, delete non-applicable rows |
|   3   | `stat_checker.py`         | Re-count to verify the transformation                                              |

Supporting scripts: `CWEchecker.py` builds the CWE → sub-type tree (`cwe_class_map.json`), and `parse_stats.py` flattens per-hunter profile metadata into `hunter_stats.csv`.

{% hint style="info" %}
**Counting rule.** Only reports with `status == "New"` are counted. The full resolution chain (`accepted → resolved → closed`) was considered and rejected: status history is inconsistent across submissions — some reports jump straight from `new` to `closed`, others cycle through intermediate states. Counting `new` gives exactly one stable, non-duplicated observation per report.
{% endhint %}

***

## 1. Baseline

`stat_checker.py` run against the raw export, before any transformation:

| Measure                                   |   Count |
| ----------------------------------------- | ------: |
| Hunters processed                         |      78 |
| New reports carrying a `bug_name`         |  32,579 |
| New reports carrying a `cwe`              |  31,611 |
| **Gap (records with a label but no CWE)** | **968** |
| Distinct `bug_name` labels                |     117 |
| Distinct CWE identifiers                  |      90 |

The 968-record gap is the target of this whole exercise. It decomposes into exactly two causes, and the post-normalization counts in [§5](data-preprocessing.md#5-before-vs-after) confirm the decomposition is complete.

***

## 2. Why Normalization Is Necessary

The export uses at least three overlapping vocabularies for the same underlying weakness:

| Scheme     | Example surface form                                                                  |
| ---------- | ------------------------------------------------------------------------------------- |
| Canonical  | `Cross-site Scripting (XSS) - Reflected (CWE-79)`                                     |
| OWASP 2017 | `OWASP-A7-Cross-Site Scripting (XSS)`, `OWASP-A6-Security Misconfiguration`           |
| OWASP 2013 | `OWASP-2013-A3-Cross-Site Scripting (XSS)`, `OWASP-2013-A5-Security Misconfiguration` |

Left untouched, a frequency count treats `OWASP-A7-Cross-Site Scripting (XSS)` and `Cross-site Scripting (XSS) - Generic` as two distinct outcomes. Two consequences follow:

* **Shannon entropy is inflated.** Entropy grows with the number of distinct outcomes, so label fragmentation manufactures diversity that does not exist in the data.
* **Per-family counts are suppressed.** A family split across three surface forms reports three small counts instead of one accurate one, distorting any ranking or correlation built on top.

### Matching strategy

`normalize_hacktivity.py` does not match label strings literally. It reduces each label to a comparison key first:

```python
_TRAILING_CWE = re.compile(r"\s*\(CWE-[\w\d]+\)\s*$", re.IGNORECASE)
_NON_ALNUM    = re.compile(r"[^a-z0-9]+")

def normalize_key(label: str) -> str:
    return _NON_ALNUM.sub(" ", strip_cwe_suffix(label).lower()).strip()
```

Two reductions happen: the trailing `(CWE-nnn)` suffix is stripped, then everything is lowercased and non-alphanumeric runs collapse to single spaces. So `OWASP-A7-XSS`, `owasp a7 xss`, and `OWASP-A7-XSS (CWE-79)` all reduce to the key `owasp a7 xss`. This is what makes the mapping table robust to punctuation and casing drift in the export.

***

## 3. Legacy → Canonical Mapping

Every legacy surface form collapsed by `normalize_hacktivity.py`, its canonical target, and the CWE written onto the record:

| Legacy label(s)                                                                                                                                                                                                                                  | Canonical name                          | CWE        |
| ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------------------- | ---------- |
| `OWASP-A7-XSS`, `OWASP-A7-Cross-Site Scripting (XSS)`, `OWASP-2013-A3-XSS`, `OWASP-2013-A3-Cross-Site Scripting (XSS)`                                                                                                                           | Cross-site Scripting (XSS) - Generic    | `CWE-79`   |
| `OWASP-A6-Security Misconfiguration`, `OWASP-2013-A5`, `OWASP-2013-A5-Security Misconfiguration`                                                                                                                                                 | Server Misconfiguration                 | `CWE-16`   |
| `OWASP-A1-Injection`, `OWASP-2013-A1-Injection` <sup>†</sup>                                                                                                                                                                                     | Command Injection - Generic             | `CWE-77`   |
| `OWASP-A2-Broken Authentication`, `OWASP-2013-A2-Broken Authentication and Session Management`, `OWASP-2013-A2-Broken Auth & Session Mgmt`                                                                                                       | Improper Authentication - Generic       | `CWE-287`  |
| `OWASP-A5-Broken Access Control`, `OWASP-2013-A7-Missing Function Level Access Control`                                                                                                                                                          | Improper Access Control - Generic       | `CWE-284`  |
| `OWASP-2013-A4-Insecure Direct Object References`                                                                                                                                                                                                | Insecure Direct Object Reference (IDOR) | `CWE-639`  |
| `OWASP-2013-A8-CSRF`, `OWASP-2013-A8-Cross-Site Request Forgery (CSRF)`                                                                                                                                                                          | Cross-Site Request Forgery (CSRF)       | `CWE-352`  |
| `OWASP-A3-Sensitive Data Exposure`, `OWASP-2013-A6`, `OWASP-2013-A6-Sensitive Data Exposure`                                                                                                                                                     | Information Disclosure                  | `CWE-200`  |
| `OWASP-2013-A10-Unvalidated Redirects and Forwards`                                                                                                                                                                                              | Open Redirect                           | `CWE-601`  |
| `OWASP-A4-XXE`, `OWASP-A4-XML External Entities (XXE)`                                                                                                                                                                                           | XML External Entity (XXE)               | `CWE-611`  |
| `OWASP-A9`, `OWASP-A9-Using Components with Known Vulnerabilities`, `OWASP-2013-A9`, `OWASP-2013-A9-Using Components with Known Vulnerabilities`, `Dependency on Vulnerable Third-Party Component`, `Use of Unmaintained Third Party Components` | Use of Vulnerable Third-Party Component | `CWE-1104` |
| `OWASP-A10-Insufficient Logging&Monitoring`, `OWASP-A10-Insufficient Logging & Monitoring`                                                                                                                                                       | Insufficient Logging                    | `CWE-778`  |

{% hint style="warning" %}
<sup>†</sup> **Inferred mapping.** `OWASP-A1-Injection` is a _category_ label — it does not state which injection sub-type occurred. It is mapped to `Command Injection - Generic (CWE-77)` as an inferred root cause and tagged `inferred` in the normalization report so the assumption stays visible downstream. 54 records are affected. Confidence in this specific mapping is **low**; every other mapping in the table is a one-to-one rename and is **high** confidence.
{% endhint %}

### Consolidation decision: CWE-1395 → CWE-1104

Two distinct labels described the same weakness — `Dependency on Vulnerable Third-Party Component` (`CWE-1395`, 6 records) and `Use of Unmaintained Third Party Components` (`CWE-1104`, 1 record) — alongside 33 OWASP-A9 records with no CWE at all. All 40 were consolidated under `Use of Vulnerable Third-Party Component (CWE-1104)`. `CWE-1395` therefore appears in the baseline output and is absent from the final output; this is intentional, not data loss.

***

## 4. Deleted Records

Records flagged as not applicable carry no exploitable finding and no usable CWE. They are removed from the JSON rather than retained with a null, so that downstream code never has to special-case an empty category.

| Deleted label               | Records removed |
| --------------------------- | --------------: |
| `Not Applicable (CWE-NULL)` |             110 |
| `None Applicable`           |              45 |
| **Total**                   |         **155** |

{% hint style="info" %}
`normalize_hacktivity.py` also registers a bare `Not Applicable` key defensively. It matched zero records in this export, but keeps the pipeline correct if a future pull uses the shorter form.
{% endhint %}

***

## 5. Before vs. After

| Measure                     | Before |        After |    Δ |
| --------------------------- | -----: | -----------: | ---: |
| New reports with `bug_name` | 32,579 |       32,424 | −155 |
| New reports with `cwe`      | 31,611 |       32,424 | +813 |
| Gap (`bug_name` − `cwe`)    |    968 |            0 | −968 |
| Distinct `bug_name` labels  |    117 | 42 + 56 = 98 |  −19 |
| Distinct CWE identifiers    |     90 |           90 |    0 |

Each figure is an independent check on the transformation:

* **`bug_name` fell by exactly 155**, matching the deletion table in [§4](data-preprocessing.md#4-deleted-records) to the record. Nothing else was dropped.
* **`cwe` rose by 813.** The 968-record gap resolves as `155 deleted + 813 relabelled = 968`. Every legacy record that previously had no CWE now has one.
* **The gap is zero.** `bug_name` and `cwe` counts are now identical, so every surviving report carries both fields.
* **Distinct labels fell by 19**: 23 legacy labels went to zero, and 4 canonical labels appeared for the first time (`Server Misconfiguration`, `Use of Vulnerable Third-Party Component`, `XML External Entity (XXE)`, `Insufficient Logging`).
* **Distinct CWE count is unchanged at 90 — but membership changed.** `CWE-1395` left the set and `CWE-778` entered it. The stability of the total is a coincidence, not evidence of anything.

### 5.1 Labels removed entirely

| Label                                                        | Before | After | Disposition                                       |
| ------------------------------------------------------------ | -----: | ----: | ------------------------------------------------- |
| `Not Applicable (CWE-NULL)`                                  |    110 |     0 | **Deleted**                                       |
| `None Applicable`                                            |     45 |     0 | **Deleted**                                       |
| `OWASP-A7-Cross-Site Scripting (XSS)`                        |    122 |     0 | Merged → XSS - Generic                            |
| `OWASP-A6-Security Misconfiguration`                         |    120 |     0 | Merged → Server Misconfiguration                  |
| `OWASP-2013-A3-Cross-Site Scripting (XSS)`                   |     90 |     0 | Merged → XSS - Generic                            |
| `OWASP-2013-A5-Security Misconfiguration`                    |     89 |     0 | Merged → Server Misconfiguration                  |
| `OWASP-2013-A8-Cross-Site Request Forgery (CSRF)`            |     73 |     0 | Merged → CSRF                                     |
| `OWASP-A3-Sensitive Data Exposure`                           |     64 |     0 | Merged → Information Disclosure                   |
| `OWASP-A5-Broken Access Control`                             |     52 |     0 | Merged → Improper Access Control                  |
| `OWASP-2013-A1-Injection`                                    |     28 |     0 | Merged → Command Injection - Generic <sup>†</sup> |
| `OWASP-2013-A6-Sensitive Data Exposure`                      |     28 |     0 | Merged → Information Disclosure                   |
| `OWASP-A1-Injection`                                         |     26 |     0 | Merged → Command Injection - Generic <sup>†</sup> |
| `OWASP-2013-A10-Unvalidated Redirects and Forwards`          |     25 |     0 | Merged → Open Redirect                            |
| `OWASP-A2-Broken Authentication`                             |     24 |     0 | Merged → Improper Authentication                  |
| `OWASP-2013-A9-Using Components with Known Vulnerabilities`  |     24 |     0 | Merged → Vulnerable Third-Party Component         |
| `OWASP-2013-A2-Broken Authentication and Session Management` |     19 |     0 | Merged → Improper Authentication                  |
| `OWASP-2013-A4-Insecure Direct Object References`            |     12 |     0 | Merged → IDOR                                     |
| `OWASP-A9-Using Components with Known Vulnerabilities`       |      9 |     0 | Merged → Vulnerable Third-Party Component         |
| `Dependency on Vulnerable Third-Party Component`             |      6 |     0 | Merged → Vulnerable Third-Party Component         |
| `OWASP-2013-A7-Missing Function Level Access Control`        |      6 |     0 | Merged → Improper Access Control                  |
| `OWASP-A10-Insufficient Logging&Monitoring`                  |      1 |     0 | Merged → Insufficient Logging                     |
| `OWASP-A4-XML External Entities (XXE)`                       |      1 |     0 | Merged → XML External Entity (XXE)                |
| `Use of Unmaintained Third Party Components`                 |      1 |     0 | Merged → Vulnerable Third-Party Component         |

### 5.2 Labels whose counts grew

| Canonical label                           | Before | After |    Δ | Absorbed from                                           |
| ----------------------------------------- | -----: | ----: | ---: | ------------------------------------------------------- |
| `Cross-site Scripting (XSS) - Generic`    |    758 |   970 | +212 | A7 (122) + 2013-A3 (90)                                 |
| `Server Misconfiguration`                 |      0 |   209 | +209 | A6 (120) + 2013-A5 (89)                                 |
| `Information Disclosure`                  |  1,798 | 1,890 |  +92 | A3 (64) + 2013-A6 (28)                                  |
| `Cross-Site Request Forgery (CSRF)`       |    750 |   823 |  +73 | 2013-A8 (73)                                            |
| `Improper Access Control - Generic`       |  4,957 | 5,015 |  +58 | A5 (52) + 2013-A7 (6)                                   |
| `Command Injection - Generic`             |     68 |   122 |  +54 | A1 (26) + 2013-A1 (28) <sup>†</sup>                     |
| `Improper Authentication - Generic`       |    597 |   640 |  +43 | A2 (24) + 2013-A2 (19)                                  |
| `Use of Vulnerable Third-Party Component` |      0 |    40 |  +40 | A9 (9) + 2013-A9 (24) + CWE-1395 (6) + unmaintained (1) |
| `Open Redirect`                           |  1,439 | 1,464 |  +25 | 2013-A10 (25)                                           |
| `Insecure Direct Object Reference (IDOR)` |  4,389 | 4,401 |  +12 | 2013-A4 (12)                                            |
| `XML External Entity (XXE)`               |      0 |     1 |   +1 | A4-XXE (1)                                              |
| `Insufficient Logging`                    |      0 |     1 |   +1 | A10 (1)                                                 |

**Sum of gains: 820.** Of those, 7 records (`CWE-1395` × 6, unmaintained × 1) already carried a CWE before normalization, so the net increase in CWE-labelled records is `820 − 7 = 813` — exactly the +813 in the summary table above.

### 5.3 CWE-level movement

| CWE        | Before | After |       Δ | Cause                                        |
| ---------- | -----: | ----: | ------: | -------------------------------------------- |
| `CWE-79`   |  8,298 | 8,510 |    +212 | Absorbed legacy XSS labels                   |
| `CWE-16`   |    441 |   650 |    +209 | Absorbed legacy misconfiguration labels      |
| `CWE-200`  |  1,798 | 1,890 |     +92 | Absorbed sensitive-data-exposure labels      |
| `CWE-352`  |    750 |   823 |     +73 | Absorbed 2013-A8                             |
| `CWE-284`  |  4,957 | 5,015 |     +58 | Absorbed broken-access-control labels        |
| `CWE-77`   |     68 |   122 |     +54 | Absorbed OWASP injection labels <sup>†</sup> |
| `CWE-287`  |    597 |   640 |     +43 | Absorbed broken-authentication labels        |
| `CWE-1104` |      1 |    40 |     +39 | Third-party-component consolidation          |
| `CWE-601`  |  1,439 | 1,464 |     +25 | Absorbed 2013-A10                            |
| `CWE-639`  |  4,389 | 4,401 |     +12 | Absorbed 2013-A4                             |
| `CWE-611`  |     66 |    67 |      +1 | Absorbed A4-XXE                              |
| `CWE-778`  |      — |     1 |     new | Canonical target for insufficient logging    |
| `CWE-1395` |      6 |     — | removed | Consolidated into `CWE-1104`                 |

***

## 6. Known Issue: Incomplete XXE Merge

{% hint style="danger" %}
The XXE consolidation did **not** complete. After normalization the export still contains two labels for the same weakness:

**Root cause.** `register(XXE, ...)` in `normalize_hacktivity.py` registers `OWASP-A4-XXE`, `OWASP-A4-XML External Entities (XXE)`, and the canonical singular form — but never the bare legacy plural `XML External Entities (XXE)`. Its normalized key is `xml external entities xxe`, which is absent from `CANONICAL_MAP`, so all 66 records fall through to the `unknown` branch and are left untouched.

**Impact.** CWE-level analysis is unaffected: both labels already resolve to `CWE-611`, so the CWE-611 total of 67 is correct. Only `bug_name`-level (sub-type) entropy is affected, where one family is still counted as two outcomes.

**Fix.** Add the legacy plural to the register call and re-run:

```python
register(XXE,
         "OWASP-A4-XXE",
         "OWASP-A4-XML External Entities (XXE)",
         "XML External Entities (XXE)",   # <- legacy plural, currently missing
         "XML External Entity (XXE)")
```
{% endhint %}

| Label                                            | Count | CWE       |
| ------------------------------------------------ | ----: | --------- |
| `XML External Entities (XXE)` (legacy plural)    |    66 | `CWE-611` |
| `XML External Entity (XXE)` (canonical singular) |     1 | `CWE-611` |

***

## 7. Bug-Name Frequency (Post-Normalization)

32,424 labelled reports across 98 distinct `bug_name` values. Split at 50 reports for readability.

{% tabs %}
{% tab title="High-frequency (≥ 50) — 42 labels" %}
| Count | Bug name                                                                    |  Share |
| ----: | --------------------------------------------------------------------------- | -----: |
| 5,015 | Improper Access Control - Generic                                           | 15.47% |
| 4,920 | Cross-site Scripting (XSS) - Reflected                                      | 15.17% |
| 4,401 | Insecure Direct Object Reference (IDOR)                                     | 13.57% |
| 1,976 | Business Logic Errors                                                       |  6.09% |
| 1,890 | Information Disclosure                                                      |  5.83% |
| 1,593 | Cross-site Scripting (XSS) - Stored                                         |  4.91% |
| 1,464 | Open Redirect                                                               |  4.52% |
| 1,121 | Violation of Secure Design Principles                                       |  3.46% |
|   970 | Cross-site Scripting (XSS) - Generic                                        |  2.99% |
|   899 | SQL Injection                                                               |  2.77% |
|   823 | Cross-Site Request Forgery (CSRF)                                           |  2.54% |
|   640 | Improper Authentication - Generic                                           |  1.97% |
|   562 | Cross-site Scripting (XSS) - DOM                                            |  1.73% |
|   550 | Server-Side Request Forgery (SSRF)                                          |  1.70% |
|   467 | Code Injection                                                              |  1.44% |
|   465 | HTML Injection                                                              |  1.43% |
|   428 | Server Misconfiguration - Subdomain Takeover                                |  1.32% |
|   355 | Acceptance of Extraneous Untrusted Data With Trusted Data - Cache Poisoning |  1.09% |
|   340 | Path Traversal                                                              |  1.05% |
|   323 | OS Command Injection                                                        |  1.00% |
|   229 | Denial of Service                                                           |  0.71% |
|   227 | Resource Injection                                                          |  0.70% |
|   209 | Server Misconfiguration                                                     |  0.64% |
|   175 | Brute Force                                                                 |  0.54% |
|   145 | Use of Hard-coded Credentials                                               |  0.45% |
|   136 | Insufficient Session Expiration                                             |  0.42% |
|   133 | Cleartext Storage of Sensitive Information                                  |  0.41% |
|   122 | Command Injection - Generic                                                 |  0.38% |
|   100 | Insecure Storage of Sensitive Information                                   |  0.31% |
|    98 | Unrestricted Upload of File with Dangerous Type                             |  0.30% |
|    98 | Use of Weak Credentials                                                     |  0.30% |
|    97 | Information Exposure Through Debug Information                              |  0.30% |
|    96 | Direct Request                                                              |  0.30% |
|    85 | Race Condition                                                              |  0.26% |
|    74 | Improper Neutralization of Input Used for LLM Prompting                     |  0.23% |
|    73 | Cleartext Transmission of Sensitive Information                             |  0.23% |
|    68 | Information Exposure Through an Error Message                               |  0.21% |
|    66 | XML External Entities (XXE)                                                 |  0.20% |
|    64 | Privacy Violation                                                           |  0.20% |
|    62 | Deserialization of Untrusted Data                                           |  0.19% |
|    54 | Information Exposure Through Directory Listing                              |  0.17% |
|    52 | Use of Default Credentials                                                  |  0.16% |
{% endtab %}

{% tab title="Long-tail (< 50) — 56 labels" %}
| Count | Bug name                                                                     |
| ----: | ---------------------------------------------------------------------------- |
|    43 | Inadequate Encryption Strength                                               |
|    43 | Use of Cache Containing Sensitive Information - Cache Deception              |
|    42 | Cryptographic Issues - Generic                                               |
|    41 | Improper Neutralization of Special Elements Used in a Template Engine - SSTI |
|    40 | Use of Vulnerable Third-Party Component                                      |
|    37 | Use of Hard-coded Cryptographic Key                                          |
|    37 | Weak Password Mechanism for Forgotten Password                               |
|    35 | Insufficiently Protected Credentials                                         |
|    34 | HTTP Request Smuggling                                                       |
|    28 | Remote File Inclusion                                                        |
|    25 | Unprotected Transport of Credentials                                         |
|    24 | Permissive Cross-domain Policy with Untrusted Domains (CORS)                 |
|    22 | CRLF Injection                                                               |
|    21 | Use of Hard-coded Password                                                   |
|    20 | Use of Externally-Controlled Format String                                   |
|    19 | Password in Configuration File                                               |
|    18 | LDAP Injection                                                               |
|    17 | Clickjacking                                                                 |
|    16 | Unverified Password Change                                                   |
|    15 | Weak Cryptography for Passwords                                              |
|    14 | Improper Handling of Extra Parameters                                        |
|    14 | Plaintext Storage of a Password                                              |
|    13 | Improper Neutralization of Special Elements Used in a Template Engine - CSTI |
|    13 | Server Misconfiguration - DNS Zone Takeover                                  |
|    12 | Use of Insufficiently Random Values                                          |
|    10 | Improper Authorization                                                       |
|    10 | Improper Neutralization of HTTP Headers for Scripting Syntax                 |
|    10 | Missing Authorization                                                        |
|    10 | Use of Web Link to Untrusted Target with window.opener Access                |
|     9 | HTTP Response Splitting                                                      |
|     7 | Improper Certificate Validation                                              |
|     7 | Use of a Broken or Risky Cryptographic Algorithm                             |
|     6 | Storing Passwords in a Recoverable Format                                    |
|     6 | XML Injection                                                                |
|     5 | Man-in-the-Middle                                                            |
|     5 | Missing Encryption of Sensitive Data                                         |
|     4 | Use of a Key Past its Expiration Date                                        |
|     3 | Integer Overflow                                                             |
|     2 | Authentication Bypass Using an Alternate Path or Channel                     |
|     2 | Heap Overflow                                                                |
|     2 | Insertion of Sensitive Information into Log File                             |
|     2 | Missing Required Cryptographic Step                                          |
|     2 | Out-of-bounds Read                                                           |
|     2 | Reusing a Nonce, Key Pair in Encryption                                      |
|     1 | Allocation of Resources Without Limits or Throttling                         |
|     1 | Buffer Over-read                                                             |
|     1 | Double Free                                                                  |
|     1 | Improper Input Validation                                                    |
|     1 | Improper Privilege Management                                                |
|     1 | Incorrect Calculation of Buffer Size                                         |
|     1 | Insufficient Logging                                                         |
|     1 | Off-by-one Error                                                             |
|     1 | Type Confusion                                                               |
|     1 | Use After Free                                                               |
|     1 | Use of Cryptographically Weak PRNG                                           |
|     1 | XML External Entity (XXE)                                                    |
{% endtab %}
{% endtabs %}

***

## 8. CWE Frequency (Post-Normalization)

32,424 labelled reports across 90 distinct CWEs. The split threshold is 100 reports, which cleanly separates the dominant families from the tail.

| Group                  | CWEs | Reports |  Share |
| ---------------------- | ---: | ------: | -----: |
| High-frequency (≥ 100) |   24 |  30,691 | 94.66% |
| Long tail (< 100)      |   66 |   1,733 |  5.34% |

The distribution is severely skewed: 24 of 90 CWEs account for 94.66% of all reports, and the top three alone (`CWE-79`, `CWE-284`, `CWE-639`) account for 17,926 reports — 55.29% of the corpus. This concentration is the central fact any entropy or correlation analysis has to contend with.

{% tabs %}
{% tab title="High-frequency (≥ 100) — 24 CWEs" %}
| CWE       | Family                                | Count |  Share |
| --------- | ------------------------------------- | ----: | -----: |
| `CWE-79`  | Cross-site Scripting                  | 8,510 | 26.25% |
| `CWE-284` | Improper Access Control               | 5,015 | 15.47% |
| `CWE-639` | Insecure Direct Object Reference      | 4,401 | 13.57% |
| `CWE-840` | Business Logic Errors                 | 1,976 |  6.09% |
| `CWE-200` | Information Disclosure                | 1,890 |  5.83% |
| `CWE-601` | Open Redirect                         | 1,464 |  4.52% |
| `CWE-657` | Violation of Secure Design Principles | 1,121 |  3.46% |
| `CWE-89`  | SQL Injection                         |   899 |  2.77% |
| `CWE-352` | Cross-Site Request Forgery            |   823 |  2.54% |
| `CWE-16`  | Server Misconfiguration               |   650 |  2.00% |
| `CWE-287` | Improper Authentication               |   640 |  1.97% |
| `CWE-918` | Server-Side Request Forgery           |   550 |  1.70% |
| `CWE-94`  | Code Injection                        |   467 |  1.44% |
| `CWE-349` | Cache Poisoning                       |   355 |  1.09% |
| `CWE-22`  | Path Traversal                        |   340 |  1.05% |
| `CWE-78`  | OS Command Injection                  |   323 |  1.00% |
| `CWE-400` | Denial of Service                     |   229 |  0.71% |
| `CWE-99`  | Resource Injection                    |   227 |  0.70% |
| `CWE-307` | Brute Force                           |   175 |  0.54% |
| `CWE-798` | Hard-coded Credentials                |   145 |  0.45% |
| `CWE-613` | Insufficient Session Expiration       |   136 |  0.42% |
| `CWE-312` | Cleartext Storage of Sensitive Info   |   133 |  0.41% |
| `CWE-77`  | Command Injection                     |   122 |  0.38% |
| `CWE-922` | Insecure Storage of Sensitive Info    |   100 |  0.31% |
{% endtab %}

{% tab title="Long-tail (< 100) — 66 CWEs" %}
| CWE        | Family                                 | Count |
| ---------- | -------------------------------------- | ----: |
| `CWE-1391` | Weak Credentials                       |    98 |
| `CWE-434`  | Unrestricted File Upload               |    98 |
| `CWE-215`  | Debug Information Exposure             |    97 |
| `CWE-425`  | Direct Request                         |    96 |
| `CWE-364`  | Race Condition                         |    85 |
| `CWE-1427` | LLM Prompt Injection                   |    74 |
| `CWE-319`  | Cleartext Transmission                 |    73 |
| `CWE-209`  | Error-Message Exposure                 |    68 |
| `CWE-611`  | XML External Entity                    |    67 |
| `CWE-359`  | Privacy Violation                      |    64 |
| `CWE-502`  | Insecure Deserialization               |    62 |
| `CWE-1336` | Template Engine Injection (SSTI/CSTI)  |    54 |
| `CWE-548`  | Directory Listing                      |    54 |
| `CWE-1392` | Default Credentials                    |    52 |
| `CWE-326`  | Inadequate Encryption Strength         |    43 |
| `CWE-524`  | Cache Deception                        |    43 |
| `CWE-310`  | Cryptographic Issues                   |    42 |
| `CWE-1104` | Vulnerable Third-Party Component       |    40 |
| `CWE-321`  | Hard-coded Crypto Key                  |    37 |
| `CWE-640`  | Weak Password Recovery                 |    37 |
| `CWE-522`  | Insufficiently Protected Credentials   |    35 |
| `CWE-444`  | HTTP Request Smuggling                 |    34 |
| `CWE-98`   | Remote File Inclusion                  |    28 |
| `CWE-523`  | Unprotected Credential Transport       |    25 |
| `CWE-942`  | Permissive CORS Policy                 |    24 |
| `CWE-93`   | CRLF Injection                         |    22 |
| `CWE-259`  | Hard-coded Password                    |    21 |
| `CWE-134`  | Format String                          |    20 |
| `CWE-260`  | Password in Config File                |    19 |
| `CWE-90`   | LDAP Injection                         |    18 |
| `CWE-1021` | Clickjacking                           |    17 |
| `CWE-620`  | Unverified Password Change             |    16 |
| `CWE-261`  | Weak Password Cryptography             |    15 |
| `CWE-235`  | Improper Handling of Extra Parameters  |    14 |
| `CWE-256`  | Plaintext Password Storage             |    14 |
| `CWE-330`  | Insufficient Randomness                |    12 |
| `CWE-1022` | Untrusted Link Target (tabnabbing)     |    10 |
| `CWE-285`  | Improper Authorization                 |    10 |
| `CWE-644`  | HTTP Header Injection                  |    10 |
| `CWE-862`  | Missing Authorization                  |    10 |
| `CWE-113`  | HTTP Response Splitting                |     9 |
| `CWE-295`  | Improper Certificate Validation        |     7 |
| `CWE-327`  | Broken Crypto Algorithm                |     7 |
| `CWE-257`  | Recoverable Password Storage           |     6 |
| `CWE-91`   | XML Injection                          |     6 |
| `CWE-300`  | Man-in-the-Middle                      |     5 |
| `CWE-311`  | Missing Encryption                     |     5 |
| `CWE-324`  | Expired Key Use                        |     4 |
| `CWE-190`  | Integer Overflow                       |     3 |
| `CWE-122`  | Heap Overflow                          |     2 |
| `CWE-125`  | Out-of-bounds Read                     |     2 |
| `CWE-288`  | Authentication Bypass (alternate path) |     2 |
| `CWE-323`  | Nonce/Key Reuse                        |     2 |
| `CWE-325`  | Missing Cryptographic Step             |     2 |
| `CWE-532`  | Sensitive Info in Logs                 |     2 |
| `CWE-126`  | Buffer Over-read                       |     1 |
| `CWE-131`  | Incorrect Buffer Size Calculation      |     1 |
| `CWE-193`  | Off-by-one Error                       |     1 |
| `CWE-20`   | Improper Input Validation              |     1 |
| `CWE-269`  | Improper Privilege Management          |     1 |
| `CWE-338`  | Weak PRNG                              |     1 |
| `CWE-415`  | Double Free                            |     1 |
| `CWE-416`  | Use After Free                         |     1 |
| `CWE-770`  | Unthrottled Resource Allocation        |     1 |
| `CWE-778`  | Insufficient Logging                   |     1 |
| `CWE-843`  | Type Confusion                         |     1 |
{% endtab %}
{% endtabs %}

***

## 9. Open Issue: Hunter Total Discrepancy

Per-hunter profile metadata (`hunter_stats.csv`, produced by `parse_stats.py`) reports a `reports` figure for each of the 78 hunters. Summing that column and comparing against the hacktivity-derived count:

| Source                                                                     |   Reports |
| -------------------------------------------------------------------------- | --------: |
| Sum of `reports` column, `hunter_stats.csv` (self-reported profile totals) |    35,224 |
| `status == "New"` reports after normalization                              |    32,424 |
| **Discrepancy**                                                            | **2,800** |

Two candidate explanations, neither yet confirmed:

1. **Definitional.** The profile `reports` counter may include submissions in states this pipeline deliberately excludes (duplicates, informative, not-applicable, spam) or reports on programs whose hacktivity is not publicly disclosed. If so, the gap is expected and the pipeline is correct.
2. **Pagination.** The scraper may have truncated hacktivity pulls for high-volume hunters, in which case the gap is real data loss and is _not_ uniformly distributed across hunters.

These predict different signatures. Under (1) the shortfall should scale roughly with each hunter's total; under (2) it should cluster in a small number of high-volume hunters and cap near a page-size multiple. The next step is a per-hunter delta table sorted by absolute shortfall — the shape of that distribution discriminates between the two. `hunters/checker.py` has been used to spot-check individual hunter records; a systematic per-hunter reconciliation is still outstanding.

{% hint style="warning" %}
Until this is resolved, treat the 78-hunter corpus as **representative but not exhaustive**. Any per-hunter rate metric (reports per year active, impact per report) inherits this uncertainty and should carry the caveat.
{% endhint %}

***

## 10. Note on `cwe_class_map.json`

`cwe_class_map.json`, produced by `CWEchecker.py`, maps each CWE to the set of `bug_name` sub-types observed under it. Two properties matter when reading it:

* **It counts all statuses**, not just `New`. Its total of 78,573 records is therefore not comparable to the 32,424 figure used throughout this page.
* **It reflects the pre-normalization state.** It still contains `CWE-1395`, shows `CWE-1104` with 2 records, has no `CWE-778`, and lists `CWE-611` under the legacy plural spelling only.

Re-run `CWEchecker.py` after normalization if a post-cleaning sub-type tree is needed.

***

## Summary

|                      | Before |  After |
| -------------------- | -----: | -----: |
| Labelled reports     | 32,579 | 32,424 |
| CWE-labelled reports | 31,611 | 32,424 |
| Label/CWE gap        |    968 |      0 |
| Distinct labels      |    117 |     98 |
| Distinct CWEs        |     90 |     90 |

The dataset is now single-vocabulary and fully CWE-labelled, with two documented caveats: the incomplete XXE merge ([§6](data-preprocessing.md#6-known-issue-incomplete-xxe-merge)) affects sub-type-level entropy only, and the 2,800-report hunter discrepancy ([§9](data-preprocessing.md#9-open-issue-hunter-total-discrepancy)) remains unexplained.
