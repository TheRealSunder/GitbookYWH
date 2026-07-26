---
description: >-
  This chapter explores the different categorical and numerical characteristics
  of the data such as mean, CWE frequency, numerical and categorical attributes,
  and report-count reconciliation.
icon: chart-mixed
---

# Statistical Inference EDA Report

This document summarizes the exploratory data analysis performed before any statistical testing. The goal is to describe the shape, spread, and consistency of the dataset so the later inference step is grounded in the data distribution rather than assumptions.

## Data Sources

* hunter\_stats.csv: `username, joined, impact, reports, points, rank, country`
* hunter\_hacktivity\_report\_counts.csv: `hunter, hacktivity_report_count`
* Stats.txt for the top bug-name and CWE frequency tables

```
Processed 81 hunters //Stats.txt
New reports with bug_name: 33649
New reports with CWE:      33649

=== Bug Types (status = new) ===
 5267  Cross-site Scripting (XSS) - Reflected
 5176  Improper Access Control - Generic
 4519  Insecure Direct Object Reference (IDOR)
 2057  Business Logic Errors
 1940  Information Disclosure
 
=== CWEs (status = new) ===
 9000  CWE-79
 5176  CWE-284
 4519  CWE-639
 2057  CWE-840
```

## Country Distribution

France dominates the public hunter set, accounting for 48 of 81 hunters, or about 59.3%. The next largest groups are Spain with 6 hunters, Sweden with 4, and China with 3. Most remaining countries contribute only one or two hunters each.

<figure><img src=".gitbook/assets/country_by_country_pie.png" alt="" width="563"><figcaption><p>Hunter distribution by country</p></figcaption></figure>

## Bug Name and CWE Frequency

### Top 20 Bug Names

<figure><img src=".gitbook/assets/top_bug_names.png" alt=""><figcaption><p>Top 20 Bug Names</p></figcaption></figure>

The most frequently reported bug types map closely onto the OWASP Top 10: injection, broken access control, and multiple forms of Cross-site Scripting account for most submissions. Hunters appear to concentrate on well-known, well-documented vulnerability classes rather than obscure or novel ones.

### Top 20 CWEs

<figure><img src=".gitbook/assets/top_cwe.png" alt=""><figcaption><p>Top 20 CWE</p></figcaption></figure>

Grouping by CWE collapses the four Cross-site Scripting variants into one category, and the effect is obvious: CWE-79 alone outweighs every other weakness class, with Improper Access Control and Insecure Direct Object Reference trailing behind. A small number of CWE families account for most of the dataset.

## Numeric Hunter Attributes

The following summaries describe the main numeric fields in hunter\_stats.csv.

### Summary Table

The histogram bin choice for each variable uses the Freedman-Diaconis rule, which adapts to spread and sample size.

| Field   |      Mean |   Std Dev | Minimum                        | Maximum                     |   Skew |
| ------- | --------: | --------: | ------------------------------ | --------------------------- | -----: |
| impact  |   20.0723 |    5.7483 | 5.1400 by Xiety, rank 21       | 37.1000 by zc, rank 51      | 0.1742 |
| reports |  452.6173 |  639.4678 | 98.0000 by Mekky, rank 90      | 5610.0000 by rabhi, rank 1  | 6.8057 |
| points  | 7159.0370 | 9557.7124 | 2586.0000 by Brumens, rank 100 | 84713.0000 by rabhi, rank 1 | 6.9547 |

<figure><img src=".gitbook/assets/impact_histogram.png" alt=""><figcaption><p>Impact Distribution</p></figcaption></figure>

Impact is close to symmetric, with very low skew, so it looks much more stable than the other two measures

<figure><img src=".gitbook/assets/points_histogram.png" alt=""><figcaption><p>Points Distribution</p></figcaption></figure>

<figure><img src=".gitbook/assets/reports_histogram.png" alt=""><figcaption><p>Reports Distribution</p></figcaption></figure>

Reports and points are both strongly right-skewed, which means a few hunters sit far above the rest and pull the mean upward

{% hint style="info" %}
Because reports and points are so skewed, any later statistical testing that assumes normality should be treated cautiously. A median-based or nonparametric check may be more robust if the analysis is sensitive to outliers.
{% endhint %}

## Report Count Reconciliation

The script compared the official report counts from hunter\_stats.csv against the counts from hunter\_hacktivity\_report\_counts.csv.

Key result: all 81 hunters matched by name, but the counts still disagree for many hunters. The official report count is generally higher than the hacktivity count. The largest absolute mismatches are:

* Icare: 701 official vs 432 hacktivity, error 269
* wlayzz: 429 official vs 225 hacktivity, error 204
* truff: 392 official vs 199 hacktivity, error 193
* Edra: 630 official vs 478 hacktivity, error 152
* kuromatae: 344 official vs 198 hacktivity, error 146

## Overall Reading of the Dataset

The dataset is small, geographically concentrated, and heavily dominated by a handful of hunter names and vulnerability categories. Impact is relatively well-behaved, but reports and points are highly skewed and likely contain influential high-end outliers. The count mismatch between the two report sources is large enough to matter analytically, so the official `reports` field should be treated as the more reliable reference for later testing.
