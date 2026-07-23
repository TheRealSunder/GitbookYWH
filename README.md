# Bug Bounty Hunter Analysis

This is a research-notes space documenting a statistical analysis of bug bounty hunter data (reports, points, CWE categories, entropy of specialization).

## Structure

* **Documentation** — write-ups of each analysis stage, meant to be read in this order:
  1. Data Preprocessing — cleaning hacktivity data, reconciling legacy OWASP labels with canonical CWE/bug\_name categories, deciding how to count a "report" (uses report status `new` as the estimator, since resolution status is inconsistent).
  2. Statistical Inference — EDA on points/reports/join-date/country distributions, and a sanity check comparing hunter-reported stats totals vs. hacktivity-derived totals (large discrepancies for some hunters, exact matches for others).
  3. Shannon Entropy Analysis — Shannon entropy analysis of each hunter's specialization across CWE categories, correlated (Spearman) against leaderboard rank.
  4. Reports to Points — Spearman correlation between reports, points, and rank.
* **Source Scripts** — the Python scripts used throughout the analysis, with descriptions and full source, viewable as dropdowns.
* **Write-ups** — standalone technical write-ups, such as the Root-Me Web-Client ch18 stored XSS exploitation.

## Working notes

* Statistical results (Spearman's ρ, p-values, N) quoted throughout come from specific analysis runs.
* Treat the documentation pages as lab-notebook-style writing: each records a research question, method, and result, often with open questions at the end.
