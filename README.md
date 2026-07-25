---
description: >-
  A web vulnerability assessment and an end-to-end data analysis of YesWeHack's
  public bug bounty leaderboard — scraping, cleaning, EDA, correlation testing,
  and entropy analysis.
icon: bug
---

# Bug Bounty Hunter Analysis

This space covers two pieces of work: an offensive web security assessment (CVSS scoring + XSS exploitation), and a full data pipeline over YesWeHack's public hunter leaderboard — scraping, cleaning, EDA, correlation testing, and entropy analysis. Pick a section below, or jump straight to a specific write-up.

***

## Web Vulnerability Assessment

A stored XSS exploitation chain against a Root-Me web-client challenge, written up as a full vulnerability report.

**The write-up covers:**

| Section                     | What it contains                                    |
| --------------------------- | --------------------------------------------------- |
| Vulnerability Summary       | The type of vulnerability and its impact            |
| Proof of Concept (PoC)      | Detailed, reproducible exploitation steps           |
| Risk Assessment             | A CVSS 3.1 score with justification for each metric |
| Remediation Recommendations | Mitigation strategies                               |

<table data-view="cards"><thead><tr><th></th><th></th><th></th><th data-hidden data-card-target data-type="content-ref"></th><th data-hidden data-card-cover data-type="image">Cover image</th></tr></thead><tbody><tr><td><h4><i class="fa-shield-halved" style="color:$primary;">:shield-halved:</i></h4></td><td><h4>Root-Me Web-Client ch18 — Stored XSS</h4></td><td>Vulnerability summary, PoC, CVSS 3.1 risk assessment, and remediation for the admin cookie exfiltration exploit.</td><td><a href="root-me-web-client-ch18-stored-xss-admin-cookie-exfiltration.md">root-me-web-client-ch18-stored-xss-admin-cookie-exfiltration.md</a></td><td><a href="https://miro.medium.com/v2/0*j3TbvaBkY1QCwn_Z.jpeg">https://miro.medium.com/v2/0*j3TbvaBkY1QCwn_Z.jpeg</a></td></tr></tbody></table>

***

## Leaderboard Data Analysis

Data on public hunters was collected from the [YesWeHack Rankings Page](https://yeswehack.com/ranking) — impact score, report count, rank, points, and full hacktivity history for hunters with a public profile (e.g. [reptou](https://yeswehack.com/hunters/reptou)) — then cleaned, explored, and tested for two relationships: whether accepted reports predict points earned, and whether specialization (vs. diversification) across vulnerability categories correlates with rank.

### The pipeline

<table data-view="cards"><thead><tr><th></th><th></th><th></th><th data-hidden data-card-target data-type="content-ref"></th></tr></thead><tbody><tr><td><h4><i class="fa-spider-web" style="color:$primary;">:spider-web:</i></h4></td><td><h4>1. Scraping the Leaderboard</h4></td><td>Reverse-engineering the ranking page's JSON API into a four-step scraping pipeline.</td><td><a href="scraping-the-yeswehack-leaderboard.md">scraping-the-yeswehack-leaderboard.md</a></td></tr><tr><td><h4><i class="fa-broom" style="color:$primary;">:broom:</i></h4></td><td><h4>2. Data Preprocessing</h4></td><td>Cleaning the hacktivity export and reconciling legacy OWASP labels with canonical CWE categories.</td><td><a href="data-preprocessing.md">data-preprocessing.md</a></td></tr><tr><td><h4><i class="fa-chart-mixed" style="color:$primary;">:chart-mixed:</i></h4></td><td><h4>3. Statistical Inference (EDA)</h4></td><td>Exploratory analysis of country, bug/CWE frequency, and numeric hunter attributes.</td><td><a href="statistical-inference-eda-report.md">statistical-inference-eda-report.md</a></td></tr><tr><td><h4><i class="fa-chart-line" style="color:$primary;">:chart-line:</i></h4></td><td><h4>4. Reports vs. Points</h4></td><td>Spearman correlation testing whether accepted reports predict total points earned.</td><td><a href="reports-vs.-points-correlation-analysis.md">reports-vs.-points-correlation-analysis.md</a></td></tr><tr><td><h4><i class="fa-shuffle" style="color:$primary;">:shuffle:</i></h4></td><td><h4>5. Shannon Entropy vs. Rank</h4></td><td>Does specialization vs. diversification across vulnerability categories correlate with leaderboard rank?</td><td><a href="spearman-correlation-analysis-rank-and-shannon-entropy.md">spearman-correlation-analysis-rank-and-shannon-entropy.md</a></td></tr><tr><td><h4><i class="fa-code" style="color:$primary;">:code:</i></h4></td><td><h4>Source Scripts</h4></td><td>Every script behind the pipeline above — full source, expandable, with a description of what each one does.</td><td><a href="source-scripts.md">source-scripts.md</a></td></tr></tbody></table>

***

## Working notes

* Read the pipeline write-ups in order (1 → 5) — each stage's output is the next stage's input.
* Statistical results (Spearman's ρ, p-values, N) quoted throughout come from specific analysis runs against the current dataset, not placeholders.
* Treat each write-up as lab-notebook-style: a research question, a method, a result, and often open questions at the end — not neutral reference documentation.
