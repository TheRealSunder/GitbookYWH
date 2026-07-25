---
description: >-
  A stored XSS assessment and an end-to-end analysis of YesWeHack's public
  hunter leaderboard.
---

# Bug Bounty Hunter Analysis

This project contains a web vulnerability assessment and a leaderboard data analysis. The assessment documents a stored XSS exploit. The analysis follows public YesWeHack hunter data from collection through statistical testing.

***

## Web vulnerability assessment

A vulnerability report documents a stored cross-site scripting (XSS) chain against a Root-Me web-client challenge. It includes the proof of concept, CVSS 3.1 assessment, and remediation guidance.

<table data-view="cards"><thead><tr><th></th><th></th><th></th><th data-hidden data-card-target data-type="content-ref"></th><th data-hidden data-card-cover data-type="image">Cover image</th></tr></thead><tbody><tr><td><h4><i class="fa-shield-halved" style="color:$primary;">:shield-halved:</i></h4></td><td><h4>Root-Me Web-Client ch18 — Stored XSS</h4></td><td>Stored XSS discovery, a proof of concept, CVSS 3.1 scoring, and remediation guidance.</td><td><a href="root-me-web-client-ch18-stored-xss-admin-cookie-exfiltration.md">root-me-web-client-ch18-stored-xss-admin-cookie-exfiltration.md</a></td><td><a href="https://miro.medium.com/v2/0*j3TbvaBkY1QCwn_Z.jpeg">https://miro.medium.com/v2/0*j3TbvaBkY1QCwn_Z.jpeg</a></td></tr></tbody></table>

***

## Leaderboard data analysis

The analysis uses data from the [YesWeHack rankings](https://yeswehack.com/ranking). It collects public hunter profiles, ranking metrics, and hacktivity histories. It then cleans and explores the dataset before testing two relationships:

* Whether accepted reports predict total points.
* Whether vulnerability-category specialization correlates with leaderboard rank.

### Analysis pipeline

Read the analysis pages in order. Each stage produces input for the next stage.

<table data-view="cards"><thead><tr><th></th><th></th><th></th><th data-hidden data-card-target data-type="content-ref"></th></tr></thead><tbody><tr><td><h4><i class="fa-spider-web" style="color:$primary;">:spider-web:</i></h4></td><td><h4>1. Scraping the leaderboard</h4></td><td>Reverse-engineer the ranking page API and collect the source dataset.</td><td><a href="scraping-the-yeswehack-leaderboard.md">scraping-the-yeswehack-leaderboard.md</a></td></tr><tr><td><h4><i class="fa-broom" style="color:$primary;">:broom:</i></h4></td><td><h4>2. Data preprocessing</h4></td><td>Clean hacktivity data and map legacy OWASP labels to CWE categories.</td><td><a href="data-preprocessing.md">data-preprocessing.md</a></td></tr><tr><td><h4><i class="fa-chart-mixed" style="color:$primary;">:chart-mixed:</i></h4></td><td><h4>3. Exploratory data analysis</h4></td><td>Explore countries, vulnerability categories, and hunter metrics.</td><td><a href="statistical-inference-eda-report.md">statistical-inference-eda-report.md</a></td></tr><tr><td><h4><i class="fa-chart-line" style="color:$primary;">:chart-line:</i></h4></td><td><h4>4. Reports versus points</h4></td><td>Test whether accepted reports correlate with total points.</td><td><a href="reports-vs.-points-correlation-analysis.md">reports-vs.-points-correlation-analysis.md</a></td></tr><tr><td><h4><i class="fa-shuffle" style="color:$primary;">:shuffle:</i></h4></td><td><h4>5. Shannon entropy versus rank</h4></td><td>Test whether vulnerability-category diversity correlates with rank.</td><td><a href="spearman-correlation-analysis-rank-and-shannon-entropy.md">spearman-correlation-analysis-rank-and-shannon-entropy.md</a></td></tr><tr><td><h4><i class="fa-code" style="color:$primary;">:code:</i></h4></td><td><h4>Source scripts</h4></td><td>Review the scripts that collect, transform, and analyze the dataset.</td><td><a href="source-scripts.md">source-scripts.md</a></td></tr></tbody></table>

***

## Interpreting the results

The reported Spearman's ρ values, p-values, and sample sizes come from analysis runs against the collected dataset. They are not placeholders.

Each write-up follows a research format. It states a question, method, result, and any remaining limitations or questions.
