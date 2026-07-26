---
description: >-
  This section conducts a Spearman Correlation between a hunter's reports and
  the total points they earned.
icon: chart-line
---

# Reports vs. Points Correlation Analysis

## Overview

The analysis covers **81 public hunter profiles** drawn from a dataset of 100 ranked hunters. The remaining 19 had undisclosed public profiles and were excluded.

***

## Research Question

> **Is there a statistically significant monotonic relationship between the number of accepted reports a hunter submits and the total points they earn?**

***

## Hypotheses

<table><thead><tr><th width="97">Symbol</th><th>Statement</th></tr></thead><tbody><tr><td><strong>H₀</strong></td><td>There is no relationship between reports and total points earned (ρ = 0)</td></tr><tr><td><strong>Hₐ</strong></td><td>There is a relationship between reports and total points earned (ρ ≠ 0)</td></tr></tbody></table>

Significance level: **α = 0.05**

***

## Data Pipeline

Each hunter's data is stored in a per-folder `stats.json` file and loaded into a single pandas DataFrame before analysis.

The report count that will be used in this analysis is from `stats.json`, not `hacktivities.json`

**Directory layout**

```
root/
├── Codes/
│   ├── reports_to_points.py
│   └── hunters/
│       └── <hunter_name>/
│           └── stats.json
└── Outputs/
    ├── reports_vs_points.png
    └── hunter_points_reports.csv
```

**Example `stats.json` record**

```json
{
  "username": "Blaklis",
  "name": "Blaklis",
  "joined": "2016",
  "impact": 24.18,
  "reports": 229,
  "points": 5140,
  "rank": 50,
  "country": "FR"
}
```

***

## Assumption Checks

Before selecting a statistical test, the following assumptions were verified.

{% stepper %}
{% step %}
### Independence of observations

Each row represents a unique hunter. One hunter's report count and points are structurally unrelated to any other hunter's, so the independence assumption is satisfied.
{% endstep %}

{% step %}
### Normality

The Shapiro-Wilk test was applied to both variables. Both returned W values below 0.40 with p < .001, indicating a strong departure from normality. Both distributions exhibit heavy right skew (skewness ≈ 6.81 for reports, 6.95 for points): a small number of high-volume hunters pull the mean well above the median.

```
Reports  — mean: 452.62,  median: 297.00,  max: 5,610
Points   — mean: 7,159.04, median: 5,222.00, max: 84,713
```
{% endstep %}

{% step %}
### Outliers

Extreme values are present in both variables. The maximum report count (5,610, from a single hunter) is roughly **12× the mean**, and the maximum points value (84,713, the same hunter) is also roughly **12× the mean**. These values would substantially inflate a Pearson correlation.
{% endstep %}

{% step %}
### Monotonicity

Exploratory scatter plots show a consistently increasing, monotonic relationship between reports and points rather than a straight-line one.

<div><figure><img src=".gitbook/assets/Screenshot 2026-07-26 233736.png" alt=""><figcaption><p>Reports and Points scatter plot with outlier</p></figcaption></figure> <figure><img src=".gitbook/assets/Screenshot 2026-07-26 233706.png" alt=""><figcaption><p>Reports and Points scatter plot with outlier</p></figcaption></figure></div>
{% endstep %}
{% endstepper %}

***

## Choice of Statistical Test

**Spearman's rank correlation** was selected for the following reasons:

| Condition                                       | Status                             |
| ----------------------------------------------- | ---------------------------------- |
| Monotonic (not necessarily linear) relationship | ✓ Confirmed by scatter             |
| Heavy right skew in both variables              | ✓ Skewness ≈ 6.8–7.0               |
| Outliers present                                | ✓ Max ≈ 12× mean                   |
| Normality required by Pearson                   | ✗ Violated (Shapiro-Wilk p < .001) |

Spearman correlates the **ranks** of the values rather than the values themselves. This makes it robust to the heavy right tail that leaderboard fields tend to have and detects any monotone relationship rather than only a linear one.

***

## Descriptive Statistics

The table below summarises central tendency, spread, and distributional shape for both variables across the **81 public hunters** in the analysis.

| Statistic          | Reports    | Points       |
| ------------------ | ---------- | ------------ |
| N                  | 81         | 81           |
| Missing            | 0          | 0            |
| Mean               | 452.62     | 7,159.04     |
| Median             | 297.00     | 5,222.00     |
| Standard deviation | 639.47     | 9,557.71     |
| Variance           | 408,919.01 | 91,349,866.0 |
| Minimum            | 98         | 2,586        |
| Maximum            | 5,610      | 84,713       |
| Skewness           | 6.81       | 6.95         |
| Shapiro-Wilk W     | 0.393      | 0.367        |
| Shapiro-Wilk p     | < .001     | < .001       |

## Results

Spearman's rank correlation was computed for three variable pairs. The points–rank pair is discussed separately because it is a structural relationship, not a behavioural finding.

<table><thead><tr><th>Variables</th><th width="62">n</th><th width="113">Spearman ρ</th><th width="132">p-value</th><th>Interpretation</th></tr></thead><tbody><tr><td>Reports vs Points</td><td>81</td><td>+0.875</td><td>1.33e-26</td><td>Very strong positive</td></tr><tr><td>Reports vs Rank</td><td>81</td><td>−0.875</td><td>1.33e-26</td><td>Very strong negative</td></tr></tbody></table>

{% tabs %}
{% tab title="Reports vs. Points" %}
A very strong positive monotonic correlation was found between accepted reports and total points earned. Because p < α = 0.05, we **reject the null hypothesis** and conclude that **hunters with more accepted reports consistently earn more points**.
{% endtab %}

{% tab title="Reports vs. Rank" %}
The strong negative correlation between reports and rank remains consistent since **a** **lower rank number denotes a higher standing.** Hence, more reports translate to a better rank. This pair mirrors the reports–points finding and adds no independent information.
{% endtab %}
{% endtabs %}

### Checking for outlier sensitivity

The most extreme hunter (5,610 reports, 84,713 points, username rabhi) could plausibly be inflating the correlation.

| Sample                      | n  | Spearman ρ | p-value  |
| --------------------------- | -- | ---------- | -------- |
| Full sample                 | 81 | +0.875     | 1.33e-26 |
| Most extreme hunter removed | 80 | +0.870     | 1.08e-25 |

The coefficient barely moves from 0.875 to 0.870.

***

## Limitations and Future Research

### Regression Analysis

An attempt was made to fit a linear regression of `points ~ reports`, specifically to answer _by how much_ points move for a given increase in reports. This was tested and did not hold up under standard regression assumption checks: residuals failed both the homoscedasticity test (Breusch-Pagan p = 0.010) and the normality test (Shapiro-Wilk p < .001), driven by the same heavy skew and outliers noted above. A log-log specification (`log(points) ~ log(reports)`) was tried next and fixed the normality issue, but homoscedasticity still failed (Breusch-Pagan p = 0.00017).

### Report severity

The dataset records accepted report counts but not severity or reward-per-report. Two hunters with equal report counts can have very different point totals depending on report severity.

***

## Conclusion

Spearman's rank correlation analysis found a **very strong, statistically significant positive monotonic relationship** between accepted reports and total points earned among the 81 public hunters analysed (ρ = +0.875, p = 1.33e-26).

***
