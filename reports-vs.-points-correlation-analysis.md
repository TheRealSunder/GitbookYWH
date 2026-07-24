---
description: >-
  Does a hunter's accepted-report count predict their total points? A Spearman
  rank-correlation analysis across 78 public hunter profiles.
icon: chart-line
---

# Reports vs. Points — Correlation Analysis

## Overview

This page documents the end-to-end analysis that investigates whether the number of accepted bug reports submitted by a hunter predicts the total number of points they earn on the platform.

The analysis covers **78 public hunter profiles** drawn from a dataset of 100. The remaining 22 had undisclosed public profiles and were excluded (see [Limitations](reports-vs.-points-correlation-analysis.md#limitations-and-future-research)).

***

## Research Question

> **Is there a statistically significant monotonic relationship between the number of accepted reports a hunter submits and the total points they earn?**

***

## Hypotheses

| Symbol | Statement                                                                         |
| ------ | --------------------------------------------------------------------------------- |
| **H₀** | There is no relationship between accepted reports and total points earned (ρ = 0) |
| **Hₐ** | There is a relationship between accepted reports and total points earned (ρ ≠ 0)  |

Significance level: **α = 0.05**

***

## Data Pipeline

Each hunter's data is stored in a per-folder `stats.json` file and loaded into a single pandas DataFrame before analysis.

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

**Loading and cleaning (simplified)**

```python
def load_stats(hunters_dir: Path) -> pd.DataFrame:
    records = []
    for stats_path in sorted(hunters_dir.glob("*/stats.json")):
        with stats_path.open(encoding="utf-8") as fh:
            data = json.load(fh)
        data["_folder"] = stats_path.parent.name
        records.append(data)
    return pd.DataFrame(records)

def clean(df: pd.DataFrame) -> pd.DataFrame:
    for col in ("points", "reports", "rank", "impact"):
        if col in df:
            df[col] = pd.to_numeric(df[col], errors="coerce")
    # Name resolution: profile name → username → folder name
    for src in ("name", "username", "_folder"):
        if src in df.columns:
            df["hunter"] = df.get("hunter", pd.NA)
            df["hunter"] = df["hunter"].fillna(df[src])
    return df
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

The Shapiro-Wilk test was applied to both variables. Both returned W values below 0.40 with p < .001, indicating a strong departure from normality. Both distributions exhibit heavy right skew (skewness ≈ 6.73 for reports, 6.90 for points): a small number of high-volume hunters pull the mean well above the median.

```
Reports  — mean: 451.59,  median: 290.00,  max: 5,610
Points   — mean: 7,121.37, median: 5,181.00, max: 84,713
```
{% endstep %}

{% step %}
### Outliers

Extreme values are present in both variables. The maximum report count (5,610) is roughly **12× the mean**, and the maximum points value (84,713) is also roughly **12× the mean**. These values would substantially inflate a Pearson correlation.
{% endstep %}

{% step %}
### Monotonicity

Exploratory scatter plots (linear and log–log, see [Visualisations](reports-vs.-points-correlation-analysis.md#visualisations)) show a consistently increasing, monotonic relationship between reports and points rather than a straight-line one. This is further evidenced by the divergence between Spearman ρ and Pearson r (see [Results](reports-vs.-points-correlation-analysis.md#results)).
{% endstep %}
{% endstepper %}

***

## Choice of Statistical Test

**Spearman's rank correlation** was selected for the following reasons:

| Condition                                       | Status                             |
| ----------------------------------------------- | ---------------------------------- |
| Monotonic (not necessarily linear) relationship | ✓ Confirmed by scatter             |
| Heavy right skew in both variables              | ✓ Skewness ≈ 6.7–6.9               |
| Outliers present                                | ✓ Max ≈ 12× mean                   |
| Normality required by Pearson                   | ✗ Violated (Shapiro-Wilk p < .001) |

Spearman correlates the **ranks** of the values rather than the values themselves. This makes it robust to the heavy right tail that leaderboard fields tend to have and detects any monotone relationship rather than only a linear one.

Pearson's r is reported alongside Spearman's ρ as a contrast metric only — not as a primary finding.

```python
sp_result  = sps.spearmanr(pair["reports"], pair["points"])
rho, p     = sp_result.correlation, sp_result.pvalue

pear_result        = sps.pearsonr(pair["reports"], pair["points"])
pear_r, pear_p     = pear_result.statistic, pear_result.pvalue
```

{% hint style="info" %}
**Note on divergence.** When |ρ − r| > 0.10, the script flags the gap and notes that the relationship is monotone but not linear — for example, points growing disproportionately faster than reports at the top end of the leaderboard.
{% endhint %}

***

## Descriptive Statistics

The table below summarises central tendency, spread, and distributional shape for both variables across the **78 public hunters** in the analysis.

| Statistic           | Reports    | Points     |
| ------------------- | ---------- | ---------- |
| N                   | 78         | 78         |
| Missing             | 0          | 0          |
| Mean                | 451.59     | 7,121.37   |
| Median              | 290.00     | 5,181.00   |
| Standard deviation  | 650.46     | 9,711.95   |
| Variance            | 423,095.80 | 94,300,000 |
| Minimum             | 98         | 2,586      |
| Maximum             | 5,610      | 84,713     |
| Skewness            | 6.73       | 6.90       |
| Std. error skewness | 0.27       | 0.27       |
| Shapiro-Wilk W      | 0.39       | 0.36       |
| Shapiro-Wilk p      | < .001     | < .001     |

The large gap between mean and median in both variables reflects the heavy right skew: a small number of high-volume hunters pull the mean substantially above the typical value.

***

## Visualisations

The script produces a side-by-side scatter plot with both a linear and a log–log axis.

**What to look for in the plots**

| Panel       | Purpose                                                                                                                                                 |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Linear**  | Shows Spearman ρ in the title and makes the cluster of typical hunters visible. Outliers appear far to the right.                                       |
| **Log–log** | Compresses the range so the full hunter population is readable. A straight line in log–log space implies a power-law relationship (points ∝ reports^k). |

**Reference line — median points-per-report**

Both panels include a dashed reference line through the origin at the **median points-per-report ratio**:

```python
ppr_median = (pair["points"] / pair["reports"].replace(0, pd.NA)).median()
xs = [pair["reports"].min(), pair["reports"].max()]
ax.plot(xs, [x * ppr_median for x in xs],
        ls="--", lw=1, color="#C44E52",
        label=f"median {ppr_median:.2f} pts/report")
```

* Hunters **above** the line earn more points per report than the typical hunter — higher-severity or higher-quality findings.
* Hunters **below** the line earn fewer points per report — higher volume at lower severity, or more informational/low-severity reports.

This makes the quality-vs-volume split visible without fitting a model.

***

## Results

Spearman's rank correlation was computed for three variable pairs. The points–rank pair is discussed separately because it is a structural relationship, not a behavioural finding.

| Variables         | n  | Spearman ρ | p-value | Pearson r | Interpretation                |
| ----------------- | -- | ---------- | ------- | --------- | ----------------------------- |
| Reports vs Points | 78 | +0.872     | < .001  | —         | Very strong positive          |
| Reports vs Rank   | 78 | −0.872     | < .001  | —         | Very strong negative          |
| Points vs Rank    | 78 | −1.000     | < .001  | —         | Perfect negative (structural) |

{% tabs %}
{% tab title="Reports vs. Points" %}
A very strong positive monotonic correlation was found between accepted reports and total points earned (ρ = +0.872, p < .001). Because p < α = 0.05, the **null hypothesis is rejected**. Hunters with more accepted reports consistently earned more points.
{% endtab %}

{% tab title="Reports vs. Rank" %}
The strong negative correlation between reports and rank (ρ = −0.872) is directionally consistent: on this platform a **lower rank number denotes a higher standing**, so more reports translates to a better (lower-numbered) rank. This pair mirrors the reports–points finding and adds no independent information.
{% endtab %}

{% tab title="Points vs. Rank (structural check)" %}
The near-perfect correlation (ρ = −1.000) confirms that rank is mathematically derived from points — they carry identical information in opposite directions. This result is expected and serves as a **sanity check**, not a finding. Rank is excluded from the primary analysis to avoid redundancy.
{% endtab %}
{% endtabs %}

{% hint style="warning" %}
**Ties note.** The Spearman function uses average ranks for tied values. If the console output reports a large tie count for either variable, interpret ρ with slight caution — tied ranks deflate the magnitude of Spearman's correlation.
{% endhint %}

***

## CSV Export

The script writes a summary CSV to `Outputs/hunter_points_reports.csv`, sorted by rank ascending.

**Schema**

| Column              | Description                                    |
| ------------------- | ---------------------------------------------- |
| `name`              | Hunter display name                            |
| `reports`           | Total accepted reports                         |
| `points`            | Total points earned                            |
| `rank`              | Platform rank (lower = better)                 |
| `points_per_report` | Derived: `points / reports`, rounded to 4 d.p. |

```python
out["points_per_report"] = (
    out["points"] / out["reports"].replace(0, pd.NA)
).round(4)
out = out.sort_values("rank", na_position="last")
out.to_csv(path, index=False, encoding="utf-8")
```

`points_per_report` is included so downstream consumers can independently verify the reference-line calculation from the scatter plot without re-running the script.

***

## Limitations and Future Research

### Hunter tenure

A hunter active on the platform for longer will naturally accumulate more reports and points. The observed correlation may partly reflect differences in account age rather than a direct link between activity and reward. Future work could control for tenure by including account creation date as a covariate (`joined` is already present in `stats.json`), or by analysing reports-per-month and points-per-month instead of raw totals.

### Undisclosed profiles

Of the 100 hunters in the full dataset, **22 had undisclosed public profiles** and were excluded. If disclosure is systematically related to performance level — for example, if top-ranked hunters are more or less likely to make their profiles public — the 78-hunter sample may not be representative of the full population. Future work could examine whether disclosed and undisclosed hunters differ in activity level, and whether the correlation holds across the full 100.

### Report severity

The dataset records accepted report counts but not severity or reward-per-report. Two hunters with equal report counts can have very different point totals depending on whether they filed critical versus low-severity reports. The `points_per_report` column in the CSV export approximates this, but a full severity breakdown would require the per-report `hacktivities.json` data already collected alongside each `stats.json`.

***

## Conclusion

Spearman's rank correlation analysis found a **very strong, statistically significant positive monotonic relationship** between accepted reports and total points earned among the 78 public hunters analysed (ρ = +0.872, p < .001). The null hypothesis of no relationship was rejected at α = 0.05.

The log–log scatter and the divergence between ρ and Pearson r both indicate that the relationship is **monotone but not linear**: points grow disproportionately faster than reports at the high end of the leaderboard, consistent with high-volume hunters also tending to file higher-severity reports or accumulate tenure-based bonuses. This non-linearity does not weaken the main finding — Spearman is designed to capture it — but it means a simple linear model would underestimate the reward for the most active hunters.

The confounds noted above (tenure, disclosure bias, severity mix) should be kept in mind when interpreting the direction and magnitude of this association.

***

## Running the Script

```bash
# From the project root
python Codes/reports_to_points.py
```

**Outputs produced**

| File                                | Description                                       |
| ----------------------------------- | ------------------------------------------------- |
| `Outputs/reports_vs_points.png`     | Side-by-side linear and log–log scatter plot      |
| `Outputs/hunter_points_reports.csv` | Per-hunter summary table with `points_per_report` |

**Dependencies**

```
matplotlib
pandas
scipy
```
