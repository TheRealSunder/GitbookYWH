---
description: >-
  Does a hunter's accepted-report count predict their total points? A Spearman
  rank-correlation analysis across 81 public hunter profiles.
icon: chart-line
---

# Reports vs. Points — Correlation Analysis

## Overview

This page documents the end-to-end analysis that investigates whether the number of accepted bug reports submitted by a hunter predicts the total number of points they earn on the platform.

The analysis covers **81 public hunter profiles** drawn from a dataset of 100 ranked hunters. The remaining 19 had undisclosed public profiles and were excluded (see [Limitations](reports-vs.-points-correlation-analysis.md#limitations-and-future-research)).

{% hint style="info" %}
**Update.** An earlier version of this page reported 78 disclosed profiles out of 100. Three additional public hunter profiles were located since, raising the analysed sample to 81 (and the undisclosed count down to 19). Every statistic on this page is recomputed from the current 81-hunter dataset; none of the earlier 78-hunter figures are reused.
{% endhint %}

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

### Steps to reproduce

{% stepper %}
{% step %}
### Collect per-hunter stats

Every disclosed hunter's `stats.json` lives under `Codes/hunters/<name>/`. `load_stats()` globs all 81 files into one DataFrame.
{% endstep %}

{% step %}
### Clean and coerce types

`clean()` forces `points`, `reports`, `rank` and `impact` to numeric, then resolves a single display name per hunter from `name` → `username` → folder name, in that priority order.
{% endstep %}

{% step %}
### Run the assumption checks

Independence, normality (Shapiro-Wilk), outlier magnitude, and monotonicity are checked before any test is chosen (see [Assumption Checks](reports-vs.-points-correlation-analysis.md#assumption-checks) below).
{% endstep %}

{% step %}
### Compute Spearman (and Pearson, for contrast)

`spearman()` runs both correlations for each variable pair, prints tie counts, and flags a monotone-but-not-linear relationship whenever |ρ − r| exceeds 0.10.
{% endstep %}

{% step %}
### Export the scatter plot and CSV

`plot_scatter()` writes the linear/log-log scatter with a median-points-per-report reference line; `export_csv()` writes the per-hunter summary table sorted by rank.
{% endstep %}
{% endstepper %}

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

Exploratory scatter plots (linear and log–log, see [Visualisations](reports-vs.-points-correlation-analysis.md#visualisations)) show a consistently increasing, monotonic relationship between reports and points rather than a straight-line one. This is further evidenced by the divergence between Spearman ρ and Pearson r (see [Results](reports-vs.-points-correlation-analysis.md#results)).
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

{% hint style="info" %}
**A separate regression-based check on this same relationship exists.** The Statistical Inference section of this space includes a dedicated assumption-check pass for fitting `points ~ reports` as a linear regression (raw scale, outlier-removed, log-log, and feasible-GLS variants). That analysis independently confirms the finding here: a plain linear model does not satisfy its own residual assumptions on this data, which is exactly why this page uses Spearman rather than a fitted regression line.
{% endhint %}

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

The large gap between mean and median in both variables reflects the heavy right skew: a small number of high-volume hunters pull the mean substantially above the typical value. The single most extreme hunter (5,610 reports, 84,713 points) sets both column maxima.

***

## Visualisations

The script produces a side-by-side scatter plot with both a linear and a log–log axis.

\*Suggested caption: "Linear panel (left) shows the raw cluster of hunters with Spearman ρ in the title; log–log panel (right) compresses the range so the full 81-hunter population is readable. The dashed line in both panels marks the median points-per-report ratio."\*

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

With the current 81-hunter sample, the median points-per-report ratio is **17.06**.

* Hunters **above** the line earn more points per report than the typical hunter — higher-severity or higher-quality findings.
* Hunters **below** the line earn fewer points per report — higher volume at lower severity, or more informational/low-severity reports.

This makes the quality-vs-volume split visible without fitting a model.

***

## Results

Spearman's rank correlation was computed for three variable pairs. The points–rank pair is discussed separately because it is a structural relationship, not a behavioural finding.

| Variables         | n  | Spearman ρ | p-value  | Pearson r | Pearson p | Interpretation                |
| ----------------- | -- | ---------- | -------- | --------- | --------- | ----------------------------- |
| Reports vs Points | 81 | +0.875     | 1.33e-26 | +0.960    | 1.27e-45  | Very strong positive          |
| Reports vs Rank   | 81 | −0.875     | 1.33e-26 | −0.478    | 6.34e-06  | Very strong negative          |
| Points vs Rank    | 81 | −1.000     | \~0      | −0.502    | 1.79e-06  | Perfect negative (structural) |

{% tabs %}
{% tab title="Reports vs. Points" %}
A very strong positive monotonic correlation was found between accepted reports and total points earned (ρ = +0.875, p = 1.33e-26). Because p < α = 0.05, the **null hypothesis is rejected**. Hunters with more accepted reports consistently earned more points.
{% endtab %}

{% tab title="Reports vs. Rank" %}
The strong negative correlation between reports and rank (ρ = −0.875) is directionally consistent: on this platform a **lower rank number denotes a higher standing**, so more reports translates to a better (lower-numbered) rank. This pair mirrors the reports–points finding and adds no independent information. Note that Pearson r (−0.478) is far weaker than Spearman ρ here — rank is a heavily nonlinear (roughly reciprocal-shaped) function of the underlying points total, so a linear correlation understates the real relationship substantially more than it does for reports-vs-points.
{% endtab %}

{% tab title="Points vs. Rank (structural check)" %}
The perfect rank correlation (ρ = −1.000) confirms that rank is mathematically derived from points — they carry identical ordering information in opposite directions. This result is expected and serves as a **sanity check**, not a finding. Note that Pearson r for this same pair is only −0.502: rank is a monotonic but distinctly nonlinear transform of points (leaderboard point gaps compress heavily at the top), which is exactly the scenario Spearman is built to detect correctly and Pearson is not. Rank is excluded from the primary analysis to avoid redundancy.
{% endtab %}
{% endtabs %}

{% hint style="warning" %}
**Ties.** `reports` has 5 tied values across the 81 hunters (5 hunters share a report count with at least one other hunter); `points` and `rank` have none. Spearman uses average ranks for ties, and 5 out of 81 is a small enough share that it has no meaningful effect on ρ here.
{% endhint %}

### Sensitivity check: is the correlation driven by one outlier?

The most extreme hunter (5,610 reports, 84,713 points — roughly 12× the sample mean on both variables) could plausibly be inflating the correlation. Because Spearman uses ranks rather than raw magnitudes, removing this single hunter is a direct way to test that:

| Sample                      | n  | Spearman ρ | p-value  |
| --------------------------- | -- | ---------- | -------- |
| Full sample                 | 81 | +0.875     | 1.33e-26 |
| Most extreme hunter removed | 80 | +0.870     | 1.08e-25 |

The coefficient barely moves (+0.875 → +0.870). This is the payoff of using rank correlation on this kind of data: the same outlier that would dominate a Pearson correlation or an OLS regression fit (see the cross-referenced regression assumption-check page) has almost no effect on Spearman ρ, because Spearman only cares that this hunter ranks highest on both variables, not by how much.

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

{% hint style="warning" %}
**Data-quality note.** One hunter's `name` field in the source `stats.json` (username `Xel`) contains a mis-decoded character, rendering as "Rapha�l Kevin Arrouas" in the exported CSV rather than the intended name. This is a pre-existing encoding issue in the scraped source data, not something introduced by this script. The `username` field for this hunter (`Xel`) is unaffected and is the more reliable identifier until the source `stats.json` is re-scraped or manually corrected.
{% endhint %}

***

## Limitations and Future Research

### Hunter tenure

A hunter active on the platform for longer will naturally accumulate more reports and points. The observed correlation may partly reflect differences in account age rather than a direct link between activity and reward. Future work could control for tenure by including account creation date as a covariate (`joined` is already present in `stats.json`), or by analysing reports-per-month and points-per-month instead of raw totals. No partial correlation or tenure-adjusted analysis has been run yet — this remains an open item, not a completed check.

### Undisclosed profiles

Of the 100 ranked hunters, **19 had undisclosed public profiles** and were excluded (down from 22 in the previous version of this page, after 3 additional public profiles were located). If disclosure is systematically related to performance level — for example, if top-ranked hunters are more or less likely to make their profiles public — the 81-hunter sample may not be representative of the full population. Future work could examine whether disclosed and undisclosed hunters differ in activity level, and whether the correlation holds across the full 100.

### Report severity

The dataset records accepted report counts but not severity or reward-per-report. Two hunters with equal report counts can have very different point totals depending on whether they filed critical versus low-severity reports. The `points_per_report` column in the CSV export approximates this, but a full severity breakdown would require the per-report `hacktivities.json` data already collected alongside each `stats.json`.

***

## Conclusion

Spearman's rank correlation analysis found a **very strong, statistically significant positive monotonic relationship** between accepted reports and total points earned among the 81 public hunters analysed (ρ = +0.875, p = 1.33e-26). The null hypothesis of no relationship was rejected at α = 0.05.

The log–log scatter and the divergence between ρ and Pearson r both indicate that the relationship is **monotone but not linear**: points grow disproportionately faster than reports at the high end of the leaderboard, consistent with high-volume hunters also tending to file higher-severity reports or accumulate tenure-based bonuses — though this specific explanation has not itself been tested and should be read as a plausible account, not a demonstrated one. This non-linearity does not weaken the main finding — Spearman is designed to capture it — but it means a simple linear model would underestimate the reward for the most active hunters. The sensitivity check above confirms this conclusion is not an artifact of the single most extreme hunter: removing them changes ρ by only 0.005.

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
