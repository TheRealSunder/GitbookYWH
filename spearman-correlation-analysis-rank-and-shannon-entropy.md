---
description: >-
  Does a hunter's leaderboard rank correlate with how specialized or diversified
  their report portfolio is, measured via Shannon entropy?
icon: shuffle
---

# Spearman Correlation Analysis: Rank and Shannon Entropy

## Research Question

Is a hunter's leaderboard rank associated with their degree of specialization or diversification across vulnerability categories?

***

## Variables

| Role             | Variable       | Description                                                  |
| ---------------- | -------------- | ------------------------------------------------------------ |
| Independent (IV) | `rank`         | The hunter's position on the leaderboard (lower = better)    |
| Dependent (DV)   | `entropy_bits` | Shannon entropy of the hunter's report distribution, in bits |

***

## How Shannon Entropy Was Constructed

The entropy values were produced by `shannon.py`. For each hunter, the script:

{% stepper %}
{% step %}
### Read every "New" record

Reads every hacktivity record whose `status` is `"New"`.
{% endstep %}

{% step %}
### Group by vulnerability category

Groups those records by vulnerability category (e.g. `bug_name` or `cwe`), producing a count per category.
{% endstep %}

{% step %}
### Compute Shannon entropy in bits

Using the standard formula:

$$H = -\sum_{i} p_i \log_2 p_i$$

where $p\_i$ is the proportion of reports that fall into category $i$. The implementation in `shannon.py` is:

```python
def shannon_entropy(counts: Counter) -> float:
    total = sum(counts.values())
    if total == 0:
        return 0.0
    h = -sum(
        (c / total) * math.log2(c / total)
        for c in counts.values()
        if c > 0
    )
    return h if h > 0 else 0.0
```
{% endstep %}
{% endstepper %}

{% hint style="info" %}
Only `entropy_bits` (the raw value of $H$) is used in this analysis. Normalized entropy (`entropy_norm = H / log2(k)`) is **not used**, because normalization conflates two distinct properties — how evenly spread the reports are and how many categories were touched — making it less suited to a between-hunter comparison on the diversity dimension alone.
{% endhint %}

### What the entropy value means for each hunter

A hunter's `entropy_bits` score reflects how evenly their accepted reports are spread across vulnerability categories:

{% hint style="success" %}
* **Low entropy (close to 0 bits):** The hunter concentrates almost all reports in one or two categories. Their portfolio is narrow and specialized.
* **High entropy:** Reports are spread across many categories with roughly equal frequency. The hunter is broadly diversified.
{% endhint %}

For example, `rabhi` (rank 1, 5 610 reports, `entropy_bits = 3.3179`) is moderately concentrated relative to the theoretical maximum for 47 categories, while `Brumens` (rank 100, 125 reports, `entropy_bits = 4.3796` across 28 categories) shows notably more uniform spread within their smaller portfolio.

***

## Hypotheses

{% columns %}
{% column width="50%" %}
### Null Hypothesis — $H\_0$

$$H_0: \rho = 0$$

There is no association between a hunter's leaderboard rank and their degree of specialization or diversification. Any observed correlation is attributable to chance.
{% endcolumn %}

{% column width="50%" %}
### Alternative Hypothesis — $H\_a$

$$H_a: \rho \neq 0$$

Specialization (or diversification) has an effect on leaderboard rank. Hunters who concentrate on fewer vulnerability types perform systematically differently from those who spread their reports across many types.
{% endcolumn %}
{% endcolumns %}

***

## Statistical Test

### Alpha Level

The significance threshold is set at:

$$\alpha = 0.05$$

A result is considered statistically significant only if the two-tailed p-value falls below this threshold.

### Spearman Rank Correlation

Spearman's $\rho$ was chosen because:

* Both variables (`rank` and `entropy_bits`) are ordinal or continuous but not assumed to be normally distributed.
* The relationship between rank and entropy may be monotonic but non-linear.
* Spearman is robust to outliers, which is important given the wide spread of report volumes in the dataset.

The correlation was computed in `spearman_entropy.py` using `scipy.stats.spearmanr` on the 81 hunters present in `hunter_entropy.csv`:

```python
from scipy.stats import spearmanr
rho, pvalue = spearmanr(df["rank"], df["entropy_bits"])
```

### Results

| Statistic            | Value   |
| -------------------- | ------- |
| Spearman's $\rho$    | −0.0489 |
| p-value (two-tailed) | 0.6647  |
| N                    | 81      |

### Interpretation

The correlation coefficient of $\rho = -0.0489$ is negligible in magnitude. The negative sign indicates that higher-ranked hunters (lower rank number) have a very slight tendency toward higher entropy — i.e., marginally more diversified — but the effect is too small to be meaningful.

{% hint style="info" %}
The p-value of $0.6647$ is far above $\alpha = 0.05$. The null hypothesis cannot be rejected. There is **no statistically significant association** between a hunter's leaderboard rank and their Shannon entropy (diversification) across vulnerability categories in this dataset.
{% endhint %}
