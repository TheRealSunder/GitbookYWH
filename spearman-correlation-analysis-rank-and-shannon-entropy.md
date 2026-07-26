---
description: >-
  Does vulnerability specialization, measured via Shannon entropy over CWE
  categories, correlate with hunter rank?
icon: shuffle
---

# Spearman Correlation Analysis: Rank and Shannon Entropy

## Research Question

Does vulnerability specialization correlate with hunter rank?

***

## Definitions

**Vulnerability specialization** is defined as the concentration of a hunter's reporting effort across vulnerability classes. Hunters whose reports are disproportionately concentrated within one or a few vulnerability classes exhibit greater specialization, whereas hunters whose reports are distributed more evenly across multiple vulnerability classes exhibit greater generalization.

**Generalization** refers to the distribution of reporting effort across a wider variety of vulnerability classes, resulting in higher Shannon entropy values.

***

## Statistical Methods

### Shannon Entropy

For each hunter, Shannon entropy (in bits) is calculated from the distribution of Common Weakness Enumeration (CWE) categories in their accepted reports. Lower entropy values indicate greater concentration of reporting effort (greater specialization) and higher entropy values indicate greater diversity of reporting effort (greater generalization).

### Spearman Correlation

Spearman's rank correlation coefficient is used to assess the monotonic relationship between Shannon entropy and hunter rank. Spearman's correlation is selected because hunter rank is an ordinal variable and exploratory data analysis indicated that the variables are non-normally distributed and contain outliers.

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

Groups those records by CWE identifier (`cwe`), producing a count per category.


{% endstep %}

{% step %}
### Compute Shannon entropy in bits

Using the standard formula:

$$H = -\sum_{i} p_i \log_2 p_i$$

where $$p_i$$ is the proportion of reports that fall into category $$i$$. The implementation in `shannon.py` is:

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
Only `entropy_bits` (the raw value of $H$) is used in this analysis. Normalizing entropy against the theoretical maximum for a hunter's category count (`entropy_norm = H / log2(k)`) was considered and phased out, because normalization conflates two distinct properties — how evenly spread the reports are and how many categories were touched — making it less suited to a between-hunter comparison on the diversity dimension alone. No `entropy_max` or `entropy_norm` column is produced by `ShannonEntropy.py` or present in `hunter_entropy.csv`.


{% endhint %}

### Why CWE Instead of `bug_name`

Entropy could be computed over either the free-text `bug_name` field or the standardized `cwe` field present in each hacktivity record. `cwe` was chosen for the following reasons:

* `bug_name` is not a standardized taxonomy. The same underlying weakness can appear under multiple labels — for example, "Reflected XSS", "Stored XSS" and "DOM XSS" are all manifestations of CWE-79 (Cross-site Scripting), but as three distinct `bug_name` values they would inflate a hunter's entropy score even where the underlying work is concentrated in a single vulnerability class.
* Naming conventions vary by program: the same weakness may be labelled "Reflected XSS", "Non-persistent XSS", "Cross Site Scripting" or "HTML Injection" depending on the platform. Entropy computed over `bug_name` would partly measure differences in labelling conventions rather than differences in the breadth of vulnerability classes a hunter works in.
* `cwe` provides a fixed, program-independent category set, so entropy computed over it measures breadth across vulnerability classes rather than breadth across report labels — which is what specialization refers to in the Definitions above.
* `bug_name` is not discarded from the analysis. It remains available as descriptive information about each report, but the entropy calculation itself is based on `cwe`.

### What the entropy value means for each hunter

A hunter's `entropy_bits` score reflects how evenly their accepted reports are spread across vulnerability categories:

{% hint style="success" %}
* **Low entropy (close to 0 bits):** The hunter concentrates almost all reports in one or two categories. Their portfolio is narrow and specialized.
* **High entropy:** Reports are spread across many categories with roughly equal frequency. The hunter is broadly diversified.
{% endhint %}

For example, `rabhi` (rank 1, 5 610 reports, `entropy_bits = 2.7254`) is moderately concentrated relative to the theoretical maximum for 43 distinct CWE categories, while `Brumens` (rank 100, 125 reports, `entropy_bits = 3.8087` across 24 categories) shows notably more uniform spread within their smaller portfolio.

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

| Statistic            | Value  |
| -------------------- | ------ |
| Spearman's $\rho$    | 0.0147 |
| p-value (two-tailed) | 0.8966 |
| N                    | 81     |

### Interpretation

The correlation coefficient of $\rho = 0.0147$ is negligible in magnitude and close to zero. The (weakly) positive sign indicates that higher-ranked hunters (lower rank number) have a very slight tendency toward lower entropy — i.e., marginally more specialized — but the effect is far too small to be meaningful.

{% hint style="info" %}
The p-value of $0.8966$ is far above $\alpha = 0.05$. The null hypothesis cannot be rejected. There is **no statistically significant association** between a hunter's leaderboard rank and their Shannon entropy (diversification) across vulnerability categories, measured by CWE, in this dataset.
{% endhint %}
