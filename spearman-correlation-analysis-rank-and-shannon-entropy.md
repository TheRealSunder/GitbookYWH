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

## How Shannon Entropy Was Constructed

Shannon entropy is a measure of the uncertainty or diversity within a probability distribution. In the context of hunter specialization, it is used to quantify the concentration of a hunter's reports across vulnerability classes.

<table><thead><tr><th width="183">Role</th><th width="138">Variable</th><th>Description</th></tr></thead><tbody><tr><td>Dependent (DV)</td><td><code>rank</code></td><td>The hunter's position on the leaderboard</td></tr><tr><td>Independent (IV)</td><td><code>entropy_bits</code></td><td>Shannon entropy of the hunter's report distribution</td></tr></tbody></table>

{% stepper %}
{% step %}
### Read every "New" record

Reads every hacktivity record whose `status` is `"New"`.
{% endstep %}

{% step %}
### Group by vulnerability category

Records are grouped per `cwe` identifier, producing a count per category
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

### Choosing `cwe` over `bug_name`

* `bug_names` falling under the same CWE, such as "Reflected XSS", "Stored XSS" and "DOM XSS" which are all under CWE-79 (Cross-site Scripting), having three distinct values would inflate a hunter's entropy score even when the majority of the hunter's reports are concentrated in a single vulnerability class.
* `cwe` provides a fixed, program-independent category set, so entropy computed over it measures breadth across vulnerability classes rather than breadth across report labels which is what specialization refers to in the Definitions above.

{% hint style="info" %}
- **Low entropy (close to 0 bits):** The hunter concentrates almost all reports in one or two categories. Their portfolio is narrow and specialized.
- **High entropy:** Reports are spread across many categories with roughly equal frequency. The hunter is broadly diversified.
{% endhint %}

Before conducting statistical tests, an assumption check was made to ensure that the data is fit for testing.

As seen in the histogram below, the entropy bits do not exhibit a normal distribution and are heavily skewed to the left.

A shap

<figure><img src=".gitbook/assets/entropy_bits_histogram.png" alt=""><figcaption></figcaption></figure>



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

### What the entropy value means for each hunter

A hunter's `entropy_bits` score reflects how evenly their accepted reports are spread across vulnerability categories:

{% hint style="success" %}
* **Low entropy (close to 0 bits):** The hunter concentrates almost all reports in one or two categories. Their portfolio is narrow and specialized.
* **High entropy:** Reports are spread across many categories with roughly equal frequency. The hunter is broadly diversified.
{% endhint %}

For example, `rabhi` (rank 1, 5 610 reports, `entropy_bits = 2.7254`) is moderately concentrated relative to the theoretical maximum for 43 distinct CWE categories, while `Brumens` (rank 100, 125 reports, `entropy_bits = 3.8087` across 24 categories) shows notably more uniform spread within their smaller portfolio.

***

## Assumption Checks

Before conducting any statistical tests, an assumption check was made in order to make sure the data is fit for testing.

### Normality

Based on the histogram below, which is heavily skewed to the left, `entropy_bits` does not appear to be normally distributed.&#x20;

<figure><img src=".gitbook/assets/entropy_bits_histogram (1).png" alt=""><figcaption></figcaption></figure>

A Shapiro-Wilk test confirms this: `entropy_bits` itself rejects normality (W = 0.8548, p = 2.06 × 10⁻⁷).

### Outliers

4 out of 81 hunters (`xavoppa`, `mheranco`, `0xsnpaii`, `ghazidz00`) fall above Cook's distance threshold in the preliminary regression, driven by unusually low or high entropy relative to their rank (for example, `xavoppa` has `entropy_bits = 0.5501`, well below the dataset's typical range).

<figure><img src=".gitbook/assets/cooks_distance.png" alt=""><figcaption></figcaption></figure>

### Homoscedasticity

A Breusch-Pagan test on the preliminary regression's residuals does not reject constant variance (LM statistic = 0.7057, p = 0.4009).

### Assumption checks result

| Assumption required by Pearson | Status                                                       |
| ------------------------------ | ------------------------------------------------------------ |
| Normality of `entropy_bits`    | ✗ Violated (Shapiro-Wilk p = 2.06 × 10⁻⁷)                    |
| No influential outliers        | ✗ Violated (4 of 81 above the Cook's distance 4/n threshold) |
| Homoscedasticity               | ✓ Not violated (Breusch-Pagan p = 0.4009)                    |

***

## Hypotheses

{% columns %}
{% column width="50%" %}
### Null Hypothesis: $$H_o$$

$$H_0: \rho = 0$$

There is no association between a hunter's leaderboard rank and their degree of specialization or diversification.&#x20;
{% endcolumn %}

{% column width="50%" %}
### Alternative Hypothesis: $$H_a$$

$$H_a: \rho \neq 0$$

Specialization (or diversification) affects leaderboard rank.&#x20;
{% endcolumn %}
{% endcolumns %}

***

## Statistical Test

Confidence level is set at $$\alpha = 0.05$$

### Spearman Rank Correlation

* Both variables (`rank` and `entropy_bits`) are ordinal or continuous but not normally distributed
* The relationship between rank and entropy may be monotonic but non-linear.
* Spearman is robust to outliers, which is important given the presence of outliers based on the assumption checks above.

The correlation was computed in `spearman_entropy.py` using `scipy.stats.spearmanr` on the 81 hunters present in `hunter_entropy.csv`:

```python
from scipy.stats import spearmanr
rho, pvalue = spearmanr(df["rank"], df["entropy_bits"])
```

### Results

| Statistic            | Value  |
| -------------------- | ------ |
| Spearman's $$\rho$$  | 0.0147 |
| p-value (two-tailed) | 0.8966 |
| N                    | 81     |

### Interpretation

The correlation coefficient of $$\rho = 0.0147$$ is negligible in magnitude and close to zero.&#x20;

The p-value of 0.8966 > indicates that we fail to reject $$H_o$$.
