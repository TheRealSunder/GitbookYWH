# Shannon Entropy Analysis

First, the script shannon.py was used to calculate Shannon entropy for each hunter.

## Research Question

Is a hunter's leaderboard rank associated with their degree of specialization or diversification across vulnerability categories?

## Variables

- Independent variable (IV): Rank
- Dependent variable (DV): Normalized Shannon Entropy

## Method

For each hunter:

1. Count reports per CWE.
2. Compute Shannon entropy.
3. Compute maximum entropy.
4. Normalize the result.

A low entropy score suggests that a hunter is more specialized, while a high entropy score suggests greater diversification.

## Normalization

Raw entropy depends on the number of vulnerability categories present. Normalization makes hunters comparable across the dataset.

Normalized entropy can be expressed as:

$H_{norm} = \frac{H}{H_{max}}$

## Result

Each hunter receives a specialization score between 0 and 1.

## Statistical Hypotheses

### Null Hypothesis

$H_0: \rho = 0$

There is no association between hunter rank and specialization.

### Alternative Hypothesis

$H_a: \rho \neq 0$

There is an association between hunter rank and specialization.

## Spearman Rank Correlation

From manualspearman.py:

- Before CWE normalization: $\rho = 0.4403$, $p = 0.000055$, $N = 78$
- After CWE normalization: $\rho = 0.458$, $p = 2.49 \times 10^{-5}$, $N = 78$, $df = 76$

Both results are consistent with the jamovi output. The normalized CWE result value of 0.458 indicates a moderate positive correlation. And a p-value of less than alpha 0.05 indicates that the results are statistically significant. This means that there is a correlation between a hunter's rank and specialization in a field

## Open Questions

- What is the significance of converting legacy labels to their canonical modern equivalents?
- Which is preferable: using CWE or using bug names? What is the impact of each approach?
- How should we clarify what Shannon entropy measures versus what Spearman correlation measures?
- Bonus question: Can we identify what the top 10 hunters specialize in?
- Alternatively, is the relationship between specialization and success still present after accounting for the number of reports submitted?