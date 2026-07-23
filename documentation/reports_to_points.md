I wanted to find out if there is a relationship between the number of points and reports between a hunter

Spearman was used for the following reasons

Spearman's rank correlation was used because exploratory data analysis indicated that the variables exhibited substantial right skew and contained several outliers. These characteristics suggest that the assumptions of Pearson's correlation, particularly linearity and sensitivity to outliers, may not be satisfied. Spearman's correlation, a non-parametric measure based on ranked observations, was therefore selected.

Even stronger would be:

Spearman's rank correlation was selected because the variables exhibited monotonic rather than linear relationships, as indicated by exploratory scatter plots. Additionally, the distributions were highly right-skewed and contained several outliers, making Spearman's correlation more appropriate than Pearson's correlation.

\begin{table}[!htbp]
\caption{Descriptives}
\label{tbl:Table_Descriptives}
\begin{adjustbox}{max size={\columnwidth}{\textheight}}
\centering
\begin{tabular}{lrr}
\toprule
~                   &   reports &   points \\
\midrule
N                   &     78.00 &    78.00 \\
Missing             &      0.00 &     0.00 \\
Mean                &    451.59 &  7121.37 \\
Median              &    290.00 &  5181.00 \\
Standard deviation  &    650.46 &  9711.95 \\
Variance            & 423095.80 &  9.43e+7 \\
Minimum             &     98.00 &  2586.00 \\
Maximum             &   5610.00 & 84713.00 \\
Skewness            &      6.73 &     6.90 \\
Std. error skewness &      0.27 &     0.27 \\
Shapiro-Wilk W      &      0.39 &     0.36 \\
Shapiro-Wilk p      &    <~.001 &   <~.001 \\
\bottomrule
\end{tabular}
\end{adjustbox}
\end{table}


## Decide whether you should add rank or not, either way works, but rank is more or less the same as points so it can make sense to omit

Variables	Spearman's ρ	p-value	Interpretation
Reports vs Points	0.872	< .001	Very strong positive correlation
Reports vs Rank	−0.872	< .001	Very strong negative correlation
Points vs Rank	−1.000	< .001	Perfect negative correlation

A strong positive Spearman correlation was observed between the number of accepted reports and total points earned (ρ = 0.872, p < .001), indicating that hunters with higher reporting activity generally accumulated more reward points.

Reporsts Vs Rank made perfect sense as well given that higher number of reports would give a smaller (in this context, a higher) rank

My initial assumption of points having a higher rank was also true.