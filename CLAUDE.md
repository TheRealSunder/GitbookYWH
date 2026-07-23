# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository purpose

This is a research-notes repository documenting a statistical analysis of bug bounty hunter data (reports, points, CWE categories, entropy of specialization). It is not a software project — there is no build, lint, or test tooling, and no application source code lives here. The repository is synced with a GitBook space (see `.mcp.json`, which wires up the `gitbook` MCP server) and `documentation/` is written to mirror that GitBook content.

## Structure

- `documentation/` — Markdown write-ups of each analysis stage, meant to be read in this order:
  1. `datapreprocessing.md` — cleaning hacktivity data, reconciling legacy OWASP labels with canonical CWE/bug_name categories, deciding how to count a "report" (uses report status `new` as the estimator, since resolution status is inconsistent).
  2. `statistical inference.md` — EDA on points/reports/join-date/country distributions, and a sanity check comparing hunter-reported stats totals vs. hacktivity-derived totals (large discrepancies for some hunters, exact matches for others).
  3. `shannon.md` — Shannon entropy analysis of each hunter's specialization across CWE categories, correlated (Spearman) against leaderboard rank.
  4. `reports_to_points.md` — Spearman correlation between reports, points, and rank.
- `output/` — Generated CSVs and PNG charts referenced by the docs (e.g. `hunter_entropy.csv`, `hunter_points_reports.csv`, distribution plots). These are analysis artifacts, not something to hand-edit.
- The Python scripts referenced throughout the docs (`stat_checker.py`, `normalize_hacktivity.py`, `shannon.py`, `manualspearman.py`, `hunter_probe.py`, `EDA.py`, `sanity_check_total_reports.py`) are **not present in this repo** — the docs describe their output/methodology, not their implementation. Don't assume these scripts exist on disk; check before referencing them as runnable.

## Working with this repo

- Treat `documentation/*.md` as lab-notebook-style writing: each file records a research question, method, and result, often with open questions at the end (see the "Open Questions" section in `shannon.md`). When editing, preserve this narrative/methodology framing rather than converting it to generic docs.
- Statistical results (Spearman's ρ, p-values, N) quoted in the docs come from specific analysis runs — don't alter reported numbers without re-deriving them from the underlying data/scripts.
- GitBook sync: content changes intended for the published GitBook space should go through the `gitbook` MCP tools (change request → edit → submit/merge), not direct pushes — see the GitBook MCP server instructions for the editing workflow.
