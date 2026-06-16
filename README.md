# Trace Budget Auditor

Practical Python CLI that audits raw request traces against latency and error budgets so a release review can focus on the routes that are actually unhealthy.

## What it does

- Loads CSV traces with `route`, `duration_ms`, and `status`
- Aggregates per-route sample count, average, P50, P95, and P99 latency
- Measures 5xx error rate by route
- Flags routes that breach a configurable P95 latency budget or error budget
- Optionally rolls routes up into family hot spots like `/api/checkout` or `/api/users`
- Prints a release posture (`clear`, `review breaches`, or `hold release`) from the current breach severity
- Can focus on one route family or emit only budget breaches
- Optionally exports the route summary as CSV for handoff into a spreadsheet or incident review doc

## Why this is useful

This is the kind of small utility that turns noisy raw logs into a release-facing answer:

- Which endpoints are breaking the latency target?
- Which routes are error-prone enough to hold a rollout?
- Which paths are fine and should stop absorbing debugging time?

## Usage

```bash
python auditor.py --input sample_traces.csv
```

Tighter budgets with CSV export:

```bash
python auditor.py --input sample_traces.csv --latency-budget 280 --error-budget 1.5 --output reports/summary.csv
```

Route-family rollup for a faster release-review pass:

```bash
python auditor.py --input sample_traces.csv --family-depth 2 --json-out reports/summary.json
```

Breach-only audit for one route family:

```bash
python auditor.py --input sample_traces.csv --route-prefix /api/checkout --breaches-only
```

## Input format

```csv
route,duration_ms,status
/api/search,182,200
/api/search,448,200
/api/checkout,812,503
```

## Sample workflow

1. Export recent request traces from your API/logging stack into CSV.
2. Run the auditor with the latency and error budgets your team actually uses.
3. Review the top breach routes first.
4. Export the summary CSV when you need to attach evidence to a release note or incident thread.

## Portfolio Positioning

- Project type: Python CLI utility
- Stack: Python, CSV, latency/error-budget analysis
- Verification path: `python auditor.py --input sample_traces.csv --family-depth 2 --output reports/summary.csv`
