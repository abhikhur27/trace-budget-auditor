from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path


@dataclass
class TraceRow:
    route: str
    duration_ms: float
    status: int


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Audit request traces against latency and error budgets."
    )
    parser.add_argument("--input", type=Path, required=True, help="CSV with route,duration_ms,status columns")
    parser.add_argument(
        "--baseline",
        type=Path,
        help="Optional CSV from a known-good window to compare against current routes.",
    )
    parser.add_argument("--latency-budget", type=float, default=350.0, help="P95 latency budget in milliseconds")
    parser.add_argument("--error-budget", type=float, default=2.0, help="Error-rate budget in percent")
    parser.add_argument("--min-samples", type=int, default=5, help="Minimum route sample count before auditing it")
    parser.add_argument("--route-prefix", type=str, help="Only audit routes starting with this prefix")
    parser.add_argument(
        "--family-depth",
        type=int,
        default=0,
        help="Optional route-family rollup depth (for example 2 groups /api/users/42 under /api/users).",
    )
    parser.add_argument("--breaches-only", action="store_true", help="Only print/export routes breaching any budget")
    parser.add_argument("--output", type=Path, help="Optional CSV path for the route summary")
    parser.add_argument("--json-out", type=Path, help="Optional JSON path for the audit summary")
    return parser.parse_args()


def read_rows(path: Path) -> list[TraceRow]:
    if not path.exists():
        raise FileNotFoundError(f"Trace file not found: {path}")

    with path.open("r", encoding="utf-8-sig", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"route", "duration_ms", "status"}
        missing = required.difference(set(reader.fieldnames or []))
        if missing:
            raise ValueError(f"Missing required columns: {', '.join(sorted(missing))}")

        rows: list[TraceRow] = []
        for index, row in enumerate(reader, start=2):
            route = str(row["route"]).strip()
            if not route:
                raise ValueError(f"Empty route at row {index}.")
            try:
                duration_ms = float(row["duration_ms"])
                status = int(row["status"])
            except (TypeError, ValueError) as exc:
                raise ValueError(f"Invalid numeric value at row {index}.") from exc

            if duration_ms < 0:
                raise ValueError(f"duration_ms must be non-negative at row {index}.")

            rows.append(TraceRow(route=route, duration_ms=duration_ms, status=status))

    if not rows:
        raise ValueError("Input CSV is empty.")

    return rows


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, round((pct / 100.0) * (len(ordered) - 1))))
    return ordered[index]


def route_family(route: str, depth: int) -> str:
    if depth <= 0:
        return route
    pieces = [piece for piece in route.split("/") if piece]
    if not pieces:
        return "/"
    return "/" + "/".join(pieces[:depth])


def summarize_routes(
    rows: list[TraceRow],
    latency_budget: float,
    error_budget: float,
    min_samples: int,
    route_prefix: str | None = None,
    breaches_only: bool = False,
) -> list[dict[str, float | int | str]]:
    grouped: dict[str, list[TraceRow]] = defaultdict(list)
    for row in rows:
        grouped[row.route].append(row)

    summary: list[dict[str, float | int | str]] = []
    for route, route_rows in sorted(grouped.items()):
        if route_prefix and not route.startswith(route_prefix):
            continue
        if len(route_rows) < min_samples:
            continue

        durations = [row.duration_ms for row in route_rows]
        errors = sum(1 for row in route_rows if row.status >= 500)
        p50 = percentile(durations, 50)
        p95 = percentile(durations, 95)
        p99 = percentile(durations, 99)
        avg = sum(durations) / len(durations)
        error_rate = (errors / len(route_rows)) * 100.0
        latency_breach = p95 - latency_budget
        error_breach = error_rate - error_budget

        verdict_parts = []
        if latency_breach > 0:
            verdict_parts.append("latency")
        if error_breach > 0:
            verdict_parts.append("errors")
        verdict = "healthy" if not verdict_parts else "breach: " + " + ".join(verdict_parts)

        row = {
            "route": route,
            "samples": len(route_rows),
            "avg_ms": round(avg, 1),
            "p50_ms": round(p50, 1),
            "p95_ms": round(p95, 1),
            "p99_ms": round(p99, 1),
            "error_rate_pct": round(error_rate, 2),
            "latency_breach_ms": round(max(latency_breach, 0.0), 1),
            "error_breach_pct": round(max(error_breach, 0.0), 2),
            "verdict": verdict,
        }
        if breaches_only and verdict == "healthy":
            continue
        summary.append(row)

    summary.sort(
        key=lambda row: (
            str(row["verdict"]) == "healthy",
            -float(row["latency_breach_ms"]),
            -float(row["error_breach_pct"]),
            -int(row["samples"]),
        )
    )
    return summary


def attach_baseline_deltas(
    summary: list[dict[str, float | int | str]],
    baseline_rows: list[TraceRow],
    min_samples: int,
    route_prefix: str | None = None,
) -> None:
    baseline_summary = summarize_routes(
        baseline_rows,
        latency_budget=float("inf"),
        error_budget=float("inf"),
        min_samples=min_samples,
        route_prefix=route_prefix,
        breaches_only=False,
    )
    baseline_lookup = {
        str(row["route"]): row
        for row in baseline_summary
    }

    for row in summary:
        baseline = baseline_lookup.get(str(row["route"]))
        if baseline is None:
            row["baseline_samples"] = 0
            row["p95_delta_ms"] = "new"
            row["error_rate_delta_pct"] = "new"
            continue

        row["baseline_samples"] = int(baseline["samples"])
        row["p95_delta_ms"] = round(float(row["p95_ms"]) - float(baseline["p95_ms"]), 1)
        row["error_rate_delta_pct"] = round(
            float(row["error_rate_pct"]) - float(baseline["error_rate_pct"]),
            2,
        )


def summarize_families(
    summary: list[dict[str, float | int | str]],
    family_depth: int,
) -> list[dict[str, float | int | str]]:
    if family_depth <= 0:
        return []

    grouped: dict[str, dict[str, float | int]] = defaultdict(
        lambda: {
            "routes": 0,
            "samples": 0,
            "avg_weighted_total": 0.0,
            "max_p95_ms": 0.0,
            "max_p99_ms": 0.0,
            "max_latency_breach_ms": 0.0,
            "max_error_breach_pct": 0.0,
            "breached_routes": 0,
        }
    )

    for row in summary:
        family = route_family(str(row["route"]), family_depth)
        bucket = grouped[family]
        samples = int(row["samples"])
        bucket["routes"] += 1
        bucket["samples"] += samples
        bucket["avg_weighted_total"] += float(row["avg_ms"]) * samples
        bucket["max_p95_ms"] = max(float(bucket["max_p95_ms"]), float(row["p95_ms"]))
        bucket["max_p99_ms"] = max(float(bucket["max_p99_ms"]), float(row["p99_ms"]))
        bucket["max_latency_breach_ms"] = max(float(bucket["max_latency_breach_ms"]), float(row["latency_breach_ms"]))
        bucket["max_error_breach_pct"] = max(float(bucket["max_error_breach_pct"]), float(row["error_breach_pct"]))
        if str(row["verdict"]) != "healthy":
            bucket["breached_routes"] += 1

    families: list[dict[str, float | int | str]] = []
    for family, bucket in grouped.items():
        samples = int(bucket["samples"])
        avg_ms = 0.0 if samples == 0 else float(bucket["avg_weighted_total"]) / samples
        verdict = "healthy"
        if int(bucket["breached_routes"]) > 0:
            verdict = "breach"
        families.append(
            {
                "family": family,
                "routes": int(bucket["routes"]),
                "samples": samples,
                "avg_ms": round(avg_ms, 1),
                "max_p95_ms": round(float(bucket["max_p95_ms"]), 1),
                "max_p99_ms": round(float(bucket["max_p99_ms"]), 1),
                "max_latency_breach_ms": round(float(bucket["max_latency_breach_ms"]), 1),
                "max_error_breach_pct": round(float(bucket["max_error_breach_pct"]), 2),
                "breached_routes": int(bucket["breached_routes"]),
                "verdict": verdict,
            }
        )

    families.sort(
        key=lambda row: (
            str(row["verdict"]) == "healthy",
            -float(row["max_latency_breach_ms"]),
            -float(row["max_error_breach_pct"]),
            -int(row["samples"]),
        )
    )
    return families


def print_summary(
    summary: list[dict[str, float | int | str]],
    family_summary: list[dict[str, float | int | str]],
    args: argparse.Namespace,
) -> None:
    print("Trace Budget Auditor")
    print("====================")
    print(f"P95 latency budget: {args.latency_budget:.1f} ms")
    print(f"Error budget:       {args.error_budget:.2f}%")
    print(f"Min samples:        {args.min_samples}")
    if args.route_prefix:
        print(f"Route prefix:       {args.route_prefix}")
    if args.family_depth > 0:
        print(f"Family depth:       {args.family_depth}")
    print(f"Breaches only:      {'yes' if args.breaches_only else 'no'}")
    if args.baseline:
        print(f"Baseline traces:    {args.baseline}")
    print()

    if not summary:
        print("No routes met the sample threshold.")
        return

    breached = [row for row in summary if str(row["verdict"]) != "healthy"]
    hold_routes = [
        row
        for row in summary
        if float(row["latency_breach_ms"]) >= 100 or float(row["error_breach_pct"]) >= 2.0
    ]
    posture = "hold release" if hold_routes else "review breaches"
    if not breached:
        posture = "clear"
    print(f"Routes reported:    {len(summary)}")
    print(f"Routes in breach:   {len(breached)}")
    print(f"Release posture:    {posture}")
    print()

    header = (
        f"{'Route':<24} {'N':>5} {'P50':>8} {'P95':>8} {'P99':>8} "
        f"{'Err%':>8} {'Verdict':>18}"
    )
    print(header)
    print("-" * len(header))
    for row in summary:
        print(
            f"{str(row['route']):<24} "
            f"{int(row['samples']):>5} "
            f"{float(row['p50_ms']):>8.1f} "
            f"{float(row['p95_ms']):>8.1f} "
            f"{float(row['p99_ms']):>8.1f} "
            f"{float(row['error_rate_pct']):>8.2f} "
            f"{str(row['verdict']):>18}"
        )

    if breached:
        print("\nHighest-priority routes:")
        for row in breached[:3]:
            delta_parts = []
            if "p95_delta_ms" in row:
                p95_delta = row["p95_delta_ms"]
                error_delta = row["error_rate_delta_pct"]
                if p95_delta == "new":
                    delta_parts.append("new route vs baseline")
                else:
                    delta_parts.append(f"p95 delta {float(p95_delta):+.1f} ms")
                    delta_parts.append(f"error delta {float(error_delta):+.2f}%")
            print(
                f"  {row['route']}: p95 +{float(row['latency_breach_ms']):.1f} ms, "
                f"error +{float(row['error_breach_pct']):.2f}%"
                + (f" | {'; '.join(delta_parts)}" if delta_parts else "")
            )

    if family_summary:
        print("\nRoute families:")
        family_header = (
            f"{'Family':<24} {'Routes':>6} {'N':>6} {'Max P95':>8} {'Breach':>8} {'Verdict':>10}"
        )
        print(family_header)
        print("-" * len(family_header))
        for row in family_summary[:5]:
            breach_label = (
                f"+{float(row['max_latency_breach_ms']):.1f}ms/"
                f"+{float(row['max_error_breach_pct']):.2f}%"
            )
            print(
                f"{str(row['family']):<24} "
                f"{int(row['routes']):>6} "
                f"{int(row['samples']):>6} "
                f"{float(row['max_p95_ms']):>8.1f} "
                f"{breach_label:>8} "
                f"{str(row['verdict']):>10}"
            )


def write_csv(summary: list[dict[str, float | int | str]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "route",
        "samples",
        "avg_ms",
        "p50_ms",
        "p95_ms",
        "p99_ms",
        "error_rate_pct",
        "latency_breach_ms",
        "error_breach_pct",
        "verdict",
    ]
    if summary and "baseline_samples" in summary[0]:
        fieldnames.extend(["baseline_samples", "p95_delta_ms", "error_rate_delta_pct"])
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=fieldnames,
        )
        writer.writeheader()
        writer.writerows(summary)


def write_json(summary: list[dict[str, float | int | str]], path: Path, args: argparse.Namespace) -> None:
    breached = [row for row in summary if str(row["verdict"]) != "healthy"]
    family_summary = summarize_families(summary, args.family_depth)
    payload = {
        "latency_budget_ms": args.latency_budget,
        "error_budget_pct": args.error_budget,
        "min_samples": args.min_samples,
        "route_prefix": args.route_prefix,
        "family_depth": args.family_depth,
        "breaches_only": args.breaches_only,
        "routes_reported": len(summary),
        "routes_in_breach": len(breached),
        "families": family_summary,
        "rows": summary,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def main() -> None:
    args = parse_args()
    rows = read_rows(args.input)
    summary = summarize_routes(
        rows,
        latency_budget=args.latency_budget,
        error_budget=args.error_budget,
        min_samples=args.min_samples,
        route_prefix=args.route_prefix,
        breaches_only=args.breaches_only,
    )
    if args.baseline:
        baseline_rows = read_rows(args.baseline)
        attach_baseline_deltas(
            summary,
            baseline_rows=baseline_rows,
            min_samples=args.min_samples,
            route_prefix=args.route_prefix,
        )
    family_summary = summarize_families(summary, args.family_depth)
    print_summary(summary, family_summary, args)

    if args.output:
        write_csv(summary, args.output)
        print()
        print(f"Wrote route summary: {args.output}")

    if args.json_out:
        write_json(summary, args.json_out, args)
        print(f"Wrote JSON summary: {args.json_out}")


if __name__ == "__main__":
    main()
