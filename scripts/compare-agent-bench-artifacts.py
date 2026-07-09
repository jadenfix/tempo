#!/usr/bin/env python3
"""Compare two live agent/browser benchmark artifact directories.

It reads PR artifact outputs from the existing benchmark, reports per-runner
p95 deltas, and labels each delta as noise, regression, or improvement using
configurable thresholds. By default it reports only; pass
`--fail-on-regression` to use the same comparison as a CI/PR gate.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any


GAP_ARTIFACT = "agent-browser-bench-gaps.json"
DEFAULT_METRICS = (
    "wall_clock_ms_p95",
    "steady_state_wall_clock_ms_p95",
    "runner_internal_wall_clock_ms_p95",
    "cpu_time_ms_p95",
    "max_rss_bytes_p95",
    "browser_rss_bytes_p95",
    "browser_peak_rss_bytes_p95",
    "max_pss_bytes_p95",
    "browser_peak_pss_bytes_p95",
    "max_uss_bytes_p95",
    "browser_peak_uss_bytes_p95",
    "max_process_count_p95",
    "process_tree_cpu_time_ms_p95",
    "browser_process_tree_cpu_time_ms_p95",
    "browser_task_duration_ms_p95",
    "web_first_contentful_paint_ms_p95",
    "web_response_end_ms_p95",
    "model_input_tokens_p95",
    "total_model_input_tokens_p95",
    "compact_observation_tokens_p95",
    "max_observation_tokens_p95",
)
HIGHER_IS_BETTER = {"success_rate"}


class CompareError(RuntimeError):
    pass


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError as error:
        raise CompareError(f"missing JSON artifact: {path}") from error
    except json.JSONDecodeError as error:
        raise CompareError(f"invalid JSON artifact {path}: {error}") from error


def artifact_dir(path: Path) -> Path:
    if (path / GAP_ARTIFACT).exists():
        return path
    matches = sorted(
        candidate.parent for candidate in path.rglob(GAP_ARTIFACT) if candidate.is_file()
    )
    if not matches:
        raise CompareError(f"{path} does not contain {GAP_ARTIFACT}")
    if len(matches) > 1:
        formatted = "\n  ".join(str(match) for match in matches)
        raise CompareError(
            f"{path} contains multiple benchmark artifact dirs; pass one directly:\n  {formatted}"
        )
    return matches[0]


def load_rows(path: Path) -> dict[str, dict[str, Any]]:
    artifact = artifact_dir(path)
    gap_report = load_json(artifact / GAP_ARTIFACT)
    rows = gap_report.get("rows")
    if not isinstance(rows, list):
        raise CompareError(f"{artifact / GAP_ARTIFACT} rows must be an array")
    row_by_runner: dict[str, dict[str, Any]] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise CompareError(f"{artifact / GAP_ARTIFACT} rows must contain objects")
        runner = row.get("runner")
        if not isinstance(runner, str) or not runner:
            raise CompareError(f"{artifact / GAP_ARTIFACT} row missing runner")
        if runner in row_by_runner:
            raise CompareError(f"{artifact / GAP_ARTIFACT} duplicate runner {runner}")
        row_by_runner[runner] = row
    return row_by_runner


def load_iterations(path: Path) -> int | None:
    artifact = artifact_dir(path)
    report = load_json(artifact / "agent-browser-bench.json")
    iterations = report.get("iterations", report.get("iteration"))
    return int(iterations) if isinstance(iterations, int) and not isinstance(iterations, bool) else None


def number(row: dict[str, Any], metric: str) -> float | None:
    value = row.get(metric)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def threshold_for(baseline: float, relative_threshold: float, absolute_threshold: float) -> float:
    return max(absolute_threshold, abs(baseline) * relative_threshold)


def classify(
    metric: str,
    baseline: float,
    candidate: float,
    relative_threshold: float,
    absolute_threshold: float,
) -> str:
    delta = candidate - baseline
    threshold = threshold_for(baseline, relative_threshold, absolute_threshold)
    if abs(delta) <= threshold:
        return "noise"
    regression = delta < 0 if metric in HIGHER_IS_BETTER else delta > 0
    return "regression" if regression else "improvement"


def compare_rows(
    baseline_rows: dict[str, dict[str, Any]],
    candidate_rows: dict[str, dict[str, Any]],
    metrics: list[str],
    relative_threshold: float,
    absolute_threshold: float,
) -> list[dict[str, Any]]:
    rows = []
    for runner in sorted(set(baseline_rows) & set(candidate_rows)):
        baseline_row = baseline_rows[runner]
        candidate_row = candidate_rows[runner]
        for metric in metrics:
            baseline = number(baseline_row, metric)
            candidate = number(candidate_row, metric)
            if baseline is None or candidate is None:
                continue
            delta = candidate - baseline
            pct_delta = (delta / baseline * 100.0) if baseline else None
            rows.append(
                {
                    "runner": runner,
                    "metric": metric,
                    "baseline": baseline,
                    "candidate": candidate,
                    "delta": delta,
                    "pct_delta": pct_delta,
                    "threshold": threshold_for(
                        baseline,
                        relative_threshold,
                        absolute_threshold,
                    ),
                    "classification": classify(
                        metric,
                        baseline,
                        candidate,
                        relative_threshold,
                        absolute_threshold,
                    ),
                }
            )
    return rows


def format_number(value: float | None) -> str:
    if value is None:
        return "-"
    if value.is_integer():
        return str(int(value))
    return f"{value:.3f}"


def format_pct(value: float | None) -> str:
    if value is None:
        return "-"
    return f"{value:+.1f}%"


def render_markdown(
    rows: list[dict[str, Any]],
    baseline_path: Path,
    candidate_path: Path,
    baseline_iterations: int | None,
    candidate_iterations: int | None,
    relative_threshold: float,
    absolute_threshold: float,
) -> str:
    counts: dict[str, int] = {}
    for row in rows:
        classification = str(row["classification"])
        counts[classification] = counts.get(classification, 0) + 1

    lines = [
        "# Agent Browser Benchmark Artifact Comparison",
        "",
        f"- Baseline: `{baseline_path}`",
        f"- Candidate: `{candidate_path}`",
        f"- Baseline iterations: `{baseline_iterations if baseline_iterations is not None else 'unknown'}`",
        f"- Candidate iterations: `{candidate_iterations if candidate_iterations is not None else 'unknown'}`",
        f"- Noise threshold: `max({absolute_threshold:g}, baseline * {relative_threshold:g})`",
        f"- Classifications: `{counts.get('regression', 0)}` regressions, `{counts.get('improvement', 0)}` improvements, `{counts.get('noise', 0)}` noise",
        "",
        "| Runner | Metric | Baseline | Candidate | Delta | Delta % | Threshold | Class |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |",
    ]
    sort_order = {"regression": 0, "improvement": 1, "noise": 2}
    for row in sorted(
        rows,
        key=lambda item: (
            sort_order.get(str(item["classification"]), 99),
            str(item["runner"]),
            str(item["metric"]),
        ),
    ):
        lines.append(
            "| {runner} | `{metric}` | {baseline} | {candidate} | {delta} | {pct} | {threshold} | {classification} |".format(
                runner=row["runner"],
                metric=row["metric"],
                baseline=format_number(row["baseline"]),
                candidate=format_number(row["candidate"]),
                delta=format_number(row["delta"]),
                pct=format_pct(row["pct_delta"]),
                threshold=format_number(row["threshold"]),
                classification=row["classification"],
            )
        )
    return "\n".join(lines) + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Compare two agent/browser benchmark artifact directories and classify "
            "per-runner p95 deltas."
        )
    )
    parser.add_argument("--baseline-dir", required=True, type=Path)
    parser.add_argument("--candidate-dir", required=True, type=Path)
    parser.add_argument(
        "--metric",
        action="append",
        dest="metrics",
        help="Metric field to compare. May be repeated. Defaults to common p95 fields.",
    )
    parser.add_argument(
        "--relative-noise-threshold",
        type=float,
        default=0.05,
        help="Relative delta treated as noise. Default: 0.05.",
    )
    parser.add_argument(
        "--absolute-noise-threshold",
        type=float,
        default=0.0,
        help="Absolute delta treated as noise. Default: 0.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON instead of Markdown.",
    )
    parser.add_argument(
        "--fail-on-regression",
        action="store_true",
        help="Exit non-zero when any comparable metric is classified as a regression.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        baseline_dir = artifact_dir(args.baseline_dir)
        candidate_dir = artifact_dir(args.candidate_dir)
        metrics = args.metrics or list(DEFAULT_METRICS)
        rows = compare_rows(
            load_rows(baseline_dir),
            load_rows(candidate_dir),
            metrics,
            args.relative_noise_threshold,
            args.absolute_noise_threshold,
        )
        if not rows:
            raise CompareError("no comparable numeric metric rows found")
        payload = {
            "baseline_dir": str(baseline_dir),
            "candidate_dir": str(candidate_dir),
            "baseline_iterations": load_iterations(baseline_dir),
            "candidate_iterations": load_iterations(candidate_dir),
            "relative_noise_threshold": args.relative_noise_threshold,
            "absolute_noise_threshold": args.absolute_noise_threshold,
            "rows": rows,
        }
        if args.json:
            print(json.dumps(payload, indent=2, sort_keys=True))
        else:
            print(
                render_markdown(
                    rows,
                    baseline_dir,
                    candidate_dir,
                    payload["baseline_iterations"],
                    payload["candidate_iterations"],
                    args.relative_noise_threshold,
                    args.absolute_noise_threshold,
                ),
                end="",
            )
        if args.fail_on_regression and any(
            row["classification"] == "regression" for row in rows
        ):
            return 2
    except CompareError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
