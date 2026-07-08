#!/usr/bin/env python3
"""Validate live agent/browser benchmark artifacts.

The Linux agent gate uses this after running the live browser benchmark. It is
deliberately stricter than file-existence checks: the benchmark is only useful
if every expected runner produced successful metrics, resource counters,
model-facing input sizes, summary rows, and the audit artifacts needed to
replay or inspect the run.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


EXPECTED_RUNNERS = {
    "tempo-cdp-agent",
    "raw-chrome-cdp",
    "synthetic-playwright-ax",
    "synthetic-browser-use-dom",
    "real-playwright",
    "external-browser-use-dom-loop",
}

REQUIRED_METRIC_FIELDS = {
    "runner",
    "suite",
    "case_id",
    "success",
    "wall_clock_ms",
    "step_count",
    "retry_count",
    "failure_mode",
    "model_input_bytes",
    "model_input_tokens",
    "observations",
    "cpu_user_ms",
    "cpu_system_ms",
    "max_rss_bytes",
    "iteration",
}

INT_FIELDS = {
    "wall_clock_ms",
    "step_count",
    "retry_count",
    "model_input_bytes",
    "model_input_tokens",
    "observations",
    "cpu_user_ms",
    "cpu_system_ms",
    "max_rss_bytes",
    "iteration",
}

SUMMARY_INT_FIELDS = {
    "wall_clock_ms",
    "cpu_user_ms",
    "cpu_system_ms",
    "max_rss_bytes",
    "model_input_bytes",
    "model_input_tokens",
    "step_count",
}

SUMMARY_STAT_FIELDS = {"min", "p50", "p95", "max"}

ROOT_ARTIFACTS = {
    "agent-browser-bench.json",
    "agent-browser-bench.jsonl",
    "agent-browser-bench-summary.json",
    "chrome-version.txt",
}

DERIVED_ARTIFACTS = {
    "tempo-journal.sqlite",
    "tempo-run.json",
    "tempo-eval-record.json",
    "eval-records.jsonl",
    "replay.json",
    "scorecard.json",
    "amdahl.json",
    "real-playwright.json",
    "real-playwright.model-input.txt",
    "real-playwright.trace.json",
    "external-browser-use-dom-loop.json",
    "external-browser-use-dom-loop.model-input.txt",
    "external-browser-use-dom-loop.trace.json",
}


class ValidationError(RuntimeError):
    pass


def load_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError as error:
        raise ValidationError(f"missing JSON artifact: {path}") from error
    except json.JSONDecodeError as error:
        raise ValidationError(f"invalid JSON artifact {path}: {error}") from error


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text().splitlines()
    except FileNotFoundError as error:
        raise ValidationError(f"missing JSONL artifact: {path}") from error
    rows = []
    for index, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValidationError(f"invalid JSONL artifact {path}:{index}: {error}") from error
        if not isinstance(value, dict):
            raise ValidationError(f"{path}:{index} must be a JSON object")
        rows.append(value)
    return rows


def require_file(path: Path) -> None:
    if not path.exists():
        raise ValidationError(f"missing artifact: {path}")
    if path.stat().st_size <= 0:
        raise ValidationError(f"empty artifact: {path}")


def require_int(metric: dict[str, Any], field: str, *, positive: bool = False) -> None:
    value = metric.get(field)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError(f"{metric.get('runner', '<unknown>')}.{field} must be an integer")
    if value < 0:
        raise ValidationError(f"{metric.get('runner', '<unknown>')}.{field} must be >= 0")
    if positive and value <= 0:
        raise ValidationError(f"{metric.get('runner', '<unknown>')}.{field} must be > 0")


def validate_metric(metric: dict[str, Any], iterations: int) -> None:
    missing = REQUIRED_METRIC_FIELDS - set(metric)
    if missing:
        raise ValidationError(f"{metric.get('runner', '<unknown>')} metric missing fields: {sorted(missing)}")
    runner = metric["runner"]
    if runner not in EXPECTED_RUNNERS:
        raise ValidationError(f"unexpected runner: {runner}")
    if metric["suite"] != "live-agent-browser-bench":
        raise ValidationError(f"{runner}.suite must be live-agent-browser-bench")
    if metric["case_id"] != "checkout-submit":
        raise ValidationError(f"{runner}.case_id must be checkout-submit")
    if metric["success"] is not True:
        raise ValidationError(f"{runner} did not report success: {metric}")
    if metric["failure_mode"] not in (None, ""):
        raise ValidationError(f"{runner}.failure_mode must be empty on success")

    for field in INT_FIELDS:
        require_int(metric, field, positive=(field in {"wall_clock_ms", "step_count"}))
    if not 1 <= int(metric["iteration"]) <= iterations:
        raise ValidationError(f"{runner}.iteration is outside expected range: {metric['iteration']}")

    if runner != "raw-chrome-cdp":
        require_int(metric, "model_input_bytes", positive=True)
        require_int(metric, "model_input_tokens", positive=True)
        require_int(metric, "observations", positive=True)

    if runner in {"real-playwright", "external-browser-use-dom-loop"}:
        if metric.get("external_process") is not True:
            raise ValidationError(f"{runner}.external_process must be true")
        for field in ("runner_report", "runner_stdout", "runner_stderr"):
            if not metric.get(field):
                raise ValidationError(f"{runner}.{field} must be populated")


def percentile(values: list[int], pct: float) -> int:
    if not values:
        return 0
    values = sorted(values)
    if len(values) == 1:
        return values[0]
    index = round((len(values) - 1) * pct)
    return values[max(0, min(index, len(values) - 1))]


def summarize_int_field(metrics: list[dict[str, Any]], field: str) -> dict[str, int]:
    values = [int(metric.get(field, 0)) for metric in metrics]
    return {
        "min": min(values) if values else 0,
        "p50": percentile(values, 0.50),
        "p95": percentile(values, 0.95),
        "max": max(values) if values else 0,
    }


def expected_summary(metrics: list[dict[str, Any]]) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    for runner in sorted(EXPECTED_RUNNERS):
        runner_metrics = [metric for metric in metrics if metric["runner"] == runner]
        successes = [metric for metric in runner_metrics if metric["success"]]
        failure_modes: dict[str, int] = {}
        for metric in runner_metrics:
            mode = metric.get("failure_mode")
            if mode:
                failure_modes[str(mode)] = failure_modes.get(str(mode), 0) + 1
        runner_summary: dict[str, Any] = {
            "runs": len(runner_metrics),
            "successes": len(successes),
            "success_rate": len(successes) / len(runner_metrics) if runner_metrics else 0.0,
            "failure_modes": failure_modes,
            "wall_clock_ms": summarize_int_field(runner_metrics, "wall_clock_ms"),
            "cpu_user_ms": summarize_int_field(runner_metrics, "cpu_user_ms"),
            "cpu_system_ms": summarize_int_field(runner_metrics, "cpu_system_ms"),
            "max_rss_bytes": summarize_int_field(runner_metrics, "max_rss_bytes"),
            "model_input_bytes": summarize_int_field(runner_metrics, "model_input_bytes"),
            "model_input_tokens": summarize_int_field(runner_metrics, "model_input_tokens"),
            "step_count": summarize_int_field(runner_metrics, "step_count"),
            "retry_count_total": sum(
                int(metric.get("retry_count", 0)) for metric in runner_metrics
            ),
        }
        for field in (
            "total_model_input_bytes",
            "total_model_input_tokens",
            "max_observation_bytes",
            "max_observation_tokens",
        ):
            if any(field in metric for metric in runner_metrics):
                runner_summary[field] = summarize_int_field(runner_metrics, field)
        summary[runner] = runner_summary
    return summary


def validate_summary(summary: dict[str, Any], iterations: int) -> None:
    runners = set(summary)
    if runners != EXPECTED_RUNNERS:
        raise ValidationError(f"summary runners mismatch: expected {sorted(EXPECTED_RUNNERS)}, got {sorted(runners)}")

    for runner, runner_summary in summary.items():
        if not isinstance(runner_summary, dict):
            raise ValidationError(f"{runner} summary must be an object")
        if runner_summary.get("runs") != iterations:
            raise ValidationError(f"{runner}.runs must be {iterations}")
        if runner_summary.get("successes") != iterations:
            raise ValidationError(f"{runner}.successes must be {iterations}")
        if runner_summary.get("success_rate") != 1.0:
            raise ValidationError(f"{runner}.success_rate must be 1.0")
        if runner_summary.get("failure_modes") != {}:
            raise ValidationError(f"{runner}.failure_modes must be empty")
        if not isinstance(runner_summary.get("retry_count_total"), int):
            raise ValidationError(f"{runner}.retry_count_total must be an integer")

        for field in SUMMARY_INT_FIELDS:
            stats = runner_summary.get(field)
            if not isinstance(stats, dict):
                raise ValidationError(f"{runner}.{field} summary must be an object")
            missing = SUMMARY_STAT_FIELDS - set(stats)
            if missing:
                raise ValidationError(f"{runner}.{field} missing stats: {sorted(missing)}")
            for stat in SUMMARY_STAT_FIELDS:
                value = stats[stat]
                if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                    raise ValidationError(f"{runner}.{field}.{stat} must be a non-negative integer")


def validate_bench_json(output_dir: Path) -> tuple[int, list[dict[str, Any]]]:
    report = load_json(output_dir / "agent-browser-bench.json")
    if not isinstance(report, dict):
        raise ValidationError("agent-browser-bench.json must be an object")
    iterations = report.get("iterations")
    if not isinstance(iterations, int) or isinstance(iterations, bool) or iterations < 1:
        raise ValidationError("agent-browser-bench.json iterations must be a positive integer")
    if not report.get("chrome"):
        raise ValidationError("agent-browser-bench.json chrome must be populated")
    if not report.get("chrome_version"):
        raise ValidationError("agent-browser-bench.json chrome_version must be populated")

    metrics = report.get("metrics")
    if not isinstance(metrics, list):
        raise ValidationError("agent-browser-bench.json metrics must be an array")
    expected_metric_count = iterations * len(EXPECTED_RUNNERS)
    if len(metrics) != expected_metric_count:
        raise ValidationError(f"expected {expected_metric_count} metrics, got {len(metrics)}")
    for metric in metrics:
        if not isinstance(metric, dict):
            raise ValidationError("each metric must be an object")
        validate_metric(metric, iterations)

    seen_pairs: set[tuple[str, int]] = set()
    for metric in metrics:
        pair = (str(metric["runner"]), int(metric["iteration"]))
        if pair in seen_pairs:
            raise ValidationError(f"duplicate runner/iteration metric: {pair}")
        seen_pairs.add(pair)
    expected_pairs = {
        (runner, iteration)
        for runner in EXPECTED_RUNNERS
        for iteration in range(1, iterations + 1)
    }
    if seen_pairs != expected_pairs:
        missing = sorted(expected_pairs - seen_pairs)
        extra = sorted(seen_pairs - expected_pairs)
        raise ValidationError(f"runner/iteration coverage mismatch: missing={missing}, extra={extra}")

    summary = report.get("summary")
    if not isinstance(summary, dict):
        raise ValidationError("agent-browser-bench.json summary must be an object")
    validate_summary(summary, iterations)
    expected = expected_summary(metrics)
    if summary != expected:
        raise ValidationError("agent-browser-bench.json summary does not match raw metrics")

    summary_file = load_json(output_dir / "agent-browser-bench-summary.json")
    if summary_file != summary:
        raise ValidationError("agent-browser-bench-summary.json does not match report summary")

    jsonl_metrics = load_jsonl(output_dir / "agent-browser-bench.jsonl")
    if jsonl_metrics != metrics:
        raise ValidationError("agent-browser-bench.jsonl does not match report metrics")

    chrome_version = load_json(output_dir / "chrome-version.txt")
    if chrome_version.get("chrome") != report["chrome"]:
        raise ValidationError("chrome-version.txt chrome does not match report")
    if chrome_version.get("version") != report["chrome_version"]:
        raise ValidationError("chrome-version.txt version does not match report")

    return iterations, metrics


def validate_iteration_dir(iteration_dir: Path, iteration: int) -> list[dict[str, Any]]:
    report = load_json(iteration_dir / "agent-browser-bench.json")
    if report.get("iteration") != iteration:
        raise ValidationError(f"{iteration_dir} iteration field must be {iteration}")
    metrics = report.get("metrics")
    if not isinstance(metrics, list) or len(metrics) != len(EXPECTED_RUNNERS):
        raise ValidationError(f"{iteration_dir} must contain one metric per expected runner")
    for metric in metrics:
        if metric.get("iteration") != iteration:
            raise ValidationError(f"{iteration_dir} metric has wrong iteration: {metric}")
        validate_metric(metric, iteration)
    if load_jsonl(iteration_dir / "agent-browser-bench.jsonl") != metrics:
        raise ValidationError(f"{iteration_dir}/agent-browser-bench.jsonl does not match metrics")
    return metrics


def validate_artifacts(
    output_dir: Path,
    iterations: int,
    root_metrics: list[dict[str, Any]],
    require_derived_artifacts: bool,
) -> None:
    for name in ROOT_ARTIFACTS:
        require_file(output_dir / name)

    iteration_dirs = sorted(output_dir.glob("iteration-*"))
    if iteration_dirs:
        if len(iteration_dirs) != iterations:
            raise ValidationError(f"expected {iterations} iteration dirs, got {len(iteration_dirs)}")
        iteration_metrics = []
        for index, iteration_dir in enumerate(iteration_dirs, start=1):
            iteration_metrics.extend(validate_iteration_dir(iteration_dir, index))
            if require_derived_artifacts:
                for name in DERIVED_ARTIFACTS:
                    require_file(iteration_dir / name)
        if iteration_metrics != root_metrics:
            raise ValidationError(
                "root agent-browser-bench.json metrics do not match iteration artifacts"
            )
        return

    if require_derived_artifacts:
        for name in DERIVED_ARTIFACTS:
            require_file(output_dir / name)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--expected-iterations", type=int, default=None)
    parser.add_argument("--require-derived-artifacts", action="store_true")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    iterations, metrics = validate_bench_json(output_dir)
    if args.expected_iterations is not None and iterations != args.expected_iterations:
        raise ValidationError(
            f"expected {args.expected_iterations} iterations, report contains {iterations}"
        )
    validate_artifacts(output_dir, iterations, metrics, args.require_derived_artifacts)
    print(f"validated agent browser benchmark artifacts: {output_dir}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValidationError as error:
        raise SystemExit(f"agent browser benchmark artifact validation failed: {error}") from None
