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
import sqlite3
from pathlib import Path
from typing import Any

from agent_bench_status import STATUS_ARTIFACT, render_status_markdown


EXPECTED_RUNNERS = {
    "tempo-cdp-agent",
    "raw-chrome-cdp",
    "synthetic-playwright-ax",
    "synthetic-browser-use-dom",
    "real-playwright",
    "external-browser-use-dom-loop",
    "real-browser-use",
}
TEMPO_RUNNER = "tempo-cdp-agent"
RAW_CHROME_RUNNER = "raw-chrome-cdp"
AGENT_STYLE_RUNNERS = {
    "tempo-cdp-agent",
    "synthetic-playwright-ax",
    "synthetic-browser-use-dom",
    "real-playwright",
    "external-browser-use-dom-loop",
    "real-browser-use",
}

BROWSER_PERFORMANCE_ROW_FIELDS = {
    "Documents": "browser_documents_p95",
    "Frames": "browser_frames_p95",
    "JSEventListeners": "browser_js_event_listeners_p95",
    "Nodes": "browser_nodes_p95",
    "LayoutCount": "browser_layout_count_p95",
    "RecalcStyleCount": "browser_recalc_style_count_p95",
    "LayoutDuration": "browser_layout_duration_ms_p95",
    "RecalcStyleDuration": "browser_recalc_style_duration_ms_p95",
    "ScriptDuration": "browser_script_duration_ms_p95",
    "TaskDuration": "browser_task_duration_ms_p95",
    "JSHeapUsedSize": "browser_js_heap_used_bytes_p95",
    "JSHeapTotalSize": "browser_js_heap_total_bytes_p95",
}

WEB_PERFORMANCE_ROW_FIELDS = {
    "navigation_duration_ms": "web_navigation_duration_ms_p95",
    "dom_content_loaded_ms": "web_dom_content_loaded_ms_p95",
    "load_event_ms": "web_load_event_ms_p95",
    "response_end_ms": "web_response_end_ms_p95",
    "resource_count": "web_resource_count_p95",
    "resource_transfer_size_bytes": "web_resource_transfer_size_bytes_p95",
    "resource_decoded_body_size_bytes": "web_resource_decoded_body_size_bytes_p95",
    "first_paint_ms": "web_first_paint_ms_p95",
    "first_contentful_paint_ms": "web_first_contentful_paint_ms_p95",
    "long_task_count": "web_long_task_count_p95",
    "long_task_duration_ms": "web_long_task_duration_ms_p95",
}

REQUIRED_METRIC_FIELDS = {
    "runner",
    "suite",
    "case_id",
    "success",
    "final_oracle",
    "wall_clock_ms",
    "step_count",
    "retry_count",
    "failure_mode",
    "model_input_bytes",
    "model_input_tokens",
    "observations",
    "model_input_observations",
    "cpu_user_ms",
    "cpu_system_ms",
    "max_rss_bytes",
    "rss_at_peak_by_command_bytes",
    "peak_rss_by_command_bytes",
    "rss_at_peak_by_process_type_bytes",
    "peak_rss_by_process_type_bytes",
    "rss_peak_elapsed_ms",
    "process_count_at_peak",
    "process_count_at_peak_by_type",
    "processes_at_peak",
    "iteration",
}

INT_FIELDS = {
    "wall_clock_ms",
    "step_count",
    "retry_count",
    "model_input_bytes",
    "model_input_tokens",
    "observations",
    "model_input_observations",
    "cpu_user_ms",
    "cpu_system_ms",
    "max_rss_bytes",
    "rss_peak_elapsed_ms",
    "process_count_at_peak",
    "iteration",
}

SUMMARY_INT_FIELDS = {
    "wall_clock_ms",
    "cpu_user_ms",
    "cpu_system_ms",
    "max_rss_bytes",
    "model_input_bytes",
    "model_input_tokens",
    "observations",
    "model_input_observations",
    "step_count",
}

SUMMARY_STAT_FIELDS = {"min", "p50", "p95", "max"}

ROOT_ARTIFACTS = {
    "agent-browser-bench.json",
    "agent-browser-bench.jsonl",
    "agent-browser-bench-gaps.json",
    "agent-browser-bench-summary.json",
    STATUS_ARTIFACT,
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
    "real-browser-use.json",
    "real-browser-use.model-input.txt",
    "real-browser-use.trace.json",
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


def require_int_map(metric: dict[str, Any], field: str, *, positive: bool = False) -> None:
    value = metric.get(field)
    runner = metric.get("runner", "<unknown>")
    if not isinstance(value, dict):
        raise ValidationError(f"{runner}.{field} must be an object")
    if positive and not value:
        raise ValidationError(f"{runner}.{field} must not be empty")
    for key, item in value.items():
        if not isinstance(key, str) or not key:
            raise ValidationError(f"{runner}.{field} keys must be non-empty strings")
        if not isinstance(item, int) or isinstance(item, bool):
            raise ValidationError(f"{runner}.{field}.{key} must be an integer")
        if item < 0:
            raise ValidationError(f"{runner}.{field}.{key} must be >= 0")
        if positive and item <= 0:
            raise ValidationError(f"{runner}.{field}.{key} must be > 0")


def validate_processes_at_peak(metric: dict[str, Any]) -> None:
    runner = metric.get("runner", "<unknown>")
    processes = metric.get("processes_at_peak")
    if not isinstance(processes, list):
        raise ValidationError(f"{runner}.processes_at_peak must be an array")
    if len(processes) != int(metric["process_count_at_peak"]):
        raise ValidationError(
            f"{runner}.processes_at_peak length must equal process_count_at_peak"
        )

    rss_total = 0
    by_command: dict[str, int] = {}
    by_process_type: dict[str, int] = {}
    count_by_process_type: dict[str, int] = {}
    for index, process in enumerate(processes):
        if not isinstance(process, dict):
            raise ValidationError(f"{runner}.processes_at_peak[{index}] must be an object")
        pid = process.get("pid")
        ppid = process.get("ppid")
        command = process.get("command")
        process_type = process.get("process_type")
        rss_bytes = process.get("rss_bytes")
        args = process.get("args")
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
            raise ValidationError(f"{runner}.processes_at_peak[{index}].pid must be > 0")
        if not isinstance(ppid, int) or isinstance(ppid, bool) or ppid < 0:
            raise ValidationError(f"{runner}.processes_at_peak[{index}].ppid must be >= 0")
        if not isinstance(command, str) or not command:
            raise ValidationError(
                f"{runner}.processes_at_peak[{index}].command must be a non-empty string"
            )
        if not isinstance(process_type, str) or not process_type:
            raise ValidationError(
                f"{runner}.processes_at_peak[{index}].process_type must be a non-empty string"
            )
        if not isinstance(rss_bytes, int) or isinstance(rss_bytes, bool) or rss_bytes <= 0:
            raise ValidationError(
                f"{runner}.processes_at_peak[{index}].rss_bytes must be > 0"
            )
        if not isinstance(args, str):
            raise ValidationError(f"{runner}.processes_at_peak[{index}].args must be a string")

        rss_total += rss_bytes
        by_command[command] = by_command.get(command, 0) + rss_bytes
        by_process_type[process_type] = by_process_type.get(process_type, 0) + rss_bytes
        count_by_process_type[process_type] = count_by_process_type.get(process_type, 0) + 1

    if rss_total != int(metric["max_rss_bytes"]):
        raise ValidationError(f"{runner}.processes_at_peak rss sum must equal max_rss_bytes")
    if dict(sorted(by_command.items())) != metric["rss_at_peak_by_command_bytes"]:
        raise ValidationError(
            f"{runner}.processes_at_peak command RSS must match rss_at_peak_by_command_bytes"
        )
    if dict(sorted(by_process_type.items())) != metric["rss_at_peak_by_process_type_bytes"]:
        raise ValidationError(
            f"{runner}.processes_at_peak type RSS must match rss_at_peak_by_process_type_bytes"
        )
    if dict(sorted(count_by_process_type.items())) != metric["process_count_at_peak_by_type"]:
        raise ValidationError(
            f"{runner}.processes_at_peak type counts must match process_count_at_peak_by_type"
        )


def artifact_path(output_dir: Path, stored_path: str) -> Path:
    path = Path(stored_path)
    if path.exists():
        return path
    parts = path.parts
    for index, part in enumerate(parts):
        if part.startswith("iteration-"):
            candidate = output_dir.joinpath(*parts[index:])
            if candidate.exists():
                return candidate
    candidate = output_dir / path.name
    if candidate.exists():
        return candidate
    return path


def validate_metric(metric: dict[str, Any], iterations: int, output_dir: Path) -> None:
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
    validate_final_oracle(runner, metric.get("final_oracle"))
    if metric["failure_mode"] not in (None, ""):
        raise ValidationError(f"{runner}.failure_mode must be empty on success")

    for field in INT_FIELDS:
        require_int(metric, field, positive=(field in {"wall_clock_ms", "step_count"}))
    require_int_map(metric, "rss_at_peak_by_command_bytes", positive=True)
    require_int_map(metric, "peak_rss_by_command_bytes", positive=True)
    require_int_map(metric, "rss_at_peak_by_process_type_bytes", positive=True)
    require_int_map(metric, "peak_rss_by_process_type_bytes", positive=True)
    require_int_map(metric, "process_count_at_peak_by_type", positive=True)
    rss_at_peak_total = sum(int(value) for value in metric["rss_at_peak_by_command_bytes"].values())
    if rss_at_peak_total != int(metric["max_rss_bytes"]):
        raise ValidationError(
            f"{runner}.rss_at_peak_by_command_bytes sum must equal max_rss_bytes"
        )
    process_type_rss_at_peak_total = sum(
        int(value) for value in metric["rss_at_peak_by_process_type_bytes"].values()
    )
    if process_type_rss_at_peak_total != int(metric["max_rss_bytes"]):
        raise ValidationError(
            f"{runner}.rss_at_peak_by_process_type_bytes sum must equal max_rss_bytes"
        )
    process_count_at_peak_total = sum(
        int(value) for value in metric["process_count_at_peak_by_type"].values()
    )
    if process_count_at_peak_total != int(metric["process_count_at_peak"]):
        raise ValidationError(
            f"{runner}.process_count_at_peak_by_type sum must equal process_count_at_peak"
        )
    validate_processes_at_peak(metric)
    if not 1 <= int(metric["iteration"]) <= iterations:
        raise ValidationError(f"{runner}.iteration is outside expected range: {metric['iteration']}")

    if runner != "raw-chrome-cdp":
        require_int(metric, "model_input_bytes", positive=True)
        require_int(metric, "model_input_tokens", positive=True)
        require_int(metric, "observations", positive=True)
        require_int(metric, "model_input_observations", positive=True)
        if int(metric["model_input_observations"]) > int(metric["observations"]):
            raise ValidationError(
                f"{runner}.model_input_observations must be <= observations"
            )

    if runner == "tempo-cdp-agent":
        if metric.get("tempo_engine") != "cdp":
            raise ValidationError(
                f"tempo-cdp-agent.tempo_engine must be cdp, got {metric.get('tempo_engine')!r}"
            )
        require_int(metric, "max_compact_observation_bytes", positive=True)
        require_int(metric, "max_compact_observation_tokens", positive=True)
        if int(metric["max_compact_observation_bytes"]) > int(metric["max_observation_bytes"]):
            raise ValidationError(
                "tempo-cdp-agent.max_compact_observation_bytes must be <= max_observation_bytes"
            )
        validate_tempo_phase_timings(metric)
    validate_browser_performance_metrics(metric)
    validate_web_performance_metrics(metric)

    if runner in {"real-playwright", "external-browser-use-dom-loop", "real-browser-use"}:
        if metric.get("external_process") is not True:
            raise ValidationError(f"{runner}.external_process must be true")
        for field in ("runner_report", "runner_stdout", "runner_stderr"):
            if not metric.get(field):
                raise ValidationError(f"{runner}.{field} must be populated")
            artifact = artifact_path(output_dir, str(metric[field]))
            if not artifact.exists():
                raise ValidationError(f"{runner}.{field} does not exist: {artifact}")
        runner_report = artifact_path(output_dir, str(metric["runner_report"]))
        raw_report = json.loads(runner_report.read_text())
        if raw_report.get("success") is not True:
            raise ValidationError(f"{runner}.runner_report success must be true")
        if raw_report.get("final_oracle") != metric.get("final_oracle"):
            raise ValidationError(f"{runner}.runner_report final_oracle must match metric")
        require_int(raw_report, "observations", positive=True)
        require_int(raw_report, "model_input_observations", positive=True)
        if int(raw_report["model_input_observations"]) > int(raw_report["observations"]):
            raise ValidationError(
                f"{runner}.runner_report model_input_observations must be <= observations"
            )
        for field in (
            "model_input_bytes",
            "model_input_tokens",
            "total_model_input_bytes",
            "total_model_input_tokens",
            "max_observation_bytes",
            "max_observation_tokens",
            *BROWSER_PERFORMANCE_ROW_FIELDS.values(),
            *WEB_PERFORMANCE_ROW_FIELDS.values(),
        ):
            if field in raw_report and field in metric and int(raw_report[field]) != int(metric[field]):
                raise ValidationError(f"{runner}.{field} must match runner_report")


def validate_final_oracle(runner: str, oracle: Any) -> None:
    if not isinstance(oracle, dict):
        raise ValidationError(f"{runner}.final_oracle must be an object")
    if oracle.get("submitted") is not True:
        raise ValidationError(f"{runner}.final_oracle.submitted must be true: {oracle}")
    if oracle.get("email_matches") is not True:
        raise ValidationError(f"{runner}.final_oracle.email_matches must be true: {oracle}")
    if oracle.get("status_done") is not True:
        raise ValidationError(f"{runner}.final_oracle.status_done must be true: {oracle}")
    if oracle.get("status_text") != "Order submitted":
        raise ValidationError(f"{runner}.final_oracle.status_text must be Order submitted: {oracle}")
    if oracle.get("remember_checked") is not True and oracle.get("remember_checked_inferred") is not True:
        raise ValidationError(f"{runner}.final_oracle remember state must be true or inferred: {oracle}")


def validate_browser_performance_metrics(metric: dict[str, Any]) -> None:
    runner = str(metric["runner"])
    if metric.get("browser_performance_metrics_available") is not True:
        raise ValidationError(f"{runner}.browser_performance_metrics_available must be true")
    metrics = metric.get("browser_performance_metrics")
    if not isinstance(metrics, dict) or not metrics:
        raise ValidationError(f"{runner}.browser_performance_metrics must be populated")
    for name in ("Nodes", "TaskDuration", "JSHeapUsedSize"):
        value = metrics.get(name)
        if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
            raise ValidationError(f"{runner}.browser_performance_metrics.{name} must be >= 0")
    for field in BROWSER_PERFORMANCE_ROW_FIELDS.values():
        require_int(metric, field)


def validate_web_performance_metrics(metric: dict[str, Any]) -> None:
    runner = str(metric["runner"])
    if metric.get("web_performance_metrics_available") is not True:
        raise ValidationError(f"{runner}.web_performance_metrics_available must be true")
    metrics = metric.get("web_performance_metrics")
    if not isinstance(metrics, dict) or not metrics:
        raise ValidationError(f"{runner}.web_performance_metrics must be populated")
    for name in WEB_PERFORMANCE_ROW_FIELDS:
        value = metrics.get(name)
        if not isinstance(value, (int, float)) or isinstance(value, bool) or value < 0:
            raise ValidationError(f"{runner}.web_performance_metrics.{name} must be >= 0")
    for field in WEB_PERFORMANCE_ROW_FIELDS.values():
        require_int(metric, field)


def validate_tempo_phase_timings(metric: dict[str, Any]) -> None:
    timings = metric.get("tempo_phase_timings_ms")
    if not isinstance(timings, dict):
        raise ValidationError("tempo-cdp-agent.tempo_phase_timings_ms must be an object")
    for field in (
        "total_wall_clock_ms",
        "runtime_setup_ms",
        "structured_probe_ms",
        "driver_launch_ms",
        "agent_run_ms",
        "driver_close_ms",
    ):
        value = timings.get(field)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValidationError(f"tempo-cdp-agent.tempo_phase_timings_ms.{field} must be >= 0")
        metric_field = f"tempo_{field}"
        if metric.get(metric_field) != value:
            raise ValidationError(
                f"tempo-cdp-agent.{metric_field} must match tempo_phase_timings_ms.{field}"
            )
    for field in ("total_wall_clock_ms", "driver_launch_ms", "agent_run_ms"):
        if int(timings[field]) <= 0:
            raise ValidationError(f"tempo-cdp-agent.tempo_phase_timings_ms.{field} must be > 0")
    child_total = int(timings["total_wall_clock_ms"])
    outer_wall = int(metric["wall_clock_ms"])
    if child_total > outer_wall + 250:
        raise ValidationError(
            "tempo-cdp-agent.tempo_phase_timings_ms.total_wall_clock_ms "
            "must fit within benchmark wall_clock_ms"
        )
    measured_phase_sum = sum(
        int(timings[field])
        for field in (
            "runtime_setup_ms",
            "structured_probe_ms",
            "driver_launch_ms",
            "agent_run_ms",
            "driver_close_ms",
        )
    )
    if measured_phase_sum > child_total + 10:
        raise ValidationError(
            "tempo-cdp-agent phase timings must not exceed total_wall_clock_ms"
        )


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
            "observations": summarize_int_field(runner_metrics, "observations"),
            "model_input_observations": summarize_int_field(
                runner_metrics, "model_input_observations"
            ),
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
            "max_compact_observation_bytes",
            "max_compact_observation_tokens",
            "max_model_input_bytes",
            "max_model_input_tokens",
        ):
            if any(field in metric for metric in runner_metrics):
                runner_summary[field] = summarize_int_field(runner_metrics, field)
        summary[runner] = runner_summary
    return summary


def expected_gap_report(metrics: list[dict[str, Any]], summary: dict[str, Any]) -> dict[str, Any]:
    runners = sorted(summary)
    rows = [
        comparison_row(
            runner,
            summary[runner],
            [metric for metric in metrics if metric["runner"] == runner],
        )
        for runner in runners
    ]
    row_by_runner = {row["runner"]: row for row in rows}
    category_specs = [
        ("success_rate", "higher_is_better", runners),
        ("cold_start_wall_clock_ms", "lower_is_better", runners),
        ("wall_clock_ms_p95", "lower_is_better", runners),
        ("runner_internal_wall_clock_ms_p95", "lower_is_better", runners),
        ("steady_state_wall_clock_ms_p95", "lower_is_better", runners),
        ("max_rss_bytes_p95", "lower_is_better", runners),
        ("browser_rss_bytes_p95", "lower_is_better", runners),
        ("process_count_at_peak_p95", "lower_is_better", runners),
        ("browser_documents_p95", "lower_is_better", runners),
        ("browser_frames_p95", "lower_is_better", runners),
        ("browser_js_event_listeners_p95", "lower_is_better", runners),
        ("browser_nodes_p95", "lower_is_better", runners),
        ("browser_layout_count_p95", "lower_is_better", runners),
        ("browser_recalc_style_count_p95", "lower_is_better", runners),
        ("browser_layout_duration_ms_p95", "lower_is_better", runners),
        ("browser_recalc_style_duration_ms_p95", "lower_is_better", runners),
        ("browser_script_duration_ms_p95", "lower_is_better", runners),
        ("browser_task_duration_ms_p95", "lower_is_better", runners),
        ("browser_js_heap_used_bytes_p95", "lower_is_better", runners),
        ("browser_js_heap_total_bytes_p95", "lower_is_better", runners),
        ("web_navigation_duration_ms_p95", "lower_is_better", runners),
        ("web_dom_content_loaded_ms_p95", "lower_is_better", runners),
        ("web_load_event_ms_p95", "lower_is_better", runners),
        ("web_response_end_ms_p95", "lower_is_better", runners),
        ("web_resource_count_p95", "lower_is_better", runners),
        ("web_resource_transfer_size_bytes_p95", "lower_is_better", runners),
        ("web_resource_decoded_body_size_bytes_p95", "lower_is_better", runners),
        ("web_first_paint_ms_p95", "lower_is_better", runners),
        ("web_first_contentful_paint_ms_p95", "lower_is_better", runners),
        ("web_long_task_count_p95", "lower_is_better", runners),
        ("web_long_task_duration_ms_p95", "lower_is_better", runners),
        ("retry_count_total", "lower_is_better", runners),
        ("failure_count", "lower_is_better", runners),
        (
            "model_input_tokens_p95",
            "lower_is_better",
            sorted(runner for runner in runners if runner in AGENT_STYLE_RUNNERS),
        ),
        (
            "total_model_input_tokens_p95",
            "lower_is_better",
            sorted(runner for runner in runners if runner in AGENT_STYLE_RUNNERS),
        ),
        (
            "model_input_observations_p95",
            "lower_is_better",
            sorted(runner for runner in runners if runner in AGENT_STYLE_RUNNERS),
        ),
        (
            "compact_observation_tokens_p95",
            "lower_is_better",
            sorted(runner for runner in runners if runner in AGENT_STYLE_RUNNERS),
        ),
        (
            "max_observation_tokens_p95",
            "lower_is_better",
            sorted(runner for runner in runners if runner in AGENT_STYLE_RUNNERS),
        ),
        (
            "step_count_p95",
            "lower_is_better",
            sorted(runner for runner in runners if runner in AGENT_STYLE_RUNNERS),
        ),
    ]
    categories = []
    gaps_to_close = []
    for name, direction, category_runners in category_specs:
        participants = [
            runner
            for runner in category_runners
            if runner in row_by_runner and row_by_runner[runner].get(name) is not None
        ]
        ranked = sorted(
            (
                {
                    "runner": runner,
                    "value": row_by_runner[runner][name],
                }
                for runner in participants
            ),
            key=lambda entry: category_sort_key(entry, direction),
        )
        if not ranked or TEMPO_RUNNER not in participants:
            continue
        tempo_value = row_by_runner[TEMPO_RUNNER][name]
        tempo_rank = comparison_rank(tempo_value, ranked, direction)
        best = {"runner": TEMPO_RUNNER, "value": tempo_value} if tempo_rank == 1 else ranked[0]
        best_value = ranked[0]["value"]
        best_runners = [
            str(entry["runner"])
            for entry in ranked
            if comparison_delta(entry["value"], best_value, direction) == 0
        ]
        best_non_tempo = next(
            (entry for entry in ranked if entry["runner"] != TEMPO_RUNNER),
            None,
        )
        raw_chrome = (
            {"runner": RAW_CHROME_RUNNER, "value": row_by_runner[RAW_CHROME_RUNNER][name]}
            if RAW_CHROME_RUNNER in participants
            else None
        )
        category = {
            "name": name,
            "direction": direction,
            "runners": participants,
            "tempo": {"runner": TEMPO_RUNNER, "value": tempo_value},
            "best": best,
            "best_runners": best_runners,
            "best_non_tempo": best_non_tempo,
            "raw_chrome": raw_chrome,
            "tempo_rank": tempo_rank,
            "tempo_is_best": tempo_rank == 1,
            "tempo_delta_vs_best": comparison_delta(tempo_value, best_value, direction),
            "tempo_delta_vs_best_non_tempo": (
                comparison_delta(tempo_value, best_non_tempo["value"], direction)
                if best_non_tempo
                else None
            ),
            "tempo_delta_vs_raw_chrome": (
                comparison_delta(tempo_value, raw_chrome["value"], direction)
                if raw_chrome
                else None
            ),
        }
        categories.append(category)
        if tempo_rank != 1:
            gaps_to_close.append(
                {
                    "category": name,
                    "direction": direction,
                    "target_runner": ranked[0]["runner"],
                    "target_runners": best_runners,
                    "tempo_value": tempo_value,
                    "target_value": best_value,
                    "delta_to_match": comparison_delta(tempo_value, best_value, direction),
                }
            )
    return {
        "suite": "live-agent-browser-bench",
        "case_id": "checkout-submit",
        "tempo_runner": TEMPO_RUNNER,
        "baseline_runner": RAW_CHROME_RUNNER,
        "agent_style_runners": sorted(AGENT_STYLE_RUNNERS),
        "comparison_notes": [
            "raw-chrome-cdp is excluded from observation-token and agent-step categories because it has no model-facing observation stream.",
            "model_input_tokens_p95 ranks the full model-facing stream each runner presents to an agent; compact_observation_tokens_p95 ranks the largest compact observation projection per run.",
            "max_observation_tokens_p95 keeps Tempo's full durable structured audit JSON cost visible and is intentionally separate from compact model-facing projections.",
            "max_observation_tokens_p95 compares the largest single durable observation per run; total_model_input_tokens_p95 ranks the cumulative model-facing stream where runners expose it.",
            "cpu_time_ms_p95 is row-level only until every runner uses the same resource-accounting scope.",
            "cold_start_wall_clock_ms reports iteration 1; steady_state_wall_clock_ms_p95 ranks iteration 2+ only and is omitted for one-iteration smoke artifacts.",
            "CDP Performance.getMetrics fields are required and ranked for every runner in this CDP-backed benchmark.",
            "web_* categories come from the browser Performance Timeline APIs and are required for every runner, including Tempo.",
            "Positive deltas mean Tempo is behind that comparison target; negative deltas mean Tempo is ahead.",
        ],
        "rows": rows,
        "categories": categories,
        "gaps_to_close": gaps_to_close,
    }


def comparison_row(
    runner: str,
    runner_summary: dict[str, Any],
    runner_metrics: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "runner": runner,
        "runs": int(runner_summary["runs"]),
        "success_rate": float(runner_summary["success_rate"]),
        "failure_count": sum(int(count) for count in runner_summary["failure_modes"].values()),
        "retry_count_total": int(runner_summary["retry_count_total"]),
        "browser_performance_metrics_available": all(
            bool(metric.get("browser_performance_metrics_available"))
            for metric in runner_metrics
        ),
        "browser_performance_metrics_unavailable_reason": first_unavailable_browser_metrics_reason(
            runner_metrics
        ),
        "wall_clock_ms_p50": int(runner_summary["wall_clock_ms"]["p50"]),
        "wall_clock_ms_p95": int(runner_summary["wall_clock_ms"]["p95"]),
        "runner_internal_wall_clock_ms_p95": runner_internal_wall_clock_ms_p95(runner_metrics),
        "cold_start_wall_clock_ms": cold_start_wall_clock_ms(runner_metrics),
        "steady_state_wall_clock_ms_p95": steady_state_wall_clock_ms_p95(runner_metrics),
        "tempo_total_wall_clock_ms_p95": optional_metric_percentile(
            runner_metrics,
            "tempo_total_wall_clock_ms",
            0.95,
        ),
        "tempo_runtime_setup_ms_p95": optional_metric_percentile(
            runner_metrics,
            "tempo_runtime_setup_ms",
            0.95,
        ),
        "tempo_structured_probe_ms_p95": optional_metric_percentile(
            runner_metrics,
            "tempo_structured_probe_ms",
            0.95,
        ),
        "tempo_driver_launch_ms_p95": optional_metric_percentile(
            runner_metrics,
            "tempo_driver_launch_ms",
            0.95,
        ),
        "tempo_agent_run_ms_p95": optional_metric_percentile(
            runner_metrics,
            "tempo_agent_run_ms",
            0.95,
        ),
        "tempo_driver_close_ms_p95": optional_metric_percentile(
            runner_metrics,
            "tempo_driver_close_ms",
            0.95,
        ),
        "browser_nodes_p95": optional_metric_percentile(
            runner_metrics,
            "browser_nodes_p95",
            0.95,
        ),
        "browser_task_duration_ms_p95": optional_metric_percentile(
            runner_metrics,
            "browser_task_duration_ms_p95",
            0.95,
        ),
        "browser_script_duration_ms_p95": optional_metric_percentile(
            runner_metrics,
            "browser_script_duration_ms_p95",
            0.95,
        ),
        "browser_layout_duration_ms_p95": optional_metric_percentile(
            runner_metrics,
            "browser_layout_duration_ms_p95",
            0.95,
        ),
        "browser_js_heap_used_bytes_p95": optional_metric_percentile(
            runner_metrics,
            "browser_js_heap_used_bytes_p95",
            0.95,
        ),
        **{
            field_name: optional_metric_percentile(runner_metrics, field_name, 0.95)
            for field_name in BROWSER_PERFORMANCE_ROW_FIELDS.values()
        },
        "cpu_time_ms_p95": percentile(
            [
                int(metric.get("cpu_user_ms", 0)) + int(metric.get("cpu_system_ms", 0))
                for metric in runner_metrics
            ],
            0.95,
        ),
        "max_rss_bytes_p95": int(runner_summary["max_rss_bytes"]["p95"]),
        "model_input_tokens_p95": int(runner_summary["model_input_tokens"]["p95"]),
        "compact_observation_tokens_p95": percentile(
            [
                comparable_compact_observation_tokens(metric)
                for metric in runner_metrics
            ],
            0.95,
        ),
        "max_observation_tokens_p95": percentile(
            [
                int(metric.get("max_observation_tokens", metric.get("model_input_tokens", 0)))
                for metric in runner_metrics
            ],
            0.95,
        ),
        "total_model_input_tokens_p95": optional_percentile(
            [
                comparable_total_model_input_tokens(metric)
                for metric in runner_metrics
            ],
            0.95,
        ),
        "browser_rss_bytes_p95": percentile(
            [browser_rss_bytes(metric) for metric in runner_metrics],
            0.95,
        ),
        "process_count_at_peak_p95": percentile(
            [int(metric.get("process_count_at_peak", 0)) for metric in runner_metrics],
            0.95,
        ),
        "web_performance_metrics_available": all(
            bool(metric.get("web_performance_metrics_available"))
            for metric in runner_metrics
        ),
        **{
            field_name: optional_metric_percentile(runner_metrics, field_name, 0.95)
            for field_name in WEB_PERFORMANCE_ROW_FIELDS.values()
        },
        "observations_p95": int(runner_summary["observations"]["p95"]),
        "model_input_observations_p95": int(runner_summary["model_input_observations"]["p95"]),
        "step_count_p95": int(runner_summary["step_count"]["p95"]),
    }


def cold_start_wall_clock_ms(runner_metrics: list[dict[str, Any]]) -> int | None:
    first = next(
        (
            metric
            for metric in sorted(runner_metrics, key=lambda item: int(item.get("iteration", 0)))
            if int(metric.get("iteration", 0)) == 1
        ),
        None,
    )
    return int(first["wall_clock_ms"]) if first else None


def steady_state_wall_clock_ms_p95(runner_metrics: list[dict[str, Any]]) -> int | None:
    values = [
        int(metric["wall_clock_ms"])
        for metric in runner_metrics
        if int(metric.get("iteration", 0)) > 1
    ]
    return percentile(values, 0.95) if values else None


def runner_internal_wall_clock_ms_p95(runner_metrics: list[dict[str, Any]]) -> int | None:
    values = []
    for metric in runner_metrics:
        if "tempo_total_wall_clock_ms" in metric:
            values.append(int(metric["tempo_total_wall_clock_ms"]))
        elif "child_wall_clock_ms" in metric:
            values.append(int(metric["child_wall_clock_ms"]))
        else:
            values.append(int(metric["wall_clock_ms"]))
    return percentile(values, 0.95) if values else None


def browser_rss_bytes(metric: dict[str, Any]) -> int:
    by_type = metric.get("rss_at_peak_by_process_type_bytes", {})
    if not isinstance(by_type, dict):
        return 0
    return sum(
        int(value)
        for key, value in by_type.items()
        if isinstance(key, str) and (key == "chrome-browser" or key.startswith("chrome-"))
    )


def optional_metric_percentile(
    runner_metrics: list[dict[str, Any]],
    field: str,
    pct: float,
) -> int | None:
    if not runner_metrics or any(field not in metric for metric in runner_metrics):
        return None
    return percentile([int(metric[field]) for metric in runner_metrics], pct)


def first_unavailable_browser_metrics_reason(runner_metrics: list[dict[str, Any]]) -> str | None:
    for metric in runner_metrics:
        if not metric.get("browser_performance_metrics_available"):
            return str(
                metric.get(
                    "browser_performance_metrics_unavailable_reason",
                    "browser performance metrics unavailable",
                )
            )
    return None


def category_sort_key(entry: dict[str, Any], direction: str) -> tuple[float, str]:
    value = float(entry["value"])
    if direction == "higher_is_better":
        return (-value, str(entry["runner"]))
    return (value, str(entry["runner"]))


def comparison_delta(
    tempo_value: int | float,
    target_value: int | float,
    direction: str,
) -> int | float:
    if direction == "higher_is_better":
        return target_value - tempo_value
    return tempo_value - target_value


def optional_percentile(values: list[int | None], pct: float) -> int | None:
    concrete = [int(value) for value in values if value is not None]
    if len(concrete) != len(values):
        return None
    return percentile(concrete, pct)


def comparable_total_model_input_tokens(metric: dict[str, Any]) -> int | None:
    model_observations = int(
        metric.get("model_input_observations", metric.get("observations", 0))
    )
    if model_observations == 0:
        return None
    if "total_model_input_tokens" in metric:
        return int(metric["total_model_input_tokens"])
    if model_observations <= 1:
        return int(metric.get("model_input_tokens", 0))
    return None


def comparable_compact_observation_tokens(metric: dict[str, Any]) -> int:
    if "max_compact_observation_tokens" in metric:
        return int(metric["max_compact_observation_tokens"])
    return int(metric.get("max_observation_tokens", metric.get("model_input_tokens", 0)))


def comparison_rank(
    tempo_value: int | float,
    ranked: list[dict[str, Any]],
    direction: str,
) -> int:
    if direction == "higher_is_better":
        return 1 + sum(1 for entry in ranked if entry["value"] > tempo_value)
    return 1 + sum(1 for entry in ranked if entry["value"] < tempo_value)


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
        validate_metric(metric, iterations, output_dir)

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

    gap_report = load_json(output_dir / "agent-browser-bench-gaps.json")
    if gap_report != expected_gap_report(metrics, summary):
        raise ValidationError("agent-browser-bench-gaps.json does not match report summary")

    jsonl_metrics = load_jsonl(output_dir / "agent-browser-bench.jsonl")
    if jsonl_metrics != metrics:
        raise ValidationError("agent-browser-bench.jsonl does not match report metrics")

    chrome_version = load_json(output_dir / "chrome-version.txt")
    if chrome_version.get("chrome") != report["chrome"]:
        raise ValidationError("chrome-version.txt chrome does not match report")
    if chrome_version.get("version") != report["chrome_version"]:
        raise ValidationError("chrome-version.txt version does not match report")

    expected_status = render_status_markdown(report, summary, gap_report, chrome_version)
    require_file(output_dir / STATUS_ARTIFACT)
    if (output_dir / STATUS_ARTIFACT).read_text() != expected_status:
        raise ValidationError(f"{STATUS_ARTIFACT} does not match report summary")

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
        validate_metric(metric, iteration, iteration_dir)
    if load_jsonl(iteration_dir / "agent-browser-bench.jsonl") != metrics:
        raise ValidationError(f"{iteration_dir}/agent-browser-bench.jsonl does not match metrics")
    return metrics


def sqlite_journal_entry_count(journal_path: Path) -> int:
    try:
        with sqlite3.connect(f"file:{journal_path}?mode=ro", uri=True) as conn:
            row = conn.execute("select count(*) from journal_entries").fetchone()
    except sqlite3.Error as error:
        raise ValidationError(f"invalid tempo journal sqlite artifact {journal_path}: {error}") from error
    if row is None:
        raise ValidationError(f"tempo journal sqlite artifact has no journal_entries count: {journal_path}")
    return int(row[0])


def require_applied_steps(path: Path, steps: Any, expected_count: int) -> None:
    if not isinstance(steps, list) or len(steps) != expected_count:
        raise ValidationError(f"{path} steps must contain {expected_count} entries")
    keys = set()
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            raise ValidationError(f"{path} step {index} must be an object")
        key = step.get("idempotency_key") or step.get("key")
        if not isinstance(key, str) or not key:
            raise ValidationError(f"{path} step {index} must include an idempotency key")
        if key in keys:
            raise ValidationError(f"{path} duplicate idempotency key: {key}")
        keys.add(key)
        outcome = step.get("outcome")
        if not isinstance(outcome, dict):
            raise ValidationError(f"{path} step {index} outcome must be an object")
        state = outcome.get("state", outcome.get("kind"))
        if state != "applied":
            raise ValidationError(f"{path} step {index} must be applied, got {state!r}")


def validate_tempo_derived_artifacts(
    output_dir: Path,
    metrics: list[dict[str, Any]],
) -> None:
    tempo = next((metric for metric in metrics if metric["runner"] == TEMPO_RUNNER), None)
    raw_chrome = next((metric for metric in metrics if metric["runner"] == RAW_CHROME_RUNNER), None)
    if tempo is None:
        raise ValidationError(f"{output_dir} missing tempo-cdp-agent metric")
    if raw_chrome is None:
        raise ValidationError(f"{output_dir} missing raw-chrome-cdp metric")

    run_report_path = output_dir / "tempo-run.json"
    replay_path = output_dir / "replay.json"
    eval_record_path = output_dir / "tempo-eval-record.json"
    eval_records_path = output_dir / "eval-records.jsonl"
    scorecard_path = output_dir / "scorecard.json"
    journal_path = output_dir / "tempo-journal.sqlite"

    run_report = load_json(run_report_path)
    if run_report.get("engine") != "cdp":
        raise ValidationError("tempo-run.json engine must be cdp")
    if run_report.get("status", {}).get("state") != "completed":
        raise ValidationError("tempo-run.json status.state must be completed")
    if int(run_report.get("actions_completed", -1)) != int(tempo["step_count"]):
        raise ValidationError("tempo-run.json actions_completed must match tempo step_count")
    if int(run_report.get("observations", -1)) != int(tempo["observations"]):
        raise ValidationError("tempo-run.json observations must match tempo metric")
    if int(run_report.get("model_input_observations", -1)) != int(tempo["model_input_observations"]):
        raise ValidationError("tempo-run.json model_input_observations must match tempo metric")
    if int(run_report.get("total_model_input_tokens", -1)) != int(tempo["model_input_tokens"]):
        raise ValidationError("tempo-run.json total_model_input_tokens must match tempo metric")
    if run_report.get("timings_ms") != tempo.get("tempo_phase_timings_ms"):
        raise ValidationError("tempo-run.json timings_ms must match tempo metric phase timings")
    if run_report.get("browser_performance_metrics_available") is not True:
        raise ValidationError("tempo-run.json browser_performance_metrics_available must be true")
    if run_report.get("web_performance_metrics_available") is not True:
        raise ValidationError("tempo-run.json web_performance_metrics_available must be true")
    if run_report.get("browser_performance_metrics") != tempo.get("browser_performance_metrics"):
        raise ValidationError("tempo-run.json browser_performance_metrics must match tempo metric")
    if run_report.get("web_performance_metrics") != tempo.get("web_performance_metrics"):
        raise ValidationError("tempo-run.json web_performance_metrics must match tempo metric")
    require_applied_steps(run_report_path, run_report.get("steps"), int(tempo["step_count"]))

    journal_count = sqlite_journal_entry_count(journal_path)
    replay = load_json(replay_path)
    if replay.get("session_started") is not True or replay.get("session_closed") is not True:
        raise ValidationError("replay.json must prove the session started and closed")
    if int(replay.get("entries", -1)) != journal_count:
        raise ValidationError("replay.json entries must match the sqlite journal entry count")
    if int(replay.get("last_seq", -1)) != journal_count - 1:
        raise ValidationError("replay.json last_seq must match the sqlite journal entry count")
    if int(replay.get("applied_steps", -1)) != int(tempo["step_count"]):
        raise ValidationError("replay.json applied_steps must match tempo step_count")
    if int(replay.get("planned_actions", -1)) != int(tempo["step_count"]):
        raise ValidationError("replay.json planned_actions must match tempo step_count")
    if int(replay.get("observations", -1)) != int(tempo["observations"]):
        raise ValidationError("replay.json observations must match tempo metric")
    if int(replay.get("step_errors", -1)) != 0:
        raise ValidationError("replay.json step_errors must be zero")
    if int(replay.get("transport_errors", -1)) != 0:
        raise ValidationError("replay.json transport_errors must be zero")
    require_applied_steps(replay_path, replay.get("steps"), int(tempo["step_count"]))
    require_applied_steps(replay_path, replay.get("step_triples"), int(tempo["step_count"]))

    eval_record = load_json(eval_record_path)
    if eval_record.get("suite") != "live-agent-browser-bench":
        raise ValidationError("tempo-eval-record.json suite must be live-agent-browser-bench")
    if eval_record.get("case_id") != "checkout-submit":
        raise ValidationError("tempo-eval-record.json case_id must be checkout-submit")
    if eval_record.get("lane") != "cdp":
        raise ValidationError("tempo-eval-record.json lane must be cdp")
    if eval_record.get("success") is not True:
        raise ValidationError("tempo-eval-record.json success must be true")
    if eval_record.get("fallback_used") is not False:
        raise ValidationError("tempo-eval-record.json fallback_used must be false")
    if int(eval_record.get("step_count", -1)) != int(tempo["step_count"]):
        raise ValidationError("tempo-eval-record.json step_count must match tempo metric")
    if int(eval_record.get("baseline_wall_clock_ms", -1)) != int(raw_chrome["wall_clock_ms"]):
        raise ValidationError(
            "tempo-eval-record.json baseline_wall_clock_ms must match raw Chrome wall_clock_ms"
        )

    eval_records = load_jsonl(eval_records_path)
    if eval_records != [eval_record]:
        raise ValidationError("eval-records.jsonl must contain exactly tempo-eval-record.json")

    scorecard = load_json(scorecard_path)
    if int(scorecard.get("total_cases", -1)) != 1:
        raise ValidationError("scorecard.json total_cases must be 1")
    if scorecard.get("success_rate") != 1.0:
        raise ValidationError("scorecard.json success_rate must be 1.0")
    if scorecard.get("fallback_rate") != 0.0:
        raise ValidationError("scorecard.json fallback_rate must be 0.0")
    if scorecard.get("violations") != []:
        raise ValidationError("scorecard.json violations must be empty")
    lanes = scorecard.get("lanes")
    if not isinstance(lanes, list) or not any(
        lane.get("lane") == "cdp"
        and lane.get("success_rate") == 1.0
        and int(lane.get("total_cases", -1)) == 1
        for lane in lanes
        if isinstance(lane, dict)
    ):
        raise ValidationError("scorecard.json must include one successful cdp lane")


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
                validate_tempo_derived_artifacts(iteration_dir, iteration_metrics[-len(EXPECTED_RUNNERS):])
        if iteration_metrics != root_metrics:
            raise ValidationError(
                "root agent-browser-bench.json metrics do not match iteration artifacts"
            )
        return

    if require_derived_artifacts:
        for name in DERIVED_ARTIFACTS:
            require_file(output_dir / name)
        validate_tempo_derived_artifacts(output_dir, root_metrics)


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
