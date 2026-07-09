#!/usr/bin/env python3
"""Render a human-readable status report from agent/browser benchmark artifacts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


STATUS_ARTIFACT = "agent-browser-bench-status.md"


def render_status_markdown(
    report: dict[str, Any],
    summary: dict[str, Any],
    gap_report: dict[str, Any],
    chrome_version: dict[str, Any],
) -> str:
    categories = gap_report.get("categories", [])
    if not isinstance(categories, list):
        categories = []
    gaps = gap_report.get("gaps_to_close", [])
    if not isinstance(gaps, list):
        gaps = []
    rows = gap_report.get("rows", [])
    if not isinstance(rows, list):
        rows = []

    best_count = sum(1 for category in categories if category.get("tempo_is_best") is True)
    total_count = len(categories)
    iterations = report.get("iterations", report.get("iteration", 1))
    chrome_label = chrome_version.get("version") or report.get("chrome_version") or "unknown"

    lines = [
        "# Agent Browser Benchmark Status",
        "",
        f"- Suite: `{gap_report.get('suite', report.get('suite', 'live-agent-browser-bench'))}`",
        f"- Case: `{gap_report.get('case_id', 'checkout-submit')}`",
        f"- Iterations: `{iterations}`",
        f"- Chrome: `{chrome_label}`",
        f"- Tempo best/tied categories: `{best_count}/{total_count}`",
        f"- Gaps to close: `{len(gaps)}`",
        "",
        "## Category Rankings",
        "",
        "| Category | Direction | Tempo | Best | Rank | Delta vs Raw Chrome | Delta vs Best |",
        "| --- | --- | ---: | --- | ---: | ---: | ---: |",
    ]
    for category in categories:
        name = str(category.get("name", "unknown"))
        best = category.get("best") if isinstance(category.get("best"), dict) else {}
        best_runner = best.get("runner", "-")
        best_value = best.get("value")
        lines.append(
            "| {name} | {direction} | {tempo} | {best_runner} {best_value} | {rank} | {raw_delta} | {best_delta} |".format(
                name=name,
                direction=category.get("direction", "-"),
                tempo=format_value(name, value_at(category, "tempo")),
                best_runner=best_runner,
                best_value=format_value(name, best_value),
                rank=category.get("tempo_rank", "-"),
                raw_delta=format_delta(name, category.get("tempo_delta_vs_raw_chrome")),
                best_delta=format_delta(name, category.get("tempo_delta_vs_best")),
            )
        )

    lines.extend(
        [
            "",
            "## Gaps To Close",
            "",
        ]
    )
    if gaps:
        for gap in gaps:
            name = str(gap.get("category", "unknown"))
            lines.append(
                "- `{category}`: Tempo `{tempo}` vs `{target_runner}` `{target}`; close `{delta}`.".format(
                    category=name,
                    tempo=format_value(name, gap.get("tempo_value")),
                    target_runner=gap.get("target_runner", "-"),
                    target=format_value(name, gap.get("target_value")),
                    delta=format_delta(name, gap.get("delta_to_match")),
                )
            )
    else:
        lines.append("- None. Tempo is best or tied in every tracked category.")

    lines.extend(
        [
            "",
            "## Runner Summary",
            "",
            "| Runner | Success | Cold Wall | Wall p95 | Steady Wall p95 | RSS p95 | Model Tokens p95 | Retries | Failures |",
            "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for row in rows:
        if not isinstance(row, dict):
            continue
        lines.append(
            "| {runner} | {success} | {cold_wall} | {wall} | {steady_wall} | {rss} | {tokens} | {retries} | {failures} |".format(
                runner=row.get("runner", "-"),
                success=format_rate(row.get("success_rate")),
                cold_wall=format_value(
                    "cold_start_wall_clock_ms",
                    row.get("cold_start_wall_clock_ms"),
                ),
                wall=format_value("wall_clock_ms_p95", row.get("wall_clock_ms_p95")),
                steady_wall=format_value(
                    "steady_state_wall_clock_ms_p95",
                    row.get("steady_state_wall_clock_ms_p95"),
                ),
                rss=format_value("max_rss_bytes_p95", row.get("max_rss_bytes_p95")),
                tokens=format_value("model_input_tokens_p95", row.get("model_input_tokens_p95")),
                retries=row.get("retry_count_total", "-"),
                failures=row.get("failure_count", "-"),
            )
        )

    lines.extend(
        [
            "",
            "## Browser Metrics",
            "",
            "| Runner | Browser Perf | Internal Wall p95 | Browser RSS p95 | Proc Count p95 | Nodes p95 | Task p95 | JS Heap p95 | Model Obs p95 | Total Tokens p95 |",
            "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
        ]
    )
    for row in rows:
        if not isinstance(row, dict):
            continue
        perf = "yes" if row.get("browser_performance_metrics_available") else "no"
        reason = row.get("browser_performance_metrics_unavailable_reason")
        if reason:
            perf = f"no ({reason})"
        lines.append(
            "| {runner} | {perf} | {internal_wall} | {browser_rss} | {proc_count} | {nodes} | {task} | {heap} | {model_obs} | {total_tokens} |".format(
                runner=row.get("runner", "-"),
                perf=perf,
                internal_wall=format_value(
                    "runner_internal_wall_clock_ms_p95",
                    row.get("runner_internal_wall_clock_ms_p95"),
                ),
                browser_rss=format_value("browser_rss_bytes_p95", row.get("browser_rss_bytes_p95")),
                proc_count=format_value(
                    "process_count_at_peak_p95",
                    row.get("process_count_at_peak_p95"),
                ),
                nodes=format_value("browser_nodes_p95", row.get("browser_nodes_p95")),
                task=format_value(
                    "browser_task_duration_ms_p95",
                    row.get("browser_task_duration_ms_p95"),
                ),
                heap=format_value(
                    "browser_js_heap_used_bytes_p95",
                    row.get("browser_js_heap_used_bytes_p95"),
                ),
                model_obs=format_value(
                    "model_input_observations_p95",
                    row.get("model_input_observations_p95"),
                ),
                total_tokens=format_value(
                    "total_model_input_tokens_p95",
                    row.get("total_model_input_tokens_p95"),
                ),
            )
        )

    tempo_row = next(
        (row for row in rows if isinstance(row, dict) and row.get("runner") == "tempo-cdp-agent"),
        None,
    )
    if isinstance(tempo_row, dict) and tempo_row.get("tempo_total_wall_clock_ms_p95") is not None:
        lines.extend(
            [
                "",
                "## Tempo Phase Timings",
                "",
                "| Phase | p95 |",
                "| --- | ---: |",
                "| CLI report total | {value} |".format(
                    value=format_value(
                        "tempo_total_wall_clock_ms_p95",
                        tempo_row.get("tempo_total_wall_clock_ms_p95"),
                    )
                ),
                "| Runtime setup | {value} |".format(
                    value=format_value(
                        "tempo_runtime_setup_ms_p95",
                        tempo_row.get("tempo_runtime_setup_ms_p95"),
                    )
                ),
                "| Structured probe | {value} |".format(
                    value=format_value(
                        "tempo_structured_probe_ms_p95",
                        tempo_row.get("tempo_structured_probe_ms_p95"),
                    )
                ),
                "| Driver launch | {value} |".format(
                    value=format_value(
                        "tempo_driver_launch_ms_p95",
                        tempo_row.get("tempo_driver_launch_ms_p95"),
                    )
                ),
                "| Agent run | {value} |".format(
                    value=format_value(
                        "tempo_agent_run_ms_p95",
                        tempo_row.get("tempo_agent_run_ms_p95"),
                    )
                ),
                "| Driver close | {value} |".format(
                    value=format_value(
                        "tempo_driver_close_ms_p95",
                        tempo_row.get("tempo_driver_close_ms_p95"),
                    )
                ),
            ]
        )

    notes = gap_report.get("comparison_notes", [])
    if isinstance(notes, list) and notes:
        lines.extend(["", "## Notes", ""])
        for note in notes:
            lines.append(f"- {note}")

    return "\n".join(lines) + "\n"


def value_at(category: dict[str, Any], key: str) -> Any:
    value = category.get(key)
    if isinstance(value, dict):
        return value.get("value")
    return None


def format_value(name: str, value: Any) -> str:
    if value is None:
        return "-"
    if name.endswith("_rate"):
        return format_rate(value)
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if "bytes" in name:
        return f"{int(value)} ({format_bytes(int(value))})"
    if name.endswith("_ms") or "_ms_" in name:
        return f"{int(value)} ms"
    if "tokens" in name:
        return f"{int(value)} tokens"
    return str(value)


def format_delta(name: str, value: Any) -> str:
    if value is None:
        return "-"
    if isinstance(value, float) and value.is_integer():
        value = int(value)
    if isinstance(value, (int, float)) and value > 0:
        return f"+{format_value(name, value)}"
    return format_value(name, value)


def format_rate(value: Any) -> str:
    if value is None:
        return "-"
    return f"{float(value):.3f}"


def format_bytes(value: int) -> str:
    units = ["B", "KiB", "MiB", "GiB", "TiB"]
    amount = float(value)
    for unit in units:
        if abs(amount) < 1024 or unit == units[-1]:
            if unit == "B":
                return f"{int(amount)} {unit}"
            return f"{amount:.1f} {unit}"
        amount /= 1024
    return f"{value} B"


def load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise RuntimeError(f"{path} must contain a JSON object")
    return value


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args()

    output_dir = Path(args.output_dir)
    report = load_json(output_dir / "agent-browser-bench.json")
    summary = load_json(output_dir / "agent-browser-bench-summary.json")
    gap_report = load_json(output_dir / "agent-browser-bench-gaps.json")
    chrome_version = load_json(output_dir / "chrome-version.txt")
    rendered = render_status_markdown(report, summary, gap_report, chrome_version)
    if args.write:
        (output_dir / STATUS_ARTIFACT).write_text(rendered)
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
