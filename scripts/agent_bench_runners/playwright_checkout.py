#!/usr/bin/env python3
"""External Playwright baseline for the live agent checkout benchmark."""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import time
from pathlib import Path


def estimated_tokens(byte_count: int) -> int:
    return (byte_count + 3) // 4


def write_report(path: Path, report: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def launch_args() -> list[str]:
    args = ["--disable-gpu", "--disable-dev-shm-usage", "--use-mock-keychain"]
    if os.environ.get("TEMPO_CDP_NO_SANDBOX") == "1":
        args.append("--no-sandbox")
    return args


def checkout_oracle_from_page(page: object) -> dict:
    value = page.evaluate(
        """() => {
          const email = document.querySelector('#email')?.value || '';
          const remember = document.querySelector('#remember')?.getAttribute('aria-checked') === 'true';
          const status = document.querySelector('#status');
          const statusText = status?.textContent?.trim() || '';
          const statusDone = status?.dataset?.done === 'true';
          return {
            email_value: email,
            email_matches: email === 'agent@example.com',
            remember_checked: remember,
            remember_checked_inferred: false,
            status_text: statusText,
            status_done: statusDone,
            submitted: email === 'agent@example.com' && remember && statusDone && statusText === 'Order submitted',
            source: 'real-playwright'
          };
        }"""
    )
    return value if isinstance(value, dict) else {"submitted": False, "source": "real-playwright"}


def cdp_performance_metrics(page: object) -> dict:
    cdp = page.context.new_cdp_session(page)
    cdp.send("Performance.enable")
    response = cdp.send("Performance.getMetrics")
    metrics = response.get("metrics", []) if isinstance(response, dict) else []
    return {
        str(metric["name"]): metric["value"]
        for metric in metrics
        if isinstance(metric, dict)
        and isinstance(metric.get("name"), str)
        and isinstance(metric.get("value"), (int, float))
        and not isinstance(metric.get("value"), bool)
    }


def metric_value_to_int(name: str, value: int | float) -> int:
    if name.endswith("Duration"):
        return int(round(float(value) * 1000))
    return int(round(float(value)))


WEB_PERFORMANCE_ROW_FIELDS = {
    "navigation_start_ms": "web_navigation_start_ms_p95",
    "navigation_duration_ms": "web_navigation_duration_ms_p95",
    "worker_start_ms": "web_worker_start_ms_p95",
    "redirect_start_ms": "web_redirect_start_ms_p95",
    "redirect_end_ms": "web_redirect_end_ms_p95",
    "fetch_start_ms": "web_fetch_start_ms_p95",
    "domain_lookup_start_ms": "web_domain_lookup_start_ms_p95",
    "domain_lookup_end_ms": "web_domain_lookup_end_ms_p95",
    "connect_start_ms": "web_connect_start_ms_p95",
    "connect_end_ms": "web_connect_end_ms_p95",
    "secure_connection_start_ms": "web_secure_connection_start_ms_p95",
    "request_start_ms": "web_request_start_ms_p95",
    "response_start_ms": "web_response_start_ms_p95",
    "response_end_ms": "web_response_end_ms_p95",
    "dom_interactive_ms": "web_dom_interactive_ms_p95",
    "dom_content_loaded_start_ms": "web_dom_content_loaded_start_ms_p95",
    "dom_content_loaded_ms": "web_dom_content_loaded_ms_p95",
    "dom_complete_ms": "web_dom_complete_ms_p95",
    "load_event_start_ms": "web_load_event_start_ms_p95",
    "load_event_ms": "web_load_event_ms_p95",
    "resource_count": "web_resource_count_p95",
    "resource_transfer_size_bytes": "web_resource_transfer_size_bytes_p95",
    "resource_encoded_body_size_bytes": "web_resource_encoded_body_size_bytes_p95",
    "resource_decoded_body_size_bytes": "web_resource_decoded_body_size_bytes_p95",
    "resource_duration_ms": "web_resource_duration_ms_p95",
    "resource_max_duration_ms": "web_resource_max_duration_ms_p95",
    "resource_response_end_ms": "web_resource_response_end_ms_p95",
    "first_paint_ms": "web_first_paint_ms_p95",
    "first_contentful_paint_ms": "web_first_contentful_paint_ms_p95",
    "long_task_count": "web_long_task_count_p95",
    "long_task_duration_ms": "web_long_task_duration_ms_p95",
    "long_task_max_duration_ms": "web_long_task_max_duration_ms_p95",
}


def web_performance_metrics(page: object) -> dict:
    value = page.evaluate(
        """async () => {
          const n = (value) => Number.isFinite(Number(value)) ? Math.round(Number(value)) : 0;
          const nav = performance.getEntriesByType('navigation')[0] || null;
          const resources = performance.getEntriesByType('resource');
          const paints = {};
          for (const entry of performance.getEntriesByType('paint')) paints[entry.name] = n(entry.startTime);
          const longTasks = await (async () => {
            const supported = window.PerformanceObserver?.supportedEntryTypes || [];
            if (!supported.includes('longtask')) return [];
            return await new Promise((resolve) => {
              const entries = [];
              let observer = null;
              const finish = () => {
                if (observer) observer.disconnect();
                resolve(entries);
              };
              try {
                observer = new PerformanceObserver((list) => {
                  entries.push(...list.getEntries());
                });
                observer.observe({ type: 'longtask', buffered: true });
                setTimeout(finish, 0);
              } catch (_error) {
                finish();
              }
            });
          })();
          const sum = (entries, field) => entries.reduce((total, entry) => total + n(entry[field]), 0);
          const max = (entries, field) => entries.reduce((largest, entry) => Math.max(largest, n(entry[field])), 0);
          return {
            navigation_start_ms: nav ? n(nav.startTime) : 0,
            navigation_duration_ms: nav ? n(nav.duration) : 0,
            worker_start_ms: nav ? n(nav.workerStart) : 0,
            redirect_start_ms: nav ? n(nav.redirectStart) : 0,
            redirect_end_ms: nav ? n(nav.redirectEnd) : 0,
            fetch_start_ms: nav ? n(nav.fetchStart) : 0,
            domain_lookup_start_ms: nav ? n(nav.domainLookupStart) : 0,
            domain_lookup_end_ms: nav ? n(nav.domainLookupEnd) : 0,
            connect_start_ms: nav ? n(nav.connectStart) : 0,
            connect_end_ms: nav ? n(nav.connectEnd) : 0,
            secure_connection_start_ms: nav ? n(nav.secureConnectionStart) : 0,
            request_start_ms: nav ? n(nav.requestStart) : 0,
            response_start_ms: nav ? n(nav.responseStart) : 0,
            response_end_ms: nav ? n(nav.responseEnd) : 0,
            dom_interactive_ms: nav ? n(nav.domInteractive) : 0,
            dom_content_loaded_start_ms: nav ? n(nav.domContentLoadedEventStart) : 0,
            dom_content_loaded_ms: nav ? n(nav.domContentLoadedEventEnd) : 0,
            dom_complete_ms: nav ? n(nav.domComplete) : 0,
            load_event_start_ms: nav ? n(nav.loadEventStart) : 0,
            load_event_ms: nav ? n(nav.loadEventEnd) : 0,
            resource_count: resources.length,
            resource_transfer_size_bytes: sum(resources, 'transferSize'),
            resource_encoded_body_size_bytes: sum(resources, 'encodedBodySize'),
            resource_decoded_body_size_bytes: sum(resources, 'decodedBodySize'),
            resource_duration_ms: sum(resources, 'duration'),
            resource_max_duration_ms: max(resources, 'duration'),
            resource_response_end_ms: max(resources, 'responseEnd'),
            first_paint_ms: paints['first-paint'] || 0,
            first_contentful_paint_ms: paints['first-contentful-paint'] || 0,
            long_task_count: longTasks.length,
            long_task_duration_ms: sum(longTasks, 'duration'),
            long_task_max_duration_ms: max(longTasks, 'duration')
          };
        }"""
    )
    return value if isinstance(value, dict) else {}


def capture_aria_snapshot(page: object) -> str:
    try:
        body = page.locator("body")
        aria_snapshot = getattr(body, "aria_snapshot", None)
        if callable(aria_snapshot):
            snapshot = aria_snapshot(timeout=5000)
            if snapshot:
                return str(snapshot)
    except Exception:  # noqa: BLE001
        pass
    return page.locator("body").inner_text(timeout=5000)


def run(url: str, chrome: str, output: Path) -> dict:
    from playwright.sync_api import sync_playwright

    failure_mode = None
    model_input = ""
    actions: list[dict] = []
    success = False
    step_count = 0
    observations = 0
    started = time.monotonic()
    final_status = ""
    final_oracle: dict = {"submitted": False, "source": "real-playwright"}
    browser_metrics: dict = {}
    web_metrics: dict = {}
    try:
        with sync_playwright() as playwright:
            with tempfile.TemporaryDirectory(prefix="tempo-real-playwright-profile-") as profile_dir:
                context = playwright.chromium.launch_persistent_context(
                    user_data_dir=profile_dir,
                    executable_path=chrome,
                    headless=True,
                    args=launch_args(),
                )
                try:
                    page = context.new_page()
                    page.goto(url, wait_until="load", timeout=15000)
                    model_input = capture_aria_snapshot(page)
                    observations = 1
                    page.get_by_label("Email").fill("agent@example.com", timeout=5000)
                    step_count += 1
                    actions.append({"kind": "fill", "target": "label=Email"})
                    page.get_by_role("checkbox", name="Remember me").click(timeout=5000)
                    step_count += 1
                    actions.append({"kind": "click", "target": "role=checkbox name=Remember me"})
                    page.get_by_role("button", name="Pay now").click(timeout=5000)
                    step_count += 1
                    actions.append({"kind": "click", "target": "role=button name=Pay now"})
                    page.wait_for_function(
                        "document.querySelector('#status')?.dataset.done === 'true'",
                        timeout=5000,
                    )
                    final_status = page.locator("#status").inner_text(timeout=5000)
                    final_oracle = checkout_oracle_from_page(page)
                    success = bool(final_oracle.get("submitted"))
                    browser_metrics = cdp_performance_metrics(page)
                    web_metrics = web_performance_metrics(page)
                finally:
                    context.close()
    except Exception as error:  # noqa: BLE001
        failure_mode = type(error).__name__
        success = False
    wall_ms = int((time.monotonic() - started) * 1000)
    byte_count = len(model_input.encode("utf-8"))
    model_input_path = output.with_suffix(".model-input.txt")
    action_trace_path = output.with_suffix(".trace.json")
    write_text(model_input_path, model_input)
    write_report(
        action_trace_path,
        {
            "actions": actions,
            "final_status": final_status,
            "final_oracle": final_oracle,
            "success": success,
        },
    )
    report = {
        "success": success,
        "final_oracle": final_oracle,
        "wall_clock_ms": wall_ms,
        "step_count": step_count,
        "retry_count": 0,
        "failure_mode": failure_mode,
        "model_input_bytes": byte_count,
        "model_input_tokens": estimated_tokens(byte_count),
        "total_model_input_bytes": byte_count,
        "total_model_input_tokens": estimated_tokens(byte_count),
        "observations": 1,
        "model_input_observations": 1,
        "max_observation_bytes": byte_count,
        "max_observation_tokens": estimated_tokens(byte_count),
        "observations": observations,
        "adapter": "playwright.sync_api",
        "external_process": True,
        "model_input_path": str(model_input_path),
        "action_trace_path": str(action_trace_path),
    }
    report["browser_performance_metrics_available"] = True
    report["browser_performance_metrics"] = browser_metrics
    for source_name, field_name in {
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
    }.items():
        if source_name in browser_metrics:
            report[field_name] = metric_value_to_int(source_name, browser_metrics[source_name])
    report["web_performance_metrics_available"] = bool(web_metrics)
    report["web_performance_metrics"] = web_metrics
    for source_name, field_name in WEB_PERFORMANCE_ROW_FIELDS.items():
        report[field_name] = int(web_metrics.get(source_name, 0))
    return report


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--chrome", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    output = Path(args.output)
    report = run(args.url, args.chrome, output)
    write_report(output, report)
    return 0 if report["success"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
