#!/usr/bin/env python3
"""External browser-use-style DOM loop baseline for live agent benchmarks."""

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
            source: 'external-browser-use-dom-loop'
          };
        }"""
    )
    return (
        value
        if isinstance(value, dict)
        else {"submitted": False, "source": "external-browser-use-dom-loop"}
    )


def cdp_performance_metrics(page: object) -> dict:
    cdp = page.context.new_cdp_session(page)
    cdp.send("Performance.enable")
    response = cdp.send("Performance.getMetrics")
    metrics = response.get("metrics", []) if isinstance(response, dict) else []
    wanted = {
        "Documents",
        "Frames",
        "JSEventListeners",
        "Nodes",
        "LayoutCount",
        "RecalcStyleCount",
        "LayoutDuration",
        "RecalcStyleDuration",
        "ScriptDuration",
        "TaskDuration",
        "JSHeapUsedSize",
        "JSHeapTotalSize",
    }
    return {
        str(metric["name"]): metric["value"]
        for metric in metrics
        if isinstance(metric, dict)
        and metric.get("name") in wanted
        and isinstance(metric.get("value"), (int, float))
    }


def metric_value_to_int(name: str, value: int | float) -> int:
    if name.endswith("Duration"):
        return int(round(float(value) * 1000))
    return int(round(float(value)))


DOM_SERIALIZER = r"""
(() => {
  const roleFor = (element) => {
    const role = element.getAttribute('role');
    if (role) return role;
    const tag = element.tagName.toLowerCase();
    if (tag === 'a') return 'link';
    if (tag === 'button') return 'button';
    if (tag === 'select') return 'combobox';
    if (tag === 'input') {
      const type = (element.getAttribute('type') || 'text').toLowerCase();
      if (type === 'search') return 'searchbox';
      if (type === 'checkbox') return 'checkbox';
      if (type === 'radio') return 'radio';
      return 'textbox';
    }
    return tag;
  };
  const isInteractive = (element) => {
    const tag = element.tagName.toLowerCase();
    return ['a', 'button', 'input', 'select', 'textarea'].includes(tag)
      || element.hasAttribute('role')
      || element.hasAttribute('tabindex');
  };
  const nameFor = (element) => {
    if (element.labels && element.labels.length > 0) {
      return Array.from(element.labels).map((label) => label.innerText.trim()).join(' ');
    }
    return (element.getAttribute('aria-label') || element.innerText || element.value || '').trim();
  };
  const nodes = [];
  const lines = ['[Start of page]'];
  Array.from(document.querySelectorAll('main *')).forEach((element, index) => {
    if (!isInteractive(element)) return;
    const role = roleFor(element);
    const name = nameFor(element);
    const selector = element.id ? `#${element.id}` : null;
    const checked = element.getAttribute('aria-checked');
    nodes.push({ index, role, name, selector, checked });
    const checkedText = checked === null ? '' : ` checked=${checked}`;
    lines.push(`[${index}]<${role}${checkedText}>${name}</${role}>`);
  });
  lines.push('[End of page]');
  return { text: lines.join('\n'), nodes };
})()
"""


def observe(page: object) -> dict:
    return page.evaluate(DOM_SERIALIZER)


def find_node(snapshot: dict, role: str, name_fragment: str) -> dict:
    needle = name_fragment.lower()
    for node in snapshot.get("nodes", []):
        if node.get("role") == role and needle in str(node.get("name", "")).lower():
            return node
    raise RuntimeError(f"missing {role} node containing {name_fragment!r}: {snapshot.get('text')}")


def run(url: str, chrome: str, output: Path) -> dict:
    from playwright.sync_api import sync_playwright

    failure_mode = None
    snapshots: list[str] = []
    actions: list[dict] = []
    success = False
    step_count = 0
    final_status = ""
    started = time.monotonic()
    final_oracle: dict = {"submitted": False, "source": "external-browser-use-dom-loop"}
    browser_metrics: dict = {}
    try:
        with sync_playwright() as playwright:
            with tempfile.TemporaryDirectory(prefix="tempo-browser-use-dom-profile-") as profile_dir:
                context = playwright.chromium.launch_persistent_context(
                    user_data_dir=profile_dir,
                    executable_path=chrome,
                    headless=True,
                    args=launch_args(),
                )
                try:
                    page = context.new_page()
                    page.goto(url, wait_until="load", timeout=15000)

                    snapshot = observe(page)
                    snapshots.append(str(snapshot["text"]))
                    email = find_node(snapshot, "textbox", "Email")
                    page.locator(str(email["selector"])).fill("agent@example.com", timeout=5000)
                    step_count += 1
                    actions.append({"kind": "fill", "node": email})

                    snapshot = observe(page)
                    snapshots.append(str(snapshot["text"]))
                    remember = find_node(snapshot, "checkbox", "Remember me")
                    page.locator(str(remember["selector"])).click(timeout=5000)
                    step_count += 1
                    actions.append({"kind": "click", "node": remember})

                    snapshot = observe(page)
                    snapshots.append(str(snapshot["text"]))
                    pay = find_node(snapshot, "button", "Pay now")
                    page.locator(str(pay["selector"])).click(timeout=5000)
                    step_count += 1
                    actions.append({"kind": "click", "node": pay})

                    page.wait_for_function(
                        "document.querySelector('#status')?.dataset.done === 'true'",
                        timeout=5000,
                    )
                    final_status = page.locator("#status").inner_text(timeout=5000)
                    final_oracle = checkout_oracle_from_page(page)
                    success = bool(final_oracle.get("submitted"))
                    browser_metrics = cdp_performance_metrics(page)
                finally:
                    context.close()
    except Exception as error:  # noqa: BLE001
        failure_mode = type(error).__name__
    wall_ms = int((time.monotonic() - started) * 1000)
    observation_bytes = [len(snapshot.encode("utf-8")) for snapshot in snapshots]
    max_bytes = max(observation_bytes) if observation_bytes else 0
    total_bytes = sum(observation_bytes)
    model_input_path = output.with_suffix(".model-input.txt")
    action_trace_path = output.with_suffix(".trace.json")
    write_text(model_input_path, "\n\n--- observation ---\n\n".join(snapshots))
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
        "model_input_bytes": total_bytes,
        "model_input_tokens": estimated_tokens(total_bytes),
        "total_model_input_bytes": total_bytes,
        "total_model_input_tokens": estimated_tokens(total_bytes),
        "observations": len(snapshots),
        "model_input_observations": len(snapshots),
        "max_observation_bytes": max_bytes,
        "max_observation_tokens": estimated_tokens(max_bytes),
        "observations": len(snapshots),
        "adapter": "playwright.browser-use-dom-format",
        "external_process": True,
        "model_input_path": str(model_input_path),
        "action_trace_path": str(action_trace_path),
    }
    report["browser_performance_metrics_available"] = True
    report["browser_performance_metrics"] = browser_metrics
    for source_name, field_name in {
        "Nodes": "browser_nodes_p95",
        "TaskDuration": "browser_task_duration_ms_p95",
        "ScriptDuration": "browser_script_duration_ms_p95",
        "LayoutDuration": "browser_layout_duration_ms_p95",
        "JSHeapUsedSize": "browser_js_heap_used_bytes_p95",
    }.items():
        if source_name in browser_metrics:
            report[field_name] = metric_value_to_int(source_name, browser_metrics[source_name])
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
