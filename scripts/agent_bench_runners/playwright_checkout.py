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
                    success = page.locator("#status").get_attribute("data-done") == "true"
                finally:
                    context.close()
    except Exception as error:  # noqa: BLE001
        failure_mode = type(error).__name__
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
            "success": success,
        },
    )
    return {
        "success": success,
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
