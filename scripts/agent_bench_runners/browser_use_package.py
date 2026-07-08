#!/usr/bin/env python3
"""External browser-use package baseline for live agent benchmarks."""

from __future__ import annotations

import argparse
import asyncio
import inspect
import json
import os
import re
import tempfile
import time
from pathlib import Path
from typing import Any


def estimated_tokens(byte_count: int) -> int:
    return (byte_count + 3) // 4


def write_report(path: Path, report: dict[str, Any]) -> None:
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


async def maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


def node_text(node: Any) -> str:
    for method in ("get_meaningful_text_for_llm", "get_all_children_text"):
        candidate = getattr(node, method, None)
        if callable(candidate):
            try:
                value = candidate()
            except Exception:  # noqa: BLE001
                continue
            if value:
                return str(value)
    attributes = getattr(node, "attributes", {}) or {}
    for key in ("aria-label", "title", "placeholder", "value", "alt"):
        value = attributes.get(key)
        if value:
            return str(value)
    return str(getattr(node, "node_value", "") or "")


def selector_index_from_map(selector_map: dict[int, Any], name_fragment: str) -> int:
    needle = name_fragment.lower()
    for index, node in sorted(selector_map.items()):
        text = node_text(node).lower()
        attributes = getattr(node, "attributes", {}) or {}
        attribute_text = " ".join(str(value) for value in attributes.values()).lower()
        if needle in text or needle in attribute_text:
            return int(index)
    raise RuntimeError(f"missing browser-use selector containing {name_fragment!r}")


def selector_index_from_text(state_text: str, name_fragment: str) -> int:
    needle = re.escape(name_fragment)
    patterns = [
        rf"\[(\d+)\][^\n]*{needle}",
        rf"{needle}[^\n]*\[(\d+)\]",
    ]
    for pattern in patterns:
        match = re.search(pattern, state_text, flags=re.IGNORECASE)
        if match:
            return int(match.group(1))
    raise RuntimeError(f"missing browser-use state index containing {name_fragment!r}: {state_text}")


async def snapshot(browser: Any) -> tuple[str, dict[int, Any]]:
    text = str(await maybe_await(browser.get_state_as_text()))
    selector_map = await maybe_await(browser.get_selector_map())
    if not isinstance(selector_map, dict):
        selector_map = {}
    return text, selector_map


async def wait_for_done(page: Any, timeout_seconds: float = 5.0) -> tuple[bool, str]:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        value = await maybe_await(
            page.evaluate(
                "() => JSON.stringify({"
                "done: document.querySelector('#status')?.dataset.done === 'true', "
                "text: document.querySelector('#status')?.textContent?.trim() || ''"
                "})"
            )
        )
        if isinstance(value, str):
            try:
                status = json.loads(value)
            except json.JSONDecodeError:
                status = {"done": False, "text": value}
        elif isinstance(value, dict):
            status = value
        else:
            status = {"done": False, "text": str(value)}
        if status.get("done") is True:
            return True, str(status.get("text") or "")
        await asyncio.sleep(0.1)
    return False, ""


def find_index(state_text: str, selector_map: dict[int, Any], name_fragment: str) -> int:
    try:
        return selector_index_from_map(selector_map, name_fragment)
    except RuntimeError:
        return selector_index_from_text(state_text, name_fragment)


async def run_browser_use(url: str, chrome: str, output: Path) -> dict[str, Any]:
    from browser_use import BrowserSession
    from browser_use.tools.service import Tools

    failure_mode = None
    snapshots: list[str] = []
    actions: list[dict[str, Any]] = []
    success = False
    step_count = 0
    final_status = ""
    started = time.monotonic()
    browser = None
    try:
        with tempfile.TemporaryDirectory(prefix="tempo-real-browser-use-profile-") as profile_dir:
            browser = BrowserSession(
                executable_path=chrome,
                is_local=True,
                headless=True,
                args=launch_args(),
                user_data_dir=profile_dir,
                use_cloud=False,
                cloud_browser=False,
                enable_default_extensions=False,
            )
            tools = Tools()
            await maybe_await(browser.start())
            await maybe_await(browser.navigate_to(url))

            state, selector_map = await snapshot(browser)
            snapshots.append(state)
            email_index = find_index(state, selector_map, "Email")
            await maybe_await(
                tools.registry.execute_action(
                    "input",
                    {"index": email_index, "text": "agent@example.com", "clear": True},
                    browser_session=browser,
                )
            )
            step_count += 1
            actions.append({"kind": "input", "index": email_index, "text": "agent@example.com"})

            state, selector_map = await snapshot(browser)
            snapshots.append(state)
            remember_index = find_index(state, selector_map, "Remember me")
            await maybe_await(
                tools.registry.execute_action(
                    "click",
                    {"index": remember_index},
                    browser_session=browser,
                )
            )
            step_count += 1
            actions.append({"kind": "click", "index": remember_index, "name": "Remember me"})

            state, selector_map = await snapshot(browser)
            snapshots.append(state)
            pay_index = find_index(state, selector_map, "Pay now")
            await maybe_await(
                tools.registry.execute_action(
                    "click",
                    {"index": pay_index},
                    browser_session=browser,
                )
            )
            step_count += 1
            actions.append({"kind": "click", "index": pay_index, "name": "Pay now"})

            page = await maybe_await(browser.get_current_page())
            if page is None:
                raise RuntimeError("browser-use did not expose a current page")
            success, final_status = await wait_for_done(page)
    except Exception as error:  # noqa: BLE001
        failure_mode = type(error).__name__
        actions.append({"kind": "error", "error": str(error)})
    finally:
        if browser is not None:
            try:
                await maybe_await(browser.close())
            except Exception:  # noqa: BLE001
                pass

    wall_ms = int((time.monotonic() - started) * 1000)
    observation_bytes = [len(item.encode("utf-8")) for item in snapshots]
    max_bytes = max(observation_bytes) if observation_bytes else 0
    total_bytes = sum(observation_bytes)
    model_input_path = output.with_suffix(".model-input.txt")
    action_trace_path = output.with_suffix(".trace.json")
    write_text(model_input_path, "\n\n--- browser-use state ---\n\n".join(snapshots))
    write_report(
        action_trace_path,
        {
            "actions": actions,
            "adapter": "browser-use.package",
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
        "model_input_bytes": total_bytes,
        "model_input_tokens": estimated_tokens(total_bytes),
        "total_model_input_bytes": total_bytes,
        "total_model_input_tokens": estimated_tokens(total_bytes),
        "observations": len(snapshots),
        "model_input_observations": len(snapshots),
        "max_observation_bytes": max_bytes,
        "max_observation_tokens": estimated_tokens(max_bytes),
        "adapter": "browser-use.package",
        "external_process": True,
        "model_input_path": str(model_input_path),
        "action_trace_path": str(action_trace_path),
    }


def run(url: str, chrome: str, output: Path) -> dict[str, Any]:
    return asyncio.run(run_browser_use(url, chrome, output))


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
