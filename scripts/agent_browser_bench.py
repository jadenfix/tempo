#!/usr/bin/env python3
"""Live browser benchmark harness for agent-oriented Tempo comparisons."""

from __future__ import annotations

import argparse
import http.server
import json
import os
import resource
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "fixtures" / "evals" / "live_agent"
FIXTURE_HTML = FIXTURE_DIR / "checkout.html"
FIXTURE_ACTIONS = FIXTURE_DIR / "checkout-actions.json"
RUNNER_DIR = ROOT / "scripts" / "agent_bench_runners"
SUITE = "live-agent-browser-bench"
CASE_ID = "checkout-submit"
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


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, _format: str, *_args: object) -> None:
        return


class ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


class StaticServer:
    def __init__(self, directory: Path) -> None:
        handler = lambda *args, **kwargs: QuietHandler(  # noqa: E731
            *args,
            directory=str(directory),
            **kwargs,
        )
        self.server = ThreadingServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> "StaticServer":
        self.thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)

    @property
    def base_url(self) -> str:
        host, port = self.server.server_address
        return f"http://{host}:{port}"


class RssSampler:
    def __init__(self, root_pid: int) -> None:
        self.root_pid = root_pid
        self.started = time.monotonic()
        self.max_rss_bytes = 0
        self.rss_at_peak_by_command_bytes: dict[str, int] = {}
        self.peak_rss_by_command_bytes: dict[str, int] = {}
        self.rss_at_peak_by_process_type_bytes: dict[str, int] = {}
        self.peak_rss_by_process_type_bytes: dict[str, int] = {}
        self.rss_peak_elapsed_ms = 0
        self.process_count_at_peak = 0
        self.process_count_at_peak_by_type: dict[str, int] = {}
        self.processes_at_peak: list[dict[str, object]] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def __enter__(self) -> "RssSampler":
        self._thread.start()
        return self

    def __exit__(self, *_exc: object) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self.sample()

    def _run(self) -> None:
        while not self._stop.is_set():
            self.sample()
            self._stop.wait(0.05)

    def sample(self) -> None:
        pids = descendants(self.root_pid)
        if self.root_pid != os.getpid():
            pids.add(self.root_pid)
        rss, by_command, by_process_type, process_count_by_type, processes = rss_snapshot(pids)
        if rss > self.max_rss_bytes:
            self.max_rss_bytes = rss
            self.rss_at_peak_by_command_bytes = by_command
            self.rss_at_peak_by_process_type_bytes = by_process_type
            self.rss_peak_elapsed_ms = int((time.monotonic() - self.started) * 1000)
            self.process_count_at_peak = sum(process_count_by_type.values())
            self.process_count_at_peak_by_type = process_count_by_type
            self.processes_at_peak = processes
        for command, command_rss in by_command.items():
            if command_rss > self.peak_rss_by_command_bytes.get(command, 0):
                self.peak_rss_by_command_bytes[command] = command_rss
        for process_type, process_type_rss in by_process_type.items():
            if process_type_rss > self.peak_rss_by_process_type_bytes.get(process_type, 0):
                self.peak_rss_by_process_type_bytes[process_type] = process_type_rss

    def metric_fields(self) -> dict[str, object]:
        return {
            "rss_at_peak_by_command_bytes": dict(
                sorted(self.rss_at_peak_by_command_bytes.items())
            ),
            "peak_rss_by_command_bytes": dict(
                sorted(self.peak_rss_by_command_bytes.items())
            ),
            "rss_at_peak_by_process_type_bytes": dict(
                sorted(self.rss_at_peak_by_process_type_bytes.items())
            ),
            "peak_rss_by_process_type_bytes": dict(
                sorted(self.peak_rss_by_process_type_bytes.items())
            ),
            "rss_peak_elapsed_ms": self.rss_peak_elapsed_ms,
            "process_count_at_peak": self.process_count_at_peak,
            "process_count_at_peak_by_type": dict(
                sorted(self.process_count_at_peak_by_type.items())
            ),
            "processes_at_peak": self.processes_at_peak,
        }


def descendants(root_pid: int) -> set[int]:
    found: set[int] = set()
    pending = [root_pid]
    while pending:
        parent = pending.pop()
        try:
            completed = subprocess.run(
                ["pgrep", "-P", str(parent)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                check=False,
            )
        except FileNotFoundError:
            return found
        if completed.returncode not in (0, 1):
            continue
        for line in completed.stdout.splitlines():
            try:
                child = int(line.strip())
            except ValueError:
                continue
            if child not in found:
                found.add(child)
                pending.append(child)
    return found


def rss_bytes(pids: set[int]) -> int:
    return rss_snapshot(pids)[0]


def rss_snapshot(
    pids: set[int],
) -> tuple[int, dict[str, int], dict[str, int], dict[str, int], list[dict[str, object]]]:
    if not pids:
        return 0, {}, {}, {}, []
    args_by_pid = process_args_by_pid(pids)
    try:
        completed = subprocess.run(
            [
                "ps",
                "-o",
                "pid=,ppid=,rss=,comm=",
                "-p",
                ",".join(str(pid) for pid in sorted(pids)),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except FileNotFoundError:
        return 0, {}, {}, {}, []
    total_kib = 0
    by_command: dict[str, int] = {}
    by_process_type: dict[str, int] = {}
    process_count_by_type: dict[str, int] = {}
    processes: list[dict[str, object]] = []
    for line in completed.stdout.splitlines():
        fields = line.strip().split(None, 3)
        if len(fields) < 3:
            continue
        try:
            pid = int(fields[0])
            ppid = int(fields[1])
            rss_kib = int(fields[2])
        except ValueError:
            continue
        if rss_kib <= 0:
            continue
        command = fields[3].strip() if len(fields) > 3 else "<unknown>"
        command = Path(command).name or command or "<unknown>"
        args = args_by_pid.get(pid, "")
        process_type = classify_process_type(command, args)
        rss_bytes_for_process = rss_kib * 1024
        total_kib += rss_kib
        by_command[command] = by_command.get(command, 0) + rss_bytes_for_process
        by_process_type[process_type] = (
            by_process_type.get(process_type, 0) + rss_bytes_for_process
        )
        process_count_by_type[process_type] = process_count_by_type.get(process_type, 0) + 1
        processes.append(
            {
                "pid": pid,
                "ppid": ppid,
                "command": command,
                "process_type": process_type,
                "rss_bytes": rss_bytes_for_process,
                "args": truncate_process_args(args),
            }
        )
    return (
        total_kib * 1024,
        dict(sorted(by_command.items())),
        dict(sorted(by_process_type.items())),
        dict(sorted(process_count_by_type.items())),
        sorted(processes, key=lambda process: (str(process["process_type"]), int(process["pid"]))),
    )


def process_args_by_pid(pids: set[int]) -> dict[int, str]:
    try:
        completed = subprocess.run(
            [
                "ps",
                "-o",
                "pid=,args=",
                "-p",
                ",".join(str(pid) for pid in sorted(pids)),
            ],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
        )
    except FileNotFoundError:
        return {}
    args_by_pid: dict[int, str] = {}
    for line in completed.stdout.splitlines():
        fields = line.strip().split(None, 1)
        if len(fields) < 2:
            continue
        try:
            pid = int(fields[0])
        except ValueError:
            continue
        args_by_pid[pid] = fields[1]
    return args_by_pid


def classify_process_type(command: str, args: str) -> str:
    if "tempo-cli" in command:
        return "tempo-cli"
    if "python" in command.lower() or command in {"MainThread"}:
        return "python-harness"
    if command == "node":
        return "playwright-node"
    if "chrome" in command.lower() or "chrome" in args.lower():
        for prefix in ("--type=", " --type="):
            marker = args.find(prefix)
            if marker >= 0:
                process_type = args[marker + len(prefix) :].split()[0].strip()
                return f"chrome-{process_type}" if process_type else "chrome-child"
        return "chrome-browser"
    return command or "<unknown>"


def truncate_process_args(args: str) -> str:
    max_len = 4096
    if len(args) <= max_len:
        return args
    return args[: max_len - 3] + "..."


def estimated_tokens(byte_count: int) -> int:
    return (byte_count + 3) // 4


def now_ms() -> int:
    return time.monotonic_ns() // 1_000_000


def usage_self() -> resource.struct_rusage:
    return resource.getrusage(resource.RUSAGE_SELF)


def usage_children() -> resource.struct_rusage:
    return resource.getrusage(resource.RUSAGE_CHILDREN)


def usage_delta(before: resource.struct_rusage, after: resource.struct_rusage) -> dict:
    return {
        "cpu_user_ms": int((after.ru_utime - before.ru_utime) * 1000),
        "cpu_system_ms": int((after.ru_stime - before.ru_stime) * 1000),
        "max_rss_bytes": max_rss_bytes(after),
    }


def combined_usage_delta(
    before_self: resource.struct_rusage,
    before_children: resource.struct_rusage,
    after_self: resource.struct_rusage,
    after_children: resource.struct_rusage,
) -> dict:
    return {
        "cpu_user_ms": int(
            (
                after_self.ru_utime
                + after_children.ru_utime
                - before_self.ru_utime
                - before_children.ru_utime
            )
            * 1000
        ),
        "cpu_system_ms": int(
            (
                after_self.ru_stime
                + after_children.ru_stime
                - before_self.ru_stime
                - before_children.ru_stime
            )
            * 1000
        ),
        "max_rss_bytes": max(max_rss_bytes(after_self), max_rss_bytes(after_children)),
    }


def max_rss_bytes(usage: resource.struct_rusage) -> int:
    if sys.platform == "darwin":
        return int(usage.ru_maxrss)
    return int(usage.ru_maxrss) * 1024


def run_checked(cmd: list[str], env: dict[str, str]) -> None:
    subprocess.run(cmd, cwd=ROOT, env=env, check=True)


def tempo_cli_command(*args: str) -> list[str]:
    tempo_cli = os.environ.get("TEMPO_CLI")
    if tempo_cli:
        return [tempo_cli, *args]
    return ["cargo", "run", "-p", "tempo-cli", "--", *args]


def chrome_version(chrome: str) -> str:
    try:
        completed = subprocess.run(
            [chrome, "--version"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=10,
        )
    except Exception as error:  # noqa: BLE001
        return f"unknown: {type(error).__name__}"
    return completed.stdout.strip() or f"unknown: exit_{completed.returncode}"


def run_tempo(url: str, chrome: str, output_dir: Path) -> dict:
    journal = output_dir / "tempo-journal.sqlite"
    run_report = output_dir / "tempo-run.json"
    env = os.environ.copy()
    env["TEMPO_CDP_CHROME"] = chrome
    env.setdefault("TEMPO_CDP_NO_SANDBOX", "1")
    env.setdefault("TEMPO_DURABLE_RETENTION", "plaintext-unsafe")
    before = usage_children()
    started = now_ms()
    cmd = tempo_cli_command(
        "run-cdp-task",
        "--start-url",
        url,
        "--actions",
        str(FIXTURE_ACTIONS),
        "--journal",
        str(journal),
        "--output",
        str(run_report),
        "--chrome",
        chrome,
        "--allow-private-network",
        "--confirmation-mode",
        "auto-clean",
    )
    failure_mode = None
    proc = subprocess.Popen(cmd, cwd=ROOT, env=env)
    with RssSampler(proc.pid) as sampler:
        returncode = proc.wait()
    if returncode != 0:
        failure_mode = f"exit_{returncode}"
    wall = now_ms() - started
    usage = usage_delta(before, usage_children())
    usage["max_rss_bytes"] = sampler.max_rss_bytes
    usage.update(sampler.metric_fields())
    report = {}
    if run_report.exists():
        report = json.loads(run_report.read_text())
    if "model_input_observations" not in report:
        raise RuntimeError("tempo run report missing model_input_observations")
    success = report.get("status", {}).get("state") in {"completed", "already_complete"}
    metric = {
        "runner": "tempo-cdp-agent",
        "suite": SUITE,
        "case_id": CASE_ID,
        "success": bool(success),
        "wall_clock_ms": wall,
        "step_count": int(report.get("actions_completed", 0)),
        "retry_count": 0,
        "failure_mode": failure_mode,
        "model_input_bytes": int(
            report.get(
                "total_model_input_bytes",
                report.get("max_model_input_bytes", report.get("max_observation_bytes", 0)),
            )
        ),
        "model_input_tokens": int(
            report.get(
                "total_model_input_tokens",
                report.get("max_model_input_tokens", report.get("max_observation_tokens", 0)),
            )
        ),
        "max_observation_bytes": int(report.get("max_observation_bytes", 0)),
        "max_observation_tokens": int(report.get("max_observation_tokens", 0)),
        "max_compact_observation_bytes": int(
            report.get("max_compact_observation_bytes", report.get("max_model_input_bytes", 0))
        ),
        "max_compact_observation_tokens": int(
            report.get("max_compact_observation_tokens", report.get("max_model_input_tokens", 0))
        ),
        "max_model_input_bytes": int(
            report.get("max_model_input_bytes", report.get("max_observation_bytes", 0))
        ),
        "max_model_input_tokens": int(
            report.get("max_model_input_tokens", report.get("max_observation_tokens", 0))
        ),
        "total_model_input_bytes": int(
            report.get(
                "total_model_input_bytes",
                report.get("max_model_input_bytes", report.get("max_observation_bytes", 0)),
            )
        ),
        "total_model_input_tokens": int(
            report.get(
                "total_model_input_tokens",
                report.get("max_model_input_tokens", report.get("max_observation_tokens", 0)),
            )
        ),
        "observations": int(report.get("observations", 0)),
        "model_input_observations": int(report["model_input_observations"]),
        "journal": str(journal),
        "run_report": str(run_report),
        "tempo_cli": cmd[0],
        "tempo_cli_prebuilt": cmd[0] != "cargo",
    }
    metric.update(usage)
    return metric


def checkout_expression() -> str:
    return """
        (() => {
          const email = document.querySelector('#email');
          email.value = 'agent@example.com';
          email.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText', data: email.value }));
          document.querySelector('#remember').click();
          document.querySelector('#pay').click();
          return document.querySelector('#status').dataset.done === 'true';
        })()
        """


def browser_use_snapshot_expression() -> str:
    return r"""
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
      const lines = ['[Start of page]'];
      Array.from(document.querySelectorAll('main *')).forEach((element, index) => {
        if (!isInteractive(element)) return;
        lines.push(`[${index}]<${roleFor(element)}>${nameFor(element)}</${roleFor(element)}>`);
      });
      lines.push('[End of page]');
      return lines.join('\n');
    })()
    """


def run_cdp_baseline(chrome: str, url: str, runner: str, snapshot: str | None) -> dict:
    from playwright.sync_api import sync_playwright

    before_self = usage_self()
    before_children = usage_children()
    started = now_ms()
    failure_mode = None
    model_input = ""
    success = False
    with RssSampler(os.getpid()) as sampler:
        try:
            args = ["--disable-gpu", "--disable-dev-shm-usage", "--use-mock-keychain"]
            if os.environ.get("TEMPO_CDP_NO_SANDBOX") == "1":
                args.append("--no-sandbox")
            with sync_playwright() as playwright:
                with tempfile.TemporaryDirectory(prefix=f"tempo-{runner}-profile-") as profile_dir:
                    context = playwright.chromium.launch_persistent_context(
                        user_data_dir=profile_dir,
                        executable_path=chrome,
                        headless=True,
                        args=args,
                    )
                    try:
                        page = context.new_page()
                        page.goto(url, wait_until="load", timeout=15000)
                        cdp = page.context.new_cdp_session(page)
                        cdp.send("Runtime.enable")
                        cdp.send("Accessibility.enable")
                        if snapshot == "ax":
                            tree = cdp.send("Accessibility.getFullAXTree")
                            lines: list[str] = []
                            for node in tree.get("nodes", []):
                                role = node.get("role", {}).get("value")
                                name = node.get("name", {}).get("value", "")
                                if role and name:
                                    lines.append(f'- {role} "{name}"')
                            model_input = "\n".join(lines)
                        elif snapshot == "browser_use_dom":
                            model_input = str(page.evaluate(browser_use_snapshot_expression()))
                        result = cdp.send(
                            "Runtime.evaluate",
                            {
                                "expression": checkout_expression(),
                                "returnByValue": True,
                                "awaitPromise": True,
                            },
                        )
                        if "exceptionDetails" in result:
                            raise RuntimeError(f"runtime exception: {result['exceptionDetails']}")
                        success = bool(
                            page.evaluate(
                                "document.querySelector('#status').dataset.done === 'true'"
                            )
                        )
                    finally:
                        context.close()
        except Exception as error:  # noqa: BLE001
            failure_mode = type(error).__name__
    wall = now_ms() - started
    usage = combined_usage_delta(before_self, before_children, usage_self(), usage_children())
    usage["max_rss_bytes"] = sampler.max_rss_bytes
    usage.update(sampler.metric_fields())
    byte_count = len(model_input.encode("utf-8"))
    metric = {
        "runner": runner,
        "suite": SUITE,
        "case_id": CASE_ID,
        "success": success,
        "wall_clock_ms": wall,
        "step_count": 3,
        "retry_count": 0,
        "failure_mode": failure_mode,
        "model_input_bytes": byte_count,
        "model_input_tokens": estimated_tokens(byte_count),
        "observations": 1 if snapshot else 0,
        "model_input_observations": 1 if snapshot else 0,
        "adapter": "playwright-cdp-session",
    }
    if snapshot:
        metric.update(
            {
                "total_model_input_bytes": byte_count,
                "total_model_input_tokens": estimated_tokens(byte_count),
                "max_observation_bytes": byte_count,
                "max_observation_tokens": estimated_tokens(byte_count),
            }
        )
    metric.update(usage)
    return metric


def run_external_baseline(
    chrome: str,
    url: str,
    runner: str,
    script_name: str,
    output_dir: Path,
) -> dict:
    report_path = output_dir / f"{runner}.json"
    stdout_path = output_dir / f"{runner}.stdout.log"
    stderr_path = output_dir / f"{runner}.stderr.log"
    script_path = RUNNER_DIR / script_name
    env = os.environ.copy()
    env.setdefault("TEMPO_CDP_NO_SANDBOX", "1")
    before = usage_children()
    started = now_ms()
    failure_mode = None
    proc = subprocess.Popen(
        [
            sys.executable,
            str(script_path),
            "--url",
            url,
            "--chrome",
            chrome,
            "--output",
            str(report_path),
        ],
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    with RssSampler(proc.pid) as sampler:
        stdout, stderr = proc.communicate()
    completed_returncode = proc.returncode
    stdout_path.write_text(stdout)
    stderr_path.write_text(stderr)
    if completed_returncode != 0:
        failure_mode = f"exit_{completed_returncode}"
    wall = now_ms() - started
    usage = usage_delta(before, usage_children())
    report: dict = {}
    if report_path.exists():
        report = json.loads(report_path.read_text())
        if report.get("failure_mode") and failure_mode is None:
            failure_mode = str(report["failure_mode"])
    else:
        failure_mode = failure_mode or "missing_report"
    success = completed_returncode == 0 and bool(report.get("success"))
    metric = {
        "runner": runner,
        "suite": SUITE,
        "case_id": CASE_ID,
        "success": success,
        "wall_clock_ms": wall,
        "child_wall_clock_ms": int(report.get("wall_clock_ms", 0)),
        "step_count": int(report.get("step_count", 0)),
        "retry_count": int(report.get("retry_count", 0)),
        "failure_mode": failure_mode,
        "model_input_bytes": int(report.get("model_input_bytes", 0)),
        "model_input_tokens": int(report.get("model_input_tokens", 0)),
        "observations": int(report.get("observations", 0)),
        "model_input_observations": int(
            report.get("model_input_observations", report.get("observations", 0))
        ),
        "adapter": str(report.get("adapter", script_name)),
        "external_process": True,
        "runner_report": str(report_path),
        "runner_stdout": str(stdout_path),
        "runner_stderr": str(stderr_path),
    }
    if "total_model_input_bytes" in report:
        metric["total_model_input_bytes"] = int(report["total_model_input_bytes"])
    if "total_model_input_tokens" in report:
        metric["total_model_input_tokens"] = int(report["total_model_input_tokens"])
    if "max_observation_bytes" in report:
        metric["max_observation_bytes"] = int(report["max_observation_bytes"])
    if "max_observation_tokens" in report:
        metric["max_observation_tokens"] = int(report["max_observation_tokens"])
    for key in ("model_input_path", "action_trace_path"):
        if key in report:
            metric[key] = str(report[key])
    metric.update(usage)
    metric["max_rss_bytes"] = sampler.max_rss_bytes
    metric.update(sampler.metric_fields())
    return metric


def write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def write_jsonl(path: Path, values: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as file:
        for value in values:
            file.write(json.dumps(value, sort_keys=True) + "\n")


def clean_output_dir(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for child in output_dir.glob("iteration-*"):
        if child.is_dir():
            shutil.rmtree(child)
    for name in [
        "agent-browser-bench.json",
        "agent-browser-bench.jsonl",
        "agent-browser-bench-gaps.json",
        "agent-browser-bench-summary.json",
        "amdahl.json",
        "eval-records.jsonl",
        "replay.json",
        "scorecard.json",
        "tempo-eval-record.json",
        "tempo-journal.sqlite",
        "tempo-journal.sqlite-shm",
        "tempo-journal.sqlite-wal",
        "tempo-journal.sqlite.lock",
        "tempo-run.json",
        "chrome-version.txt",
        "real-playwright.json",
        "real-playwright.stdout.log",
        "real-playwright.stderr.log",
        "real-playwright.model-input.txt",
        "real-playwright.trace.json",
        "external-browser-use-dom-loop.json",
        "external-browser-use-dom-loop.stdout.log",
        "external-browser-use-dom-loop.stderr.log",
        "external-browser-use-dom-loop.model-input.txt",
        "external-browser-use-dom-loop.trace.json",
        "real-browser-use.json",
        "real-browser-use.stdout.log",
        "real-browser-use.stderr.log",
        "real-browser-use.model-input.txt",
        "real-browser-use.trace.json",
    ]:
        path = output_dir / name
        if path.exists():
            path.unlink()


def percentile(values: list[int], pct: float) -> int:
    if not values:
        return 0
    values = sorted(values)
    if len(values) == 1:
        return values[0]
    index = round((len(values) - 1) * pct)
    return values[max(0, min(index, len(values) - 1))]


def summarize_metrics(metrics: list[dict]) -> dict:
    runners = sorted({str(metric["runner"]) for metric in metrics})
    summary = {}
    for runner in runners:
        runner_metrics = [metric for metric in metrics if metric["runner"] == runner]
        successes = [metric for metric in runner_metrics if metric["success"]]
        failure_modes: dict[str, int] = {}
        for metric in runner_metrics:
            mode = metric.get("failure_mode")
            if mode:
                failure_modes[str(mode)] = failure_modes.get(str(mode), 0) + 1
        summary[runner] = {
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
            "model_input_observations": summarize_int_field(
                runner_metrics, "model_input_observations"
            ),
            "step_count": summarize_int_field(runner_metrics, "step_count"),
            "retry_count_total": sum(int(metric.get("retry_count", 0)) for metric in runner_metrics),
        }
        if any("total_model_input_bytes" in metric for metric in runner_metrics):
            summary[runner]["total_model_input_bytes"] = summarize_int_field(
                runner_metrics, "total_model_input_bytes"
            )
        if any("total_model_input_tokens" in metric for metric in runner_metrics):
            summary[runner]["total_model_input_tokens"] = summarize_int_field(
                runner_metrics, "total_model_input_tokens"
            )
        if any("max_observation_bytes" in metric for metric in runner_metrics):
            summary[runner]["max_observation_bytes"] = summarize_int_field(
                runner_metrics, "max_observation_bytes"
            )
        if any("max_observation_tokens" in metric for metric in runner_metrics):
            summary[runner]["max_observation_tokens"] = summarize_int_field(
                runner_metrics, "max_observation_tokens"
            )
        if any("max_compact_observation_bytes" in metric for metric in runner_metrics):
            summary[runner]["max_compact_observation_bytes"] = summarize_int_field(
                runner_metrics, "max_compact_observation_bytes"
            )
        if any("max_compact_observation_tokens" in metric for metric in runner_metrics):
            summary[runner]["max_compact_observation_tokens"] = summarize_int_field(
                runner_metrics, "max_compact_observation_tokens"
            )
        if any("max_model_input_bytes" in metric for metric in runner_metrics):
            summary[runner]["max_model_input_bytes"] = summarize_int_field(
                runner_metrics, "max_model_input_bytes"
            )
        if any("max_model_input_tokens" in metric for metric in runner_metrics):
            summary[runner]["max_model_input_tokens"] = summarize_int_field(
                runner_metrics, "max_model_input_tokens"
            )
    return summary


def validate_summary(summary: dict, args: argparse.Namespace) -> list[str]:
    violations = []
    for runner, runner_summary in summary.items():
        success_rate = float(runner_summary["success_rate"])
        if args.min_success_rate is not None and success_rate < args.min_success_rate:
            violations.append(
                f"{runner}: success_rate {success_rate:.3f} < {args.min_success_rate:.3f}"
            )
        wall_p95 = int(runner_summary["wall_clock_ms"]["p95"])
        if args.max_p95_wall_ms is not None and wall_p95 > args.max_p95_wall_ms:
            violations.append(f"{runner}: wall_clock_ms.p95 {wall_p95} > {args.max_p95_wall_ms}")
        tokens_p95 = int(runner_summary["model_input_tokens"]["p95"])
        if (
            args.max_p95_model_input_tokens is not None
            and tokens_p95 > args.max_p95_model_input_tokens
        ):
            violations.append(
                f"{runner}: model_input_tokens.p95 {tokens_p95} > "
                f"{args.max_p95_model_input_tokens}"
            )
        rss_p95 = int(runner_summary["max_rss_bytes"]["p95"])
        if args.max_p95_rss_bytes is not None and rss_p95 > args.max_p95_rss_bytes:
            violations.append(f"{runner}: max_rss_bytes.p95 {rss_p95} > {args.max_p95_rss_bytes}")
    return violations


def summarize_int_field(metrics: list[dict], field: str) -> dict:
    values = [int(metric.get(field, 0)) for metric in metrics]
    return {
        "min": min(values) if values else 0,
        "p50": percentile(values, 0.50),
        "p95": percentile(values, 0.95),
        "max": max(values) if values else 0,
    }


def benchmark_gap_report(metrics: list[dict], summary: dict) -> dict:
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
        ("wall_clock_ms_p95", "lower_is_better", runners),
        ("max_rss_bytes_p95", "lower_is_better", runners),
        ("retry_count_total", "lower_is_better", runners),
        ("failure_count", "lower_is_better", runners),
        (
            "model_input_tokens_p95",
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
        participants = [runner for runner in category_runners if runner in row_by_runner]
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
        "suite": SUITE,
        "case_id": CASE_ID,
        "tempo_runner": TEMPO_RUNNER,
        "baseline_runner": RAW_CHROME_RUNNER,
        "agent_style_runners": sorted(AGENT_STYLE_RUNNERS),
        "comparison_notes": [
            "raw-chrome-cdp is excluded from observation-token and agent-step categories because it has no model-facing observation stream.",
            "model_input_tokens_p95 ranks the full model-facing stream each runner presents to an agent; compact_observation_tokens_p95 ranks the largest compact observation projection per run.",
            "max_observation_tokens_p95 keeps Tempo's full durable structured audit JSON cost visible and is intentionally separate from compact model-facing projections.",
            "max_observation_tokens_p95 compares the largest single durable observation per run; total_model_input_tokens_p95 is row-level only until every agent runner records true total stream cost.",
            "cpu_time_ms_p95 is row-level only until every runner uses the same resource-accounting scope.",
            "Positive deltas mean Tempo is behind that comparison target; negative deltas mean Tempo is ahead.",
        ],
        "rows": rows,
        "categories": categories,
        "gaps_to_close": gaps_to_close,
    }


def comparison_row(runner: str, runner_summary: dict, runner_metrics: list[dict]) -> dict:
    return {
        "runner": runner,
        "runs": int(runner_summary["runs"]),
        "success_rate": float(runner_summary["success_rate"]),
        "failure_count": sum(int(count) for count in runner_summary["failure_modes"].values()),
        "retry_count_total": int(runner_summary["retry_count_total"]),
        "wall_clock_ms_p50": int(runner_summary["wall_clock_ms"]["p50"]),
        "wall_clock_ms_p95": int(runner_summary["wall_clock_ms"]["p95"]),
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
        "step_count_p95": int(runner_summary["step_count"]["p95"]),
    }


def category_sort_key(entry: dict, direction: str) -> tuple[float, str]:
    value = float(entry["value"])
    if direction == "higher_is_better":
        return (-value, str(entry["runner"]))
    return (value, str(entry["runner"]))


def comparison_delta(tempo_value: int | float, target_value: int | float, direction: str) -> int | float:
    if direction == "higher_is_better":
        return target_value - tempo_value
    return tempo_value - target_value


def optional_percentile(values: list[int | None], pct: float) -> int | None:
    concrete = [int(value) for value in values if value is not None]
    if len(concrete) != len(values):
        return None
    return percentile(concrete, pct)


def comparable_total_model_input_tokens(metric: dict) -> int | None:
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


def comparable_compact_observation_tokens(metric: dict) -> int:
    if "max_compact_observation_tokens" in metric:
        return int(metric["max_compact_observation_tokens"])
    return int(metric.get("max_observation_tokens", metric.get("model_input_tokens", 0)))


def comparison_rank(tempo_value: int | float, ranked: list[dict], direction: str) -> int:
    if direction == "higher_is_better":
        return 1 + sum(1 for entry in ranked if entry["value"] > tempo_value)
    return 1 + sum(1 for entry in ranked if entry["value"] < tempo_value)


def derive_artifacts(output_dir: Path, metrics: list[dict], url: str) -> None:
    env = os.environ.copy()
    env.setdefault("TEMPO_DURABLE_RETENTION", "plaintext-unsafe")
    tempo = next((metric for metric in metrics if metric["runner"] == TEMPO_RUNNER), None)
    chrome = next((metric for metric in metrics if metric["runner"] == RAW_CHROME_RUNNER), None)
    if tempo is None:
        return
    journal = Path(str(tempo["journal"]))
    baseline_wall = int(chrome["wall_clock_ms"]) if chrome else 0
    eval_record = output_dir / "tempo-eval-record.json"
    run_checked(
        tempo_cli_command(
            "session-eval",
            "--journal",
            str(journal),
            "--suite",
            SUITE,
            "--case-id",
            CASE_ID,
            "--origin",
            url,
            "--lane",
            "cdp",
            "--success",
            "true" if tempo["success"] else "false",
            "--fallback-used",
            "false",
            "--baseline-wall-clock-ms",
            str(baseline_wall),
            "--output",
            str(eval_record),
        ),
        env,
    )
    record = json.loads(eval_record.read_text())
    records = output_dir / "eval-records.jsonl"
    records.write_text(json.dumps(record, sort_keys=True) + "\n")
    run_checked(
        tempo_cli_command(
            "replay",
            "--journal",
            str(journal),
            "--output",
            str(output_dir / "replay.json"),
        ),
        env,
    )
    run_checked(
        tempo_cli_command(
            "scorecard",
            "--input",
            str(records),
            "--output",
            str(output_dir / "scorecard.json"),
            "--allow-missing-speculation",
        ),
        env,
    )
    write_json(output_dir / "amdahl.json", amdahl_summary(metrics))


def amdahl_summary(metrics: list[dict]) -> dict:
    baseline = next((metric for metric in metrics if metric["runner"] == "raw-chrome-cdp"), None)
    baseline_wall_ms = int(baseline["wall_clock_ms"]) if baseline else 0
    rows = []
    for metric in metrics:
        wall_ms = int(metric.get("wall_clock_ms", 0))
        rows.append(
            {
                "runner": metric["runner"],
                "wall_clock_ms": wall_ms,
                "baseline_wall_clock_ms": baseline_wall_ms,
                "relative_wall_clock": (
                    wall_ms / baseline_wall_ms if baseline_wall_ms > 0 else None
                ),
                "agent_overhead_ms": wall_ms - baseline_wall_ms if baseline_wall_ms > 0 else None,
                "model_input_tokens": int(metric.get("model_input_tokens", 0)),
                "model_input_observations": int(
                    metric.get("model_input_observations", metric.get("observations", 0))
                ),
                "success": bool(metric.get("success")),
            }
        )
    return {
        "suite": SUITE,
        "case_id": CASE_ID,
        "baseline_runner": RAW_CHROME_RUNNER,
        "baseline_wall_clock_ms": baseline_wall_ms,
        "rows": rows,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--full", action="store_true")
    parser.add_argument(
        "--iterations",
        type=int,
        default=None,
        help="number of benchmark iterations; defaults to 1 for smoke and 5 for --full",
    )
    parser.add_argument("--min-success-rate", type=float, default=None)
    parser.add_argument("--max-p95-wall-ms", type=int, default=None)
    parser.add_argument("--max-p95-model-input-tokens", type=int, default=None)
    parser.add_argument("--max-p95-rss-bytes", type=int, default=None)
    parser.add_argument("--chrome", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    if not FIXTURE_HTML.exists():
        raise RuntimeError(f"missing fixture: {FIXTURE_HTML}")

    output_dir = Path(args.output_dir)
    clean_output_dir(output_dir)
    iterations = args.iterations if args.iterations is not None else (5 if args.full else 1)
    if iterations < 1:
        raise RuntimeError("--iterations must be >= 1")
    resolved_chrome_version = chrome_version(args.chrome)

    with StaticServer(FIXTURE_DIR) as server:
        url = f"{server.base_url}/checkout.html"
        metrics = []
        for iteration in range(1, iterations + 1):
            iteration_dir = output_dir if iterations == 1 else output_dir / f"iteration-{iteration:03d}"
            clean_output_dir(iteration_dir)
            iteration_metrics = [
                run_tempo(url, args.chrome, iteration_dir),
                run_cdp_baseline(args.chrome, url, "raw-chrome-cdp", None),
                run_cdp_baseline(args.chrome, url, "synthetic-playwright-ax", "ax"),
                run_cdp_baseline(args.chrome, url, "synthetic-browser-use-dom", "browser_use_dom"),
                run_external_baseline(
                    args.chrome,
                    url,
                    "real-playwright",
                    "playwright_checkout.py",
                    iteration_dir,
                ),
                run_external_baseline(
                    args.chrome,
                    url,
                    "external-browser-use-dom-loop",
                    "browser_use_dom_loop.py",
                    iteration_dir,
                ),
                run_external_baseline(
                    args.chrome,
                    url,
                    "real-browser-use",
                    "browser_use_package.py",
                    iteration_dir,
                ),
            ]
            for metric in iteration_metrics:
                metric["iteration"] = iteration
            write_json(
                iteration_dir / "agent-browser-bench.json",
                {
                    "url": url,
                    "iteration": iteration,
                    "chrome": args.chrome,
                    "chrome_version": resolved_chrome_version,
                    "metrics": iteration_metrics,
                },
            )
            write_jsonl(iteration_dir / "agent-browser-bench.jsonl", iteration_metrics)
            derive_artifacts(iteration_dir, iteration_metrics, url)
            metrics.extend(iteration_metrics)
        summary = summarize_metrics(metrics)
        write_json(
            output_dir / "agent-browser-bench.json",
            {
                "url": url,
                "iterations": iterations,
                "chrome": args.chrome,
                "chrome_version": resolved_chrome_version,
                "metrics": metrics,
                "summary": summary,
            },
        )
        write_jsonl(output_dir / "agent-browser-bench.jsonl", metrics)
        write_json(output_dir / "agent-browser-bench-summary.json", summary)
        write_json(output_dir / "agent-browser-bench-gaps.json", benchmark_gap_report(metrics, summary))
        write_json(
            output_dir / "chrome-version.txt",
            {"chrome": args.chrome, "version": resolved_chrome_version},
        )

    violations = validate_summary(summary, args)
    if violations:
        print(json.dumps({"violations": violations}, indent=2), file=sys.stderr)
        return 1
    failures = [metric for metric in metrics if not metric["success"]]
    if failures:
        print(json.dumps({"failed": failures}, indent=2), file=sys.stderr)
        return 1
    print(f"agent browser benchmark artifacts: {output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
