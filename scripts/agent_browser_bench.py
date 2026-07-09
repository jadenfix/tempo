#!/usr/bin/env python3
"""Live browser benchmark harness for agent-oriented Tempo comparisons."""

from __future__ import annotations

import argparse
import http.server
import json
import os
import resource
import shutil
import sqlite3
import socketserver
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from pathlib import Path

from agent_bench_status import STATUS_ARTIFACT, render_status_markdown


ROOT = Path(__file__).resolve().parents[1]
PROC_ROOT = Path(os.environ.get("TEMPO_PROC_ROOT", "/proc"))
FIXTURE_DIR = ROOT / "fixtures" / "evals" / "live_agent"
FIXTURE_HTML = FIXTURE_DIR / "checkout.html"
FIXTURE_ACTIONS = FIXTURE_DIR / "checkout-actions.json"
RUNNER_DIR = ROOT / "scripts" / "agent_bench_runners"
SUITE = "live-agent-browser-bench"
CASE_ID = "checkout-submit"
TEMPO_RUNNER = "tempo-cdp-agent"
RAW_CHROME_RUNNER = "raw-chrome-cdp"
DEFAULT_RUNNER_ORDER = (
    "tempo-cdp-agent",
    "raw-chrome-cdp",
    "synthetic-playwright-ax",
    "synthetic-browser-use-dom",
    "real-playwright",
    "external-browser-use-dom-loop",
    "real-browser-use",
)
AGENT_STYLE_RUNNERS = {
    "tempo-cdp-agent",
    "synthetic-playwright-ax",
    "synthetic-browser-use-dom",
    "real-playwright",
    "external-browser-use-dom-loop",
    "real-browser-use",
}
TEMPO_RUNTIME_FLAVORS = {"multi-thread", "current-thread"}
BROWSER_PERFORMANCE_METRIC_NAMES = [
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
]
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
TEMPO_CDP_OBSERVATION_COUNTER_FIELDS = (
    "snapshot_since_count",
    "record_snapshot_count",
    "ax_full_tree_count",
    "ax_partial_tree_count",
    "observe_count",
    "observe_diff_count",
    "act_batch_count",
)
RANKED_WEB_PERFORMANCE_ROW_FIELDS = (
    "web_navigation_duration_ms_p95",
    "web_fetch_start_ms_p95",
    "web_request_start_ms_p95",
    "web_response_start_ms_p95",
    "web_response_end_ms_p95",
    "web_dom_interactive_ms_p95",
    "web_dom_content_loaded_start_ms_p95",
    "web_dom_content_loaded_ms_p95",
    "web_dom_complete_ms_p95",
    "web_load_event_start_ms_p95",
    "web_load_event_ms_p95",
    "web_resource_duration_ms_p95",
    "web_resource_max_duration_ms_p95",
    "web_resource_response_end_ms_p95",
    "web_first_paint_ms_p95",
    "web_first_contentful_paint_ms_p95",
    "web_long_task_count_p95",
    "web_long_task_duration_ms_p95",
    "web_long_task_max_duration_ms_p95",
)
CHECKOUT_ORACLE_EMAIL = "agent@example.com"
CHECKOUT_ORACLE_STATUS = "Order submitted"
ALLOW_UNSAFE_HOST_ENV = "TEMPO_AGENT_BENCH_ALLOW_UNSAFE_HOST_ENV"
UNSAFE_HOST_ENV_KEYS = {
    "ANTHROPIC_API_KEY",
    "AWS_ACCESS_KEY_ID",
    "AWS_PROFILE",
    "AWS_ROLE_ARN",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_WEB_IDENTITY_TOKEN_FILE",
    "GOOGLE_API_KEY",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "OPENAI_API_KEY",
    "TEMPO_DURABLE_ENCRYPTION_KEY_HEX",
    "TEMPO_OTLP_ENDPOINT",
    "TEMPO_OTLP_JSONL",
    "TEMPO_TEMPOD_AUTH_TOKEN",
    "TEMPO_TEMPOD_AUTH_TOKEN_FILE",
    "TEMPO_THREAT_DOMAIN_AUDIT_JSONL",
    "TEMPO_THREAT_DOMAIN_CACHE_FILE",
    "TEMPO_THREAT_DOMAIN_FAILURE_MODE",
    "TEMPO_THREAT_DOMAIN_FILE",
    "TEMPO_THREAT_DOMAIN_MAX_STALE_SECONDS",
    "TEMPO_THREAT_DOMAIN_METADATA_CACHE_FILE",
    "TEMPO_THREAT_DOMAIN_METADATA_URL",
    "TEMPO_THREAT_DOMAIN_PUBLIC_KEYS",
    "TEMPO_THREAT_DOMAIN_REFRESH_INTERVAL_SECONDS",
    "TEMPO_THREAT_DOMAIN_SHA256",
    "TEMPO_THREAT_DOMAIN_URL",
}


class QuietHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, _format: str, *_args: object) -> None:
        return


class ThreadingServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True


def unsafe_host_env_keys() -> list[str]:
    return sorted(key for key in UNSAFE_HOST_ENV_KEYS if os.environ.get(key))


def assert_safe_benchmark_environment() -> None:
    if os.environ.get(ALLOW_UNSAFE_HOST_ENV) == "1":
        return
    present = unsafe_host_env_keys()
    if present:
        joined = ", ".join(present)
        raise RuntimeError(
            "refusing to run browser benchmark with ambient production/secret env vars: "
            f"{joined}. Unset them, or set {ALLOW_UNSAFE_HOST_ENV}=1 for an intentional "
            "unsafe-env run."
        )


def benchmark_child_env() -> dict[str, str]:
    env = os.environ.copy()
    if os.environ.get(ALLOW_UNSAFE_HOST_ENV) != "1":
        for key in UNSAFE_HOST_ENV_KEYS:
            env.pop(key, None)
    return env


def path_is_under(path: Path, parent: Path) -> bool:
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def assert_safe_output_dir(output_dir: Path) -> None:
    if os.environ.get(ALLOW_UNSAFE_HOST_ENV) == "1":
        return
    allowed_roots = [
        ROOT / "target",
        Path(tempfile.gettempdir()),
        Path("/tmp"),
    ]
    if not any(path_is_under(output_dir, allowed_root) for allowed_root in allowed_roots):
        roots = ", ".join(str(root.resolve()) for root in allowed_roots)
        raise RuntimeError(
            f"refusing to clean/write browser benchmark output outside safe roots: {output_dir}. "
            f"Allowed roots: {roots}. Set {ALLOW_UNSAFE_HOST_ENV}=1 for an intentional "
            "unsafe-output run."
        )


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
        self.max_pss_bytes = 0
        self.max_uss_bytes = 0
        self.pss_at_peak_by_process_type_bytes: dict[str, int] = {}
        self.uss_at_peak_by_process_type_bytes: dict[str, int] = {}
        self.peak_pss_by_process_type_bytes: dict[str, int] = {}
        self.peak_uss_by_process_type_bytes: dict[str, int] = {}
        self.rss_peak_elapsed_ms = 0
        self.max_process_count = 0
        self.max_process_count_by_type: dict[str, int] = {}
        self.processes_at_max_count: list[dict[str, object]] = []
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
        pids.add(self.root_pid)
        rss, by_command, by_process_type, process_count_by_type, processes = rss_snapshot(pids)
        process_type_by_pid = {
            int(process["pid"]): str(process["process_type"]) for process in processes
        }
        pss, uss, pss_by_process_type, uss_by_process_type = pss_uss_snapshot(
            pids,
            process_type_by_pid,
        )
        process_count = sum(process_count_by_type.values())
        if process_count > self.max_process_count:
            self.max_process_count = process_count
            self.max_process_count_by_type = process_count_by_type
            self.processes_at_max_count = processes
        if rss > self.max_rss_bytes:
            self.max_rss_bytes = rss
            self.rss_at_peak_by_command_bytes = by_command
            self.rss_at_peak_by_process_type_bytes = by_process_type
            self.rss_peak_elapsed_ms = int((time.monotonic() - self.started) * 1000)
            self.process_count_at_peak = process_count
            self.process_count_at_peak_by_type = process_count_by_type
            self.processes_at_peak = processes
        for command, command_rss in by_command.items():
            if command_rss > self.peak_rss_by_command_bytes.get(command, 0):
                self.peak_rss_by_command_bytes[command] = command_rss
        for process_type, process_type_rss in by_process_type.items():
            if process_type_rss > self.peak_rss_by_process_type_bytes.get(process_type, 0):
                self.peak_rss_by_process_type_bytes[process_type] = process_type_rss
        if pss > self.max_pss_bytes:
            self.max_pss_bytes = pss
            self.pss_at_peak_by_process_type_bytes = pss_by_process_type
        if uss > self.max_uss_bytes:
            self.max_uss_bytes = uss
            self.uss_at_peak_by_process_type_bytes = uss_by_process_type
        for process_type, process_type_pss in pss_by_process_type.items():
            if process_type_pss > self.peak_pss_by_process_type_bytes.get(process_type, 0):
                self.peak_pss_by_process_type_bytes[process_type] = process_type_pss
        for process_type, process_type_uss in uss_by_process_type.items():
            if process_type_uss > self.peak_uss_by_process_type_bytes.get(process_type, 0):
                self.peak_uss_by_process_type_bytes[process_type] = process_type_uss

    def metric_fields(self) -> dict[str, object]:
        return {
            "sampler_root_pid": self.root_pid,
            "sampler_root_included": True,
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
            "max_pss_bytes": self.max_pss_bytes,
            "max_uss_bytes": self.max_uss_bytes,
            "pss_at_peak_by_process_type_bytes": dict(
                sorted(self.pss_at_peak_by_process_type_bytes.items())
            ),
            "uss_at_peak_by_process_type_bytes": dict(
                sorted(self.uss_at_peak_by_process_type_bytes.items())
            ),
            "peak_pss_by_process_type_bytes": dict(
                sorted(self.peak_pss_by_process_type_bytes.items())
            ),
            "peak_uss_by_process_type_bytes": dict(
                sorted(self.peak_uss_by_process_type_bytes.items())
            ),
            "rss_peak_elapsed_ms": self.rss_peak_elapsed_ms,
            "max_process_count": self.max_process_count,
            "max_process_count_by_type": dict(sorted(self.max_process_count_by_type.items())),
            "processes_at_max_count": self.processes_at_max_count,
            "process_count_at_peak": self.process_count_at_peak,
            "process_count_at_peak_by_type": dict(
                sorted(self.process_count_at_peak_by_type.items())
            ),
            "processes_at_peak": self.processes_at_peak,
        }


def descendants(root_pid: int) -> set[int]:
    if PROC_ROOT.is_dir():
        return proc_descendants(root_pid)
    return subprocess_descendants(root_pid)


def proc_descendants(root_pid: int) -> set[int]:
    children_by_parent: dict[int, list[int]] = {}
    for status_path in PROC_ROOT.glob("[0-9]*/status"):
        try:
            pid = int(status_path.parent.name)
            fields = proc_status_fields(status_path)
            ppid = int(fields.get("PPid", "0"))
        except (OSError, ValueError):
            continue
        children_by_parent.setdefault(ppid, []).append(pid)

    found: set[int] = set()
    pending = [root_pid]
    while pending:
        parent = pending.pop()
        for child in children_by_parent.get(parent, []):
            if child not in found:
                found.add(child)
                pending.append(child)
    return found


def subprocess_descendants(root_pid: int) -> set[int]:
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
    if PROC_ROOT.is_dir():
        return proc_rss_snapshot(pids)
    return subprocess_rss_snapshot(pids)


def proc_rss_snapshot(
    pids: set[int],
) -> tuple[int, dict[str, int], dict[str, int], dict[str, int], list[dict[str, object]]]:
    total_bytes = 0
    by_command: dict[str, int] = {}
    by_process_type: dict[str, int] = {}
    process_count_by_type: dict[str, int] = {}
    processes: list[dict[str, object]] = []
    for pid in sorted(pids):
        proc_dir = PROC_ROOT / str(pid)
        try:
            fields = proc_status_fields(proc_dir / "status")
            ppid = int(fields.get("PPid", "0"))
            rss_kib = int(fields.get("VmRSS", "0 kB").split()[0])
        except (OSError, ValueError, IndexError):
            continue
        if rss_kib <= 0:
            continue
        args = proc_cmdline(proc_dir / "cmdline")
        fallback_command = Path(args.split()[0]).name if args else ""
        command = proc_comm(proc_dir / "comm") or fallback_command
        command = Path(command).name or command or "<unknown>"
        process_type = classify_process_type(command, args)
        rss_bytes_for_process = rss_kib * 1024
        total_bytes += rss_bytes_for_process
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
        total_bytes,
        dict(sorted(by_command.items())),
        dict(sorted(by_process_type.items())),
        dict(sorted(process_count_by_type.items())),
        sorted(processes, key=lambda process: (str(process["process_type"]), int(process["pid"]))),
    )


def subprocess_rss_snapshot(
    pids: set[int],
) -> tuple[int, dict[str, int], dict[str, int], dict[str, int], list[dict[str, object]]]:
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


def pss_uss_snapshot(
    pids: set[int],
    process_type_by_pid: dict[int, str],
) -> tuple[int, int, dict[str, int], dict[str, int]]:
    total_pss_kib = 0
    total_uss_kib = 0
    pss_by_process_type: dict[str, int] = {}
    uss_by_process_type: dict[str, int] = {}
    for pid in pids:
        pss_kib, uss_kib = smaps_rollup_memory_kib(pid)
        if pss_kib <= 0 and uss_kib <= 0:
            continue
        process_type = process_type_by_pid.get(pid, "<unknown>")
        total_pss_kib += pss_kib
        total_uss_kib += uss_kib
        pss_by_process_type[process_type] = (
            pss_by_process_type.get(process_type, 0) + pss_kib * 1024
        )
        uss_by_process_type[process_type] = (
            uss_by_process_type.get(process_type, 0) + uss_kib * 1024
        )
    return (
        total_pss_kib * 1024,
        total_uss_kib * 1024,
        dict(sorted(pss_by_process_type.items())),
        dict(sorted(uss_by_process_type.items())),
    )


def smaps_rollup_memory_kib(pid: int) -> tuple[int, int]:
    path = PROC_ROOT / str(pid) / "smaps_rollup"
    try:
        lines = path.read_text(errors="ignore").splitlines()
    except OSError:
        return 0, 0
    pss_kib = 0
    private_clean_kib = 0
    private_dirty_kib = 0
    for line in lines:
        name, sep, value = line.partition(":")
        if not sep:
            continue
        fields = value.strip().split()
        if not fields:
            continue
        try:
            kib = int(fields[0])
        except ValueError:
            continue
        if name == "Pss":
            pss_kib = kib
        elif name == "Private_Clean":
            private_clean_kib = kib
        elif name == "Private_Dirty":
            private_dirty_kib = kib
    return pss_kib, private_clean_kib + private_dirty_kib


def process_args_by_pid(pids: set[int]) -> dict[int, str]:
    if PROC_ROOT.is_dir():
        return {
            pid: args
            for pid in pids
            if (args := proc_cmdline(PROC_ROOT / str(pid) / "cmdline"))
        }
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


def proc_status_fields(path: Path) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in path.read_text(errors="ignore").splitlines():
        name, sep, value = line.partition(":")
        if sep:
            fields[name] = value.strip()
    return fields


def proc_cmdline(path: Path) -> str:
    try:
        data = path.read_bytes()
    except OSError:
        return ""
    return " ".join(part.decode(errors="replace") for part in data.split(b"\0") if part)


def proc_comm(path: Path) -> str:
    try:
        return path.read_text(errors="ignore").strip()
    except OSError:
        return ""


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
            env=benchmark_child_env(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
            timeout=10,
        )
    except Exception as error:  # noqa: BLE001
        return f"unknown: {type(error).__name__}"
    return completed.stdout.strip() or f"unknown: exit_{completed.returncode}"


def load_checkout_actions() -> list[dict]:
    value = json.loads(FIXTURE_ACTIONS.read_text())
    if not isinstance(value, list):
        raise RuntimeError(f"{FIXTURE_ACTIONS} must contain an action array")
    return value


def text_values(parts: object) -> list[str]:
    if not isinstance(parts, list):
        return []
    values = []
    for part in parts:
        if isinstance(part, dict) and isinstance(part.get("text"), str):
            values.append(part["text"])
    return values


def checkout_oracle_from_observation(observation: dict) -> dict:
    email_ok = False
    status_ok = False
    for element in observation.get("elements", []):
        if not isinstance(element, dict):
            continue
        role = element.get("role")
        names = text_values(element.get("name"))
        values = text_values(element.get("value"))
        if role == "textbox" and "Email" in names and CHECKOUT_ORACLE_EMAIL in values:
            email_ok = True
        if role == "status" and CHECKOUT_ORACLE_STATUS in names:
            status_ok = True
    return {
        "email_value": CHECKOUT_ORACLE_EMAIL if email_ok else "",
        "email_matches": email_ok,
        "remember_checked": True if status_ok else None,
        "remember_checked_inferred": status_ok,
        "status_text": CHECKOUT_ORACLE_STATUS if status_ok else "",
        "status_done": status_ok,
        "submitted": email_ok and status_ok,
        "source": "tempo-final-observation",
    }


def tempo_final_oracle(journal: Path) -> dict:
    try:
        connection = sqlite3.connect(journal)
        try:
            rows = connection.execute(
                "select event_json from journal_entries order by seq desc"
            ).fetchall()
        finally:
            connection.close()
    except sqlite3.Error as error:
        return {
            "submitted": False,
            "source": "tempo-final-observation",
            "error": type(error).__name__,
        }
    for (event_json,) in rows:
        try:
            event = json.loads(event_json)
        except json.JSONDecodeError:
            continue
        if event.get("kind") == "observation" and isinstance(event.get("observation"), dict):
            return checkout_oracle_from_observation(event["observation"])
    return {
        "submitted": False,
        "source": "tempo-final-observation",
        "error": "missing_final_observation",
    }


def tempo_final_oracle_from_report(report: dict, journal: Path) -> dict:
    final_page_state = report.get("final_page_state")
    if isinstance(final_page_state, dict):
        final_page_state.setdefault("source", "tempo-final-page-state")
        return final_page_state
    return {
        "submitted": False,
        "source": "tempo-final-page-state",
        "error": "missing_final_page_state",
        "journal": str(journal),
    }


def checkout_oracle_from_page(page: object, source: str) -> dict:
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
            submitted: email === 'agent@example.com' && remember && statusDone && statusText === 'Order submitted'
          };
        }"""
    )
    if not isinstance(value, dict):
        value = {"submitted": False, "error": "oracle_eval_returned_non_object"}
    value["source"] = source
    return value


def run_tempo(url: str, chrome: str, output_dir: Path) -> dict:
    journal = output_dir / "tempo-journal.sqlite"
    run_report = output_dir / "tempo-run.json"
    env = benchmark_child_env()
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
    timings = report.get("timings_ms")
    if not isinstance(timings, dict):
        raise RuntimeError("tempo run report missing timings_ms")
    browser_metrics = report.get("browser_performance_metrics")
    if not isinstance(browser_metrics, dict):
        raise RuntimeError("tempo run report missing browser_performance_metrics")
    web_metrics = report.get("web_performance_metrics")
    if not isinstance(web_metrics, dict):
        raise RuntimeError("tempo run report missing web_performance_metrics")
    cdp_observation_counters = report.get("cdp_observation_counters")
    if not isinstance(cdp_observation_counters, dict):
        raise RuntimeError("tempo run report missing cdp_observation_counters")
    missing_counter_fields = [
        field
        for field in TEMPO_CDP_OBSERVATION_COUNTER_FIELDS
        if field not in cdp_observation_counters
    ]
    if missing_counter_fields:
        raise RuntimeError(
            "tempo run report cdp_observation_counters missing fields: "
            f"{missing_counter_fields}"
        )
    runtime_flavor = report.get("runtime_flavor")
    if runtime_flavor not in TEMPO_RUNTIME_FLAVORS:
        raise RuntimeError(f"tempo run report missing valid runtime_flavor: {runtime_flavor!r}")
    final_oracle = tempo_final_oracle_from_report(report, journal)
    success = (
        report.get("status", {}).get("state") in {"completed", "already_complete"}
        and final_oracle.get("submitted") is True
    )
    metric = {
        "runner": "tempo-cdp-agent",
        "suite": SUITE,
        "case_id": CASE_ID,
        "success": bool(success),
        "final_oracle": final_oracle,
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
        "tempo_engine": str(report.get("engine", "")),
        "tempo_runtime_flavor": runtime_flavor,
        "cdp_launch_profile": (
            "playwright-lifecycle"
            if env.get("TEMPO_CDP_BENCH_PLAYWRIGHT_LIFECYCLE_ARGS") == "1"
            else "tempo-default"
        ),
        "cdp_type_dispatch": (
            "insert-text" if env.get("TEMPO_CDP_BENCH_INSERT_TEXT_TYPE") == "1" else "key-events"
        ),
        "cdp_browser_context": (
            "fresh-profile"
            if env.get("TEMPO_CDP_BENCH_NO_INCOGNITO") == "1"
            else "incognito-context"
        ),
        "cdp_browser_cache": (
            "enabled" if env.get("TEMPO_CDP_BENCH_ENABLE_CACHE") == "1" else "disabled"
        ),
        "cdp_desktop_integration": (
            "suppressed" if env.get("TEMPO_CDP_BENCH_SUPPRESS_DESKTOP") == "1" else "default"
        ),
        "tempo_phase_timings_ms": timings,
        "browser_performance_metrics_available": bool(
            report.get("browser_performance_metrics_available")
        ),
        "browser_performance_metrics": browser_metrics,
    }
    for field in TEMPO_CDP_OBSERVATION_COUNTER_FIELDS:
        metric[f"cdp_{field}"] = int(cdp_observation_counters[field])
    apply_browser_performance_metrics(metric, browser_metrics)
    apply_web_performance_metrics(
        metric,
        {
            key: int(web_metrics.get(key, 0))
            for key in WEB_PERFORMANCE_ROW_FIELDS
            if isinstance(web_metrics.get(key, 0), (int, float))
        },
    )
    for timing_name, metric_name in (
        ("total_wall_clock_ms", "tempo_total_wall_clock_ms"),
        ("runtime_setup_ms", "tempo_runtime_setup_ms"),
        ("structured_probe_ms", "tempo_structured_probe_ms"),
        ("driver_launch_ms", "tempo_driver_launch_ms"),
        ("agent_run_ms", "tempo_agent_run_ms"),
        ("driver_close_ms", "tempo_driver_close_ms"),
    ):
        if timing_name in timings:
            metric[metric_name] = int(timings[timing_name])
    metric.update(usage)
    return metric


def cdp_performance_metrics(cdp: object) -> dict[str, int | float]:
    cdp.send("Performance.enable")
    response = cdp.send("Performance.getMetrics")
    metrics = response.get("metrics", []) if isinstance(response, dict) else []
    values = {}
    for metric in metrics:
        if not isinstance(metric, dict):
            continue
        name = metric.get("name")
        value = metric.get("value")
        if isinstance(name, str) and isinstance(value, (int, float)) and not isinstance(value, bool):
            values[str(name)] = value
    return values


def metric_value_to_int(name: str, value: int | float) -> int:
    if name.endswith("Duration"):
        return int(round(float(value) * 1000))
    return int(round(float(value)))


def apply_browser_performance_metrics(metric: dict, metrics: dict[str, int | float]) -> None:
    metric["browser_performance_metrics_available"] = bool(metrics)
    metric["browser_performance_metrics"] = dict(sorted(metrics.items()))
    for source_name, field_name in BROWSER_PERFORMANCE_ROW_FIELDS.items():
        if source_name in metrics:
            metric[field_name] = metric_value_to_int(source_name, metrics[source_name])


def cdp_element_center(cdp: object, selector: str) -> dict:
    expression = """
        (() => {
          const selector = __SELECTOR__;
          const element = document.querySelector(selector);
          if (!element) return { found: false, reason: 'missing selector', selector };
          element.scrollIntoView({ block: 'center', inline: 'center' });
          const rect = element.getBoundingClientRect();
          if (rect.width <= 0 || rect.height <= 0) {
            return { found: false, reason: 'empty bounding box', selector };
          }
          return {
            found: true,
            selector,
            x: Math.round(rect.left + rect.width / 2),
            y: Math.round(rect.top + rect.height / 2)
          };
        })()
    """.replace("__SELECTOR__", json.dumps(selector))
    result = cdp.send(
        "Runtime.evaluate",
        {
            "expression": expression,
            "returnByValue": True,
            "awaitPromise": True,
        },
    )
    if "exceptionDetails" in result:
        raise RuntimeError(f"runtime exception: {result['exceptionDetails']}")
    value = result.get("result", {}).get("value")
    if not isinstance(value, dict) or value.get("found") is not True:
        raise RuntimeError(f"selector failed: {value}")
    return value


def cdp_click_at(cdp: object, x: int, y: int) -> None:
    cdp.send("Input.dispatchMouseEvent", {"type": "mouseMoved", "x": x, "y": y})
    cdp.send(
        "Input.dispatchMouseEvent",
        {
            "type": "mousePressed",
            "x": x,
            "y": y,
            "button": "left",
            "clickCount": 1,
        },
    )
    cdp.send(
        "Input.dispatchMouseEvent",
        {
            "type": "mouseReleased",
            "x": x,
            "y": y,
            "button": "left",
            "clickCount": 1,
        },
    )


def run_cdp_action(cdp: object, action: dict) -> dict:
    kind = action.get("kind")
    selector = str(action.get("node", ""))
    center = cdp_element_center(cdp, selector)
    x = int(center["x"])
    y = int(center["y"])
    if kind == "type":
        text = str(action.get("text", ""))
        cdp_click_at(cdp, x, y)
        # CDP input-domain text insertion is closer to browser automation than
        # direct DOM value assignment, but it is still not a keydown/keyup stream.
        cdp.send("Input.insertText", {"text": text})
        return {
            "applied": True,
            "kind": "type",
            "selector": selector,
            "text": text,
            "x": x,
            "y": y,
        }
    if kind == "click":
        cdp_click_at(cdp, x, y)
        return {"applied": True, "kind": "click", "selector": selector, "x": x, "y": y}
    raise RuntimeError(f"unsupported checkout action: {action}")


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


def web_performance_expression() -> str:
    return r"""
    (async () => {
      const n = (value) => Number.isFinite(Number(value)) ? Math.round(Number(value)) : 0;
      const nav = performance.getEntriesByType('navigation')[0] || null;
      const resources = performance.getEntriesByType('resource');
      const paints = {};
      for (const entry of performance.getEntriesByType('paint')) {
        paints[entry.name] = n(entry.startTime);
      }
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
    })()
    """


def web_performance_metrics(page: object) -> dict[str, int]:
    value = page.evaluate(web_performance_expression())
    if not isinstance(value, dict):
        raise RuntimeError("web performance metrics returned non-object")
    return {
        key: int(value.get(key, 0))
        for key in WEB_PERFORMANCE_ROW_FIELDS
        if isinstance(value.get(key, 0), (int, float))
    }


def apply_web_performance_metrics(metric: dict, metrics: dict[str, int]) -> None:
    metric["web_performance_metrics_available"] = bool(metrics)
    metric["web_performance_metrics"] = dict(sorted(metrics.items()))
    for source_name, field_name in WEB_PERFORMANCE_ROW_FIELDS.items():
        metric[field_name] = int(metrics.get(source_name, 0))


def run_cdp_baseline(chrome: str, url: str, runner: str, snapshot: str | None) -> dict:
    from playwright.sync_api import sync_playwright

    before_self = usage_self()
    before_children = usage_children()
    started = now_ms()
    failure_mode = None
    model_input = ""
    browser_metrics: dict[str, int | float] = {}
    web_metrics: dict[str, int] = {}
    action_trace: list[dict] = []
    checkout_actions = load_checkout_actions()
    final_oracle: dict = {"submitted": False, "source": runner}
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
                        env=benchmark_child_env(),
                    )
                    try:
                        page = context.new_page()
                        cdp = page.context.new_cdp_session(page)
                        cdp.send("Performance.enable")
                        page.goto(url, wait_until="load", timeout=15000)
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
                        for index, action in enumerate(checkout_actions):
                            action_result = run_cdp_action(cdp, action)
                            action_trace.append(
                                {
                                    "index": index,
                                    "action": action,
                                    "result": action_result,
                                }
                            )
                        page.wait_for_function(
                            "document.querySelector('#status')?.dataset.done === 'true'",
                            timeout=5000,
                        )
                        final_oracle = checkout_oracle_from_page(page, runner)
                        success = bool(final_oracle.get("submitted"))
                        browser_metrics = cdp_performance_metrics(cdp)
                        web_metrics = web_performance_metrics(page)
                    finally:
                        context.close()
        except Exception as error:  # noqa: BLE001
            failure_mode = type(error).__name__
            success = False
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
        "final_oracle": final_oracle,
        "action_trace": action_trace,
        "wall_clock_ms": wall,
        "step_count": len(action_trace),
        "retry_count": 0,
        "failure_mode": failure_mode,
        "model_input_bytes": byte_count,
        "model_input_tokens": estimated_tokens(byte_count),
        "observations": 1 if snapshot else 0,
        "model_input_observations": 1 if snapshot else 0,
        "adapter": "playwright-cdp-session",
        "cdp_action_mode": "input-events",
    }
    apply_browser_performance_metrics(metric, browser_metrics)
    apply_web_performance_metrics(metric, web_metrics)
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
    env = benchmark_child_env()
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
        "final_oracle": report.get("final_oracle", {}),
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
    if "browser_performance_metrics_available" in report:
        metric["browser_performance_metrics_available"] = bool(
            report["browser_performance_metrics_available"]
        )
    if "browser_performance_metrics_unavailable_reason" in report:
        metric["browser_performance_metrics_unavailable_reason"] = str(
            report["browser_performance_metrics_unavailable_reason"]
        )
    if "browser_performance_metrics" in report:
        metrics = report["browser_performance_metrics"]
        if isinstance(metrics, dict):
            metric["browser_performance_metrics"] = metrics
    for field_name in BROWSER_PERFORMANCE_ROW_FIELDS.values():
        if field_name in report:
            metric[field_name] = int(report[field_name])
    if "web_performance_metrics_available" in report:
        metric["web_performance_metrics_available"] = bool(
            report["web_performance_metrics_available"]
        )
    if "web_performance_metrics" in report:
        metrics = report["web_performance_metrics"]
        if isinstance(metrics, dict):
            metric["web_performance_metrics"] = metrics
    for field_name in WEB_PERFORMANCE_ROW_FIELDS.values():
        if field_name in report:
            metric[field_name] = int(report[field_name])
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
        STATUS_ARTIFACT,
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
            "observations": summarize_int_field(runner_metrics, "observations"),
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
        for field in TEMPO_CDP_OBSERVATION_COUNTER_FIELDS:
            metric_field = f"cdp_{field}"
            if any(metric_field in metric for metric in runner_metrics):
                summary[runner][metric_field] = summarize_int_field(runner_metrics, metric_field)
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


def rotate_runner_plan(
    runner_plan: list[tuple[str, Callable[[], dict]]],
    iteration: int,
) -> list[tuple[str, Callable[[], dict]]]:
    if not runner_plan:
        return []
    offset = (iteration - 1) % len(runner_plan)
    return runner_plan[offset:] + runner_plan[:offset]


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
        ("cold_start_wall_clock_ms", "lower_is_better", runners),
        ("wall_clock_ms_p95", "lower_is_better", runners),
        ("runner_internal_wall_clock_ms_p95", "lower_is_better", runners),
        ("steady_state_wall_clock_ms_p95", "lower_is_better", runners),
        ("max_rss_bytes_p95", "lower_is_better", runners),
        ("browser_rss_bytes_p95", "lower_is_better", runners),
        ("browser_peak_rss_bytes_p95", "lower_is_better", runners),
        ("max_pss_bytes_p95", "lower_is_better", runners),
        ("browser_pss_bytes_p95", "lower_is_better", runners),
        ("browser_peak_pss_bytes_p95", "lower_is_better", runners),
        ("max_uss_bytes_p95", "lower_is_better", runners),
        ("browser_uss_bytes_p95", "lower_is_better", runners),
        ("browser_peak_uss_bytes_p95", "lower_is_better", runners),
        ("max_process_count_p95", "lower_is_better", runners),
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
            "observations_p95",
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
    ranked_category_fields = {name for name, _direction, _runners in category_specs}
    for field_name in RANKED_WEB_PERFORMANCE_ROW_FIELDS:
        if field_name not in ranked_category_fields:
            category_specs.append((field_name, "lower_is_better", runners))
            ranked_category_fields.add(field_name)
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
    comparison_notes = [
        "raw-chrome-cdp is excluded from observation-token and agent-step categories because it has no model-facing observation stream.",
        "raw/synthetic CDP baselines dispatch Chrome input events for checkout actions; they do not mutate form state through direct DOM assignment.",
        "model_input_tokens_p95 ranks the full model-facing stream each runner presents to an agent; compact_observation_tokens_p95 ranks the largest compact observation projection per run.",
        "max_observation_tokens_p95 keeps Tempo's full durable structured audit JSON cost visible and is intentionally separate from compact model-facing projections.",
        "max_observation_tokens_p95 compares the largest single durable observation per run; total_model_input_tokens_p95 ranks the cumulative model-facing stream where runners expose it.",
        "cpu_time_ms_p95 is row-level only until every runner uses the same resource-accounting scope.",
        "cold_start_wall_clock_ms reports iteration 1; steady_state_wall_clock_ms_p95 ranks iteration 2+ only and is omitted for one-iteration smoke artifacts.",
    ]
    if any("runner_order" in metric for metric in metrics):
        comparison_notes.append(
            "Benchmark runner order rotates per iteration to reduce deterministic warm-cache/order bias; each metric row records runner_order and runner_order_index."
        )
    if any(metric.get("sampler_root_included") is True for metric in metrics):
        comparison_notes.append(
            "Process-tree memory/process metrics include each runner root process and its descendants; rows record sampler_root_included so subprocess and in-process lanes expose their accounting scope."
        )
    comparison_notes.extend(
        [
            "CDP Performance.getMetrics fields are required and ranked for every runner in this CDP-backed benchmark.",
            "Known CDP runtime fields use stable browser_* category names; any additional numeric Performance.getMetrics values are preserved as browser_cdp_* row fields but not ranked until promoted to the stable contract.",
            "web_* categories come from the browser Performance Timeline APIs and are required for every runner, including Tempo.",
            "Web resource count and byte fields are preserved as parity/integrity metrics, not ranked lower-is-better optimization categories.",
            "browser_rss_bytes_p95/browser_pss_bytes_p95/browser_uss_bytes_p95 report Chrome memory at the process-tree RSS/PSS/USS peak; browser_peak_* fields report Chrome process-type peaks even when they occur at a different sample.",
            "Positive deltas mean Tempo is behind that comparison target; negative deltas mean Tempo is ahead.",
        ]
    )
    return {
        "suite": SUITE,
        "case_id": CASE_ID,
        "tempo_runner": TEMPO_RUNNER,
        "baseline_runner": RAW_CHROME_RUNNER,
        "agent_style_runners": sorted(AGENT_STYLE_RUNNERS),
        "comparison_notes": comparison_notes,
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
        **browser_performance_metric_percentile_fields(runner_metrics),
        "browser_rss_bytes_p95": percentile(
            [browser_rss_bytes(metric) for metric in runner_metrics],
            0.95,
        ),
        "browser_peak_rss_bytes_p95": percentile(
            [
                browser_memory_bytes(metric, "peak_rss_by_process_type_bytes")
                for metric in runner_metrics
            ],
            0.95,
        ),
        "max_pss_bytes_p95": optional_metric_percentile(
            runner_metrics,
            "max_pss_bytes",
            0.95,
        ),
        "browser_pss_bytes_p95": optional_percentile(
            [
                browser_memory_bytes(metric, "pss_at_peak_by_process_type_bytes")
                for metric in runner_metrics
            ],
            0.95,
        ),
        "browser_peak_pss_bytes_p95": optional_percentile(
            [
                browser_memory_bytes(metric, "peak_pss_by_process_type_bytes")
                for metric in runner_metrics
            ],
            0.95,
        ),
        "max_uss_bytes_p95": optional_metric_percentile(
            runner_metrics,
            "max_uss_bytes",
            0.95,
        ),
        "browser_uss_bytes_p95": optional_percentile(
            [
                browser_memory_bytes(metric, "uss_at_peak_by_process_type_bytes")
                for metric in runner_metrics
            ],
            0.95,
        ),
        "browser_peak_uss_bytes_p95": optional_percentile(
            [
                browser_memory_bytes(metric, "peak_uss_by_process_type_bytes")
                for metric in runner_metrics
            ],
            0.95,
        ),
        "process_count_at_peak_p95": percentile(
            [int(metric.get("process_count_at_peak", 0)) for metric in runner_metrics],
            0.95,
        ),
        "max_process_count_p95": percentile(
            [
                int(metric.get("max_process_count", metric.get("process_count_at_peak", 0)))
                for metric in runner_metrics
            ],
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
        "observations_p95": int(runner_summary["observations"]["p95"])
        if "observations" in runner_summary
        else None,
        "model_input_observations_p95": int(runner_summary["model_input_observations"]["p95"]),
        "step_count_p95": int(runner_summary["step_count"]["p95"]),
    }


def cold_start_wall_clock_ms(runner_metrics: list[dict]) -> int | None:
    first = next(
        (
            metric
            for metric in sorted(runner_metrics, key=lambda item: int(item.get("iteration", 0)))
            if int(metric.get("iteration", 0)) == 1
        ),
        None,
    )
    return int(first["wall_clock_ms"]) if first else None


def steady_state_wall_clock_ms_p95(runner_metrics: list[dict]) -> int | None:
    values = [
        int(metric["wall_clock_ms"])
        for metric in runner_metrics
        if int(metric.get("iteration", 0)) > 1
    ]
    return percentile(values, 0.95) if values else None


def runner_internal_wall_clock_ms_p95(runner_metrics: list[dict]) -> int | None:
    values = []
    for metric in runner_metrics:
        if "tempo_total_wall_clock_ms" in metric:
            values.append(int(metric["tempo_total_wall_clock_ms"]))
        elif "child_wall_clock_ms" in metric:
            values.append(int(metric["child_wall_clock_ms"]))
        else:
            values.append(int(metric["wall_clock_ms"]))
    return percentile(values, 0.95) if values else None


def browser_rss_bytes(metric: dict) -> int:
    return browser_memory_bytes(metric, "rss_at_peak_by_process_type_bytes")


def browser_memory_bytes(metric: dict, field: str) -> int:
    by_type = metric.get(field, {})
    if not isinstance(by_type, dict):
        return 0
    return sum(
        int(value)
        for key, value in by_type.items()
        if isinstance(key, str) and (key == "chrome-browser" or key.startswith("chrome-"))
    )


def browser_performance_metric_names(metrics: list[dict]) -> list[str]:
    names = set()
    for metric in metrics:
        browser_metrics = metric.get("browser_performance_metrics")
        if isinstance(browser_metrics, dict):
            names.update(str(name) for name in browser_metrics)
    return sorted(names)


def assert_browser_performance_metric_key_coverage(metrics: list[dict]) -> None:
    expected_names = set(browser_performance_metric_names(metrics))
    for metric in metrics:
        runner = str(metric.get("runner", "<unknown>"))
        iteration = int(metric.get("iteration", 0))
        browser_metrics = metric.get("browser_performance_metrics")
        if not isinstance(browser_metrics, dict):
            raise RuntimeError(f"{runner} iteration {iteration} missing browser_performance_metrics")
        names = set(str(name) for name in browser_metrics)
        if names != expected_names:
            missing = sorted(expected_names - names)
            extra = sorted(names - expected_names)
            raise RuntimeError(
                f"{runner} iteration {iteration} CDP metric key coverage mismatch: "
                f"missing={missing} extra={extra}"
            )


def browser_performance_metric_row_field(metric_name: str) -> str:
    if metric_name in BROWSER_PERFORMANCE_ROW_FIELDS:
        return BROWSER_PERFORMANCE_ROW_FIELDS[metric_name]
    slug = "".join(
        char.lower() if char.isalnum() else "_"
        for char in metric_name
    ).strip("_")
    while "__" in slug:
        slug = slug.replace("__", "_")
    suffix = "ms" if metric_name.endswith("Duration") else "bytes" if metric_name.endswith("Size") else ""
    suffix_part = f"_{suffix}" if suffix else ""
    return f"browser_cdp_{slug}{suffix_part}_p95"


def browser_performance_metric_percentile_fields(runner_metrics: list[dict]) -> dict[str, int | None]:
    fields = {}
    for metric_name in browser_performance_metric_names(runner_metrics):
        field_name = browser_performance_metric_row_field(metric_name)
        if field_name in BROWSER_PERFORMANCE_ROW_FIELDS.values():
            continue
        values = []
        for metric in runner_metrics:
            browser_metrics = metric.get("browser_performance_metrics")
            if not isinstance(browser_metrics, dict) or metric_name not in browser_metrics:
                values = []
                break
            raw_value = browser_metrics[metric_name]
            if not isinstance(raw_value, (int, float)) or isinstance(raw_value, bool):
                values = []
                break
            values.append(metric_value_to_int(metric_name, raw_value))
        fields[field_name] = percentile(values, 0.95) if values else None
    return fields


def optional_metric_percentile(
    runner_metrics: list[dict],
    field: str,
    pct: float,
) -> int | None:
    if not runner_metrics or any(field not in metric for metric in runner_metrics):
        return None
    return percentile([int(metric[field]) for metric in runner_metrics], pct)


def first_unavailable_browser_metrics_reason(runner_metrics: list[dict]) -> str | None:
    for metric in runner_metrics:
        if not metric.get("browser_performance_metrics_available"):
            return str(
                metric.get(
                    "browser_performance_metrics_unavailable_reason",
                    "browser performance metrics unavailable",
                )
            )
    return None


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
    env = benchmark_child_env()
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
        help=(
            "number of benchmark iterations; defaults to 1 for smoke and one "
            "complete runner-order cycle for --full"
        ),
    )
    parser.add_argument("--min-success-rate", type=float, default=None)
    parser.add_argument("--max-p95-wall-ms", type=int, default=None)
    parser.add_argument("--max-p95-model-input-tokens", type=int, default=None)
    parser.add_argument("--max-p95-rss-bytes", type=int, default=None)
    parser.add_argument("--chrome", required=True)
    parser.add_argument("--output-dir", required=True)
    args = parser.parse_args()

    assert_safe_benchmark_environment()

    if not FIXTURE_HTML.exists():
        raise RuntimeError(f"missing fixture: {FIXTURE_HTML}")

    output_dir = Path(args.output_dir)
    assert_safe_output_dir(output_dir)
    clean_output_dir(output_dir)
    iterations = (
        args.iterations
        if args.iterations is not None
        else (len(DEFAULT_RUNNER_ORDER) if args.full else 1)
    )
    if iterations < 1:
        raise RuntimeError("--iterations must be >= 1")
    resolved_chrome_version = chrome_version(args.chrome)

    with StaticServer(FIXTURE_DIR) as server:
        url = f"{server.base_url}/checkout.html"
        metrics = []
        runner_orders: dict[str, list[str]] = {}
        for iteration in range(1, iterations + 1):
            iteration_dir = output_dir if iterations == 1 else output_dir / f"iteration-{iteration:03d}"
            clean_output_dir(iteration_dir)
            runner_plan: list[tuple[str, Callable[[], dict]]] = [
                ("tempo-cdp-agent", lambda: run_tempo(url, args.chrome, iteration_dir)),
                ("raw-chrome-cdp", lambda: run_cdp_baseline(args.chrome, url, "raw-chrome-cdp", None)),
                (
                    "synthetic-playwright-ax",
                    lambda: run_cdp_baseline(args.chrome, url, "synthetic-playwright-ax", "ax"),
                ),
                (
                    "synthetic-browser-use-dom",
                    lambda: run_cdp_baseline(
                        args.chrome,
                        url,
                        "synthetic-browser-use-dom",
                        "browser_use_dom",
                    ),
                ),
                (
                    "real-playwright",
                    lambda: run_external_baseline(
                        args.chrome,
                        url,
                        "real-playwright",
                        "playwright_checkout.py",
                        iteration_dir,
                    ),
                ),
                (
                    "external-browser-use-dom-loop",
                    lambda: run_external_baseline(
                        args.chrome,
                        url,
                        "external-browser-use-dom-loop",
                        "browser_use_dom_loop.py",
                        iteration_dir,
                    ),
                ),
                (
                    "real-browser-use",
                    lambda: run_external_baseline(
                        args.chrome,
                        url,
                        "real-browser-use",
                        "browser_use_package.py",
                        iteration_dir,
                    ),
                ),
            ]
            if tuple(runner for runner, _run in runner_plan) != DEFAULT_RUNNER_ORDER:
                raise RuntimeError("runner plan order does not match DEFAULT_RUNNER_ORDER")
            ordered_runner_plan = rotate_runner_plan(runner_plan, iteration)
            runner_order = [runner for runner, _run in ordered_runner_plan]
            runner_orders[str(iteration)] = runner_order
            iteration_metrics = []
            for runner_order_index, (expected_runner, run_runner) in enumerate(
                ordered_runner_plan,
                start=1,
            ):
                metric = run_runner()
                if metric.get("runner") != expected_runner:
                    raise RuntimeError(
                        f"runner plan expected {expected_runner}, got {metric.get('runner')}"
                    )
                metric["iteration"] = iteration
                metric["runner_order"] = runner_order
                metric["runner_order_index"] = runner_order_index
                iteration_metrics.append(metric)
            write_json(
                iteration_dir / "agent-browser-bench.json",
                {
                    "url": url,
                    "iteration": iteration,
                    "runner_order": runner_order,
                    "chrome": args.chrome,
                    "chrome_version": resolved_chrome_version,
                    "metrics": iteration_metrics,
                },
            )
            write_jsonl(iteration_dir / "agent-browser-bench.jsonl", iteration_metrics)
            derive_artifacts(iteration_dir, iteration_metrics, url)
            metrics.extend(iteration_metrics)
        assert_browser_performance_metric_key_coverage(metrics)
        summary = summarize_metrics(metrics)
        root_report = {
            "url": url,
            "iterations": iterations,
            "chrome": args.chrome,
            "chrome_version": resolved_chrome_version,
            "runner_orders": runner_orders,
            "metrics": metrics,
            "summary": summary,
        }
        write_json(output_dir / "agent-browser-bench.json", root_report)
        write_jsonl(output_dir / "agent-browser-bench.jsonl", metrics)
        write_json(output_dir / "agent-browser-bench-summary.json", summary)
        gap_report = benchmark_gap_report(metrics, summary)
        write_json(output_dir / "agent-browser-bench-gaps.json", gap_report)
        chrome_version_artifact = {"chrome": args.chrome, "version": resolved_chrome_version}
        write_json(
            output_dir / "chrome-version.txt",
            chrome_version_artifact,
        )
        (output_dir / STATUS_ARTIFACT).write_text(
            render_status_markdown(
                root_report,
                summary,
                gap_report,
                chrome_version_artifact,
            )
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
