#!/usr/bin/env python3
"""Live browser benchmark harness for agent-oriented Tempo comparisons."""

from __future__ import annotations

import argparse
import base64
import hashlib
import http.client
import http.server
import json
import os
import random
import resource
import shutil
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from urllib.parse import urlparse


ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "fixtures" / "evals" / "live_agent"
FIXTURE_HTML = FIXTURE_DIR / "checkout.html"
FIXTURE_ACTIONS = FIXTURE_DIR / "checkout-actions.json"
SUITE = "live-agent-browser-bench"
CASE_ID = "checkout-submit"


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


class WebSocket:
    def __init__(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme != "ws":
            raise RuntimeError(f"unsupported websocket URL: {url}")
        self.sock = socket.create_connection((parsed.hostname, parsed.port), timeout=10)
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        path = parsed.path
        if parsed.query:
            path = f"{path}?{parsed.query}"
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {parsed.hostname}:{parsed.port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n"
            "\r\n"
        )
        self.sock.sendall(request.encode("ascii"))
        response = self._read_http_response()
        if b" 101 " not in response.split(b"\r\n", 1)[0]:
            raise RuntimeError(f"websocket upgrade failed: {response[:200]!r}")

    def _read_http_response(self) -> bytes:
        data = bytearray()
        while b"\r\n\r\n" not in data:
            chunk = self.sock.recv(4096)
            if not chunk:
                break
            data.extend(chunk)
        return bytes(data)

    def send_json(self, value: dict) -> None:
        payload = json.dumps(value, separators=(",", ":")).encode("utf-8")
        header = bytearray([0x81])
        length = len(payload)
        if length < 126:
            header.append(0x80 | length)
        elif length <= 0xFFFF:
            header.append(0x80 | 126)
            header.extend(struct.pack("!H", length))
        else:
            header.append(0x80 | 127)
            header.extend(struct.pack("!Q", length))
        mask = os.urandom(4)
        header.extend(mask)
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    def recv_json(self) -> dict:
        payload = self._recv_frame()
        return json.loads(payload.decode("utf-8"))

    def _recv_exact(self, length: int) -> bytes:
        data = bytearray()
        while len(data) < length:
            chunk = self.sock.recv(length - len(data))
            if not chunk:
                raise RuntimeError("websocket closed")
            data.extend(chunk)
        return bytes(data)

    def _recv_frame(self) -> bytes:
        first, second = self._recv_exact(2)
        opcode = first & 0x0F
        masked = second & 0x80
        length = second & 0x7F
        if length == 126:
            length = struct.unpack("!H", self._recv_exact(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self._recv_exact(8))[0]
        mask = self._recv_exact(4) if masked else b""
        payload = self._recv_exact(length)
        if masked:
            payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        if opcode == 0x8:
            raise RuntimeError("websocket close frame received")
        if opcode == 0x9:
            self._send_pong(payload)
            return self._recv_frame()
        if opcode != 0x1:
            return self._recv_frame()
        return payload

    def _send_pong(self, payload: bytes) -> None:
        header = bytearray([0x8A, 0x80 | len(payload)])
        mask = os.urandom(4)
        header.extend(mask)
        masked = bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    def close(self) -> None:
        self.sock.close()


class ChromeCdp:
    def __init__(self, chrome: str) -> None:
        self.profile = tempfile.mkdtemp(prefix="tempo-agent-bench-chrome-")
        self.port = free_port()
        args = [
            chrome,
            "--headless=new",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            "--remote-debugging-address=127.0.0.1",
            f"--remote-debugging-port={self.port}",
            f"--user-data-dir={self.profile}",
            "about:blank",
        ]
        if os.environ.get("TEMPO_CDP_NO_SANDBOX") == "1":
            args.insert(1, "--no-sandbox")
        self.proc = subprocess.Popen(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        ws_url = self._wait_for_browser_ws()
        self.ws = WebSocket(ws_url)
        self.next_id = 0
        self.session_id = self._new_page_session()

    def _wait_for_browser_ws(self) -> str:
        deadline = time.monotonic() + 15
        last_error = ""
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                stderr = ""
                if self.proc.stderr is not None:
                    stderr = self.proc.stderr.read()
                raise RuntimeError(f"chrome exited before CDP was ready: {stderr}")
            try:
                conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=1)
                conn.request("GET", "/json/version")
                response = conn.getresponse()
                body = response.read()
                conn.close()
                if response.status == 200:
                    return json.loads(body.decode("utf-8"))["webSocketDebuggerUrl"]
            except Exception as error:  # noqa: BLE001
                last_error = str(error)
            time.sleep(0.05)
        raise RuntimeError(f"timed out waiting for Chrome CDP: {last_error}")

    def _new_page_session(self) -> str:
        created = self.command("Target.createTarget", {"url": "about:blank"})
        attached = self.command(
            "Target.attachToTarget",
            {"targetId": created["targetId"], "flatten": True},
        )
        session_id = attached["sessionId"]
        self.command("Page.enable", session_id=session_id)
        self.command("Runtime.enable", session_id=session_id)
        self.command("Accessibility.enable", session_id=session_id)
        return session_id

    def command(
        self,
        method: str,
        params: dict | None = None,
        session_id: str | None = None,
    ) -> dict:
        self.next_id += 1
        message = {"id": self.next_id, "method": method}
        if params is not None:
            message["params"] = params
        if session_id is not None:
            message["sessionId"] = session_id
        self.ws.send_json(message)
        while True:
            received = self.ws.recv_json()
            if received.get("id") == self.next_id:
                if "error" in received:
                    raise RuntimeError(f"CDP {method} failed: {received['error']}")
                return received.get("result", {})

    def wait_event(self, method: str, timeout: float = 10.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            received = self.ws.recv_json()
            if received.get("method") == method and received.get("sessionId") == self.session_id:
                return
        raise RuntimeError(f"timed out waiting for {method}")

    def navigate(self, url: str) -> None:
        self.command("Page.navigate", {"url": url}, session_id=self.session_id)
        self.wait_event("Page.loadEventFired")

    def evaluate(self, expression: str) -> object:
        result = self.command(
            "Runtime.evaluate",
            {"expression": expression, "returnByValue": True, "awaitPromise": True},
            session_id=self.session_id,
        )
        remote = result.get("result", {})
        if "exceptionDetails" in result:
            raise RuntimeError(f"runtime exception: {result['exceptionDetails']}")
        return remote.get("value")

    def ax_text(self) -> str:
        tree = self.command("Accessibility.getFullAXTree", session_id=self.session_id)
        lines: list[str] = []
        for node in tree.get("nodes", []):
            role = node.get("role", {}).get("value")
            name = node.get("name", {}).get("value", "")
            if role and name:
                lines.append(f'- {role} "{name}"')
        return "\n".join(lines)

    def close(self) -> None:
        try:
            self.ws.close()
        finally:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)
            shutil.rmtree(self.profile, ignore_errors=True)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


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


def run_tempo(url: str, chrome: str, output_dir: Path) -> dict:
    journal = output_dir / "tempo-journal.sqlite"
    run_report = output_dir / "tempo-run.json"
    env = os.environ.copy()
    env["TEMPO_CDP_CHROME"] = chrome
    env.setdefault("TEMPO_CDP_NO_SANDBOX", "1")
    env.setdefault("TEMPO_DURABLE_RETENTION", "plaintext-unsafe")
    before = usage_children()
    started = now_ms()
    cmd = [
        "cargo",
        "run",
        "-p",
        "tempo-cli",
        "--",
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
    ]
    failure_mode = None
    try:
        run_checked(cmd, env)
    except subprocess.CalledProcessError as error:
        failure_mode = f"exit_{error.returncode}"
    wall = now_ms() - started
    usage = usage_delta(before, usage_children())
    report = {}
    if run_report.exists():
        report = json.loads(run_report.read_text())
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
        "model_input_bytes": int(report.get("max_observation_bytes", 0)),
        "model_input_tokens": int(report.get("max_observation_tokens", 0)),
        "observations": int(report.get("observations", 0)),
        "journal": str(journal),
        "run_report": str(run_report),
    }
    metric.update(usage)
    return metric


def perform_checkout(cdp: ChromeCdp, url: str) -> bool:
    cdp.navigate(url)
    cdp.evaluate(
        """
        (() => {
          const email = document.querySelector('#email');
          email.value = 'agent@example.com';
          email.dispatchEvent(new InputEvent('input', { bubbles: true, inputType: 'insertText', data: email.value }));
          document.querySelector('#remember').click();
          document.querySelector('#pay').click();
          return document.querySelector('#status').dataset.done === 'true';
        })()
        """
    )
    return bool(cdp.evaluate("document.querySelector('#status').dataset.done === 'true'"))


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
    before_self = usage_self()
    before_children = usage_children()
    started = now_ms()
    failure_mode = None
    model_input = ""
    success = False
    cdp = None
    try:
        cdp = ChromeCdp(chrome)
        cdp.navigate(url)
        if snapshot == "ax":
            model_input = cdp.ax_text()
        elif snapshot == "browser_use_dom":
            model_input = str(cdp.evaluate(browser_use_snapshot_expression()))
        success = perform_checkout(cdp, url)
    except Exception as error:  # noqa: BLE001
        failure_mode = type(error).__name__
    finally:
        if cdp is not None:
            cdp.close()
    wall = now_ms() - started
    usage = combined_usage_delta(before_self, before_children, usage_self(), usage_children())
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
    }
    metric.update(usage)
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
    for name in [
        "agent-browser-bench.json",
        "agent-browser-bench.jsonl",
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
            "step_count": summarize_int_field(runner_metrics, "step_count"),
            "retry_count_total": sum(int(metric.get("retry_count", 0)) for metric in runner_metrics),
        }
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


def derive_artifacts(output_dir: Path, metrics: list[dict], url: str) -> None:
    env = os.environ.copy()
    env.setdefault("TEMPO_DURABLE_RETENTION", "plaintext-unsafe")
    tempo = next((metric for metric in metrics if metric["runner"] == "tempo-cdp-agent"), None)
    chrome = next((metric for metric in metrics if metric["runner"] == "raw-chrome-cdp"), None)
    if tempo is None:
        return
    journal = Path(str(tempo["journal"]))
    baseline_wall = int(chrome["wall_clock_ms"]) if chrome else 0
    eval_record = output_dir / "tempo-eval-record.json"
    run_checked(
        [
            "cargo",
            "run",
            "-p",
            "tempo-cli",
            "--",
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
        ],
        env,
    )
    record = json.loads(eval_record.read_text())
    records = output_dir / "eval-records.jsonl"
    records.write_text(json.dumps(record, sort_keys=True) + "\n")
    run_checked(
        [
            "cargo",
            "run",
            "-p",
            "tempo-cli",
            "--",
            "replay",
            "--journal",
            str(journal),
            "--output",
            str(output_dir / "replay.json"),
        ],
        env,
    )
    run_checked(
        [
            "cargo",
            "run",
            "-p",
            "tempo-cli",
            "--",
            "scorecard",
            "--input",
            str(records),
            "--output",
            str(output_dir / "scorecard.json"),
            "--allow-missing-speculation",
        ],
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
                "success": bool(metric.get("success")),
            }
        )
    return {
        "suite": SUITE,
        "case_id": CASE_ID,
        "baseline_runner": "raw-chrome-cdp",
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
            ]
            for metric in iteration_metrics:
                metric["iteration"] = iteration
            write_json(
                iteration_dir / "agent-browser-bench.json",
                {"url": url, "iteration": iteration, "metrics": iteration_metrics},
            )
            write_jsonl(iteration_dir / "agent-browser-bench.jsonl", iteration_metrics)
            derive_artifacts(iteration_dir, iteration_metrics, url)
            metrics.extend(iteration_metrics)
        summary = summarize_metrics(metrics)
        write_json(
            output_dir / "agent-browser-bench.json",
            {"url": url, "iterations": iterations, "metrics": metrics, "summary": summary},
        )
        write_jsonl(output_dir / "agent-browser-bench.jsonl", metrics)
        write_json(output_dir / "agent-browser-bench-summary.json", summary)

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
