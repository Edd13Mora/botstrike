"""
BotStrike Distributed Engine — modules/distributor.py

Orchestrates parallel BotStrike runs across multiple remote Linux VPS nodes
via SSH/SFTP. Each node runs the full pipeline independently from its own IP.
Results are streamed back in real-time, downloaded, and merged into a unified
fleet report saved locally.

nodes.yaml format:
  nodes:
    - id: sg-01
      host: 1.2.3.4
      user: root
      key: ~/.ssh/botstrike_key
      port: 22          # optional, default 22
"""
from __future__ import annotations

import json
import os
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import paramiko
    from paramiko.ssh_exception import AuthenticationException, SSHException
    HAS_PARAMIKO = True
except ImportError:
    HAS_PARAMIKO = False

import yaml
from rich import box
from rich.live import Live
from rich.table import Table

from .utils import console, log, now_utc, phase_banner, TOOL_VERSION

# ─── Constants ────────────────────────────────────────────────────────────────

REMOTE_BASE    = "botstrike"   # uploaded to $HOME/botstrike on every node
CONN_TIMEOUT   = 15            # SSH connect timeout in seconds
BANNER_TIMEOUT = 10            # SSH banner timeout in seconds
PIP_TIMEOUT    = 300           # max seconds to wait for pip install

# Names/extensions to skip when uploading the project to remote nodes
SKIP_NAMES = frozenset({
    "__pycache__", ".git", "reports", "nodes.yaml",
    ".gitignore", "README.md", ".DS_Store", "Thumbs.db",
})
SKIP_EXTS = frozenset({".pyc", ".pyo", ".log"})

STATUS_ICONS = {
    "PENDING":     "[dim]○  PENDING[/dim]",
    "CONNECTING":  "[yellow]◌  CONNECTING[/yellow]",
    "UPLOADING":   "[yellow]↑  UPLOADING[/yellow]",
    "INSTALLING":  "[yellow]⚙  INSTALLING[/yellow]",
    "RUNNING":     "[bold green]●  RUNNING[/bold green]",
    "DONE":        "[bold green]✓  DONE[/bold green]",
    "FAILED":      "[bold red]✗  FAILED[/bold red]",
}


# ─── Data classes ─────────────────────────────────────────────────────────────

@dataclass
class NodeConfig:
    """SSH configuration for one remote node."""
    id:   str
    host: str
    user: str
    key:  str          # absolute path to private key file on local machine
    port: int = 22

    @property
    def address(self) -> str:
        return f"{self.user}@{self.host}:{self.port}"


@dataclass
class NodeResult:
    """Live state + final results for one node. Thread-safe via _lock."""
    node_id:     str
    host:        str
    status:      str   = "PENDING"
    phase:       str   = "—"
    requests:    int   = 0
    blocked_pct: float = 0.0
    score:       int   = 0
    grade:       str   = "—"
    last_line:   str   = ""
    log_lines:   list  = field(default_factory=list)
    json_data:   dict  = field(default_factory=dict)
    html_path:   Optional[Path] = None
    json_path:   Optional[Path] = None
    error:       str   = ""
    start_time:  float = field(default_factory=time.time)
    end_time:    float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def update(self, **kwargs) -> None:
        with self._lock:
            for k, v in kwargs.items():
                setattr(self, k, v)

    def append_log(self, line: str) -> None:
        stripped = line.strip()
        if not stripped:
            return
        with self._lock:
            self.log_lines.append(stripped)
            self.last_line = stripped[-80:]
            ll = stripped.lower()
            # Infer current phase from log output
            if "stealth scraping" in ll or "phase 2a" in ll:
                self.phase = "Stealth Scrape"
            elif "aggressive scraping" in ll or "phase 2b" in ll:
                self.phase = "Aggressive Scrape"
            elif "http flood" in ll and "vector" in ll:
                self.phase = "HTTP Flood"
            elif "slowloris" in ll and "vector" in ll:
                self.phase = "Slowloris"
            elif "post flood" in ll:
                self.phase = "POST Flood"
            elif "cache buster" in ll:
                self.phase = "Cache Buster"
            elif "pre-flight" in ll or "preflight" in ll:
                self.phase = "Pre-Flight"
            elif "passive recon" in ll or "module 1" in ll:
                self.phase = "Recon"
            elif "generating report" in ll:
                self.phase = "Reporting"


# ─── Node loading ─────────────────────────────────────────────────────────────

def load_nodes(path: str) -> list[NodeConfig]:
    """Parse nodes.yaml and return validated NodeConfig list."""
    p = Path(path)
    if not p.exists():
        console.print(f"[red][!] Fleet config not found: {p}[/red]")
        console.print(f"    Copy nodes.yaml.example → {p} and fill in your VPS details.")
        sys.exit(1)

    with open(p, encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    raw = data.get("nodes", [])
    if not raw:
        console.print("[red][!] nodes.yaml has no nodes defined.[/red]")
        sys.exit(1)

    nodes: list[NodeConfig] = []
    for i, n in enumerate(raw):
        try:
            key = os.path.expanduser(str(n.get("key", "~/.ssh/id_rsa")))
            nodes.append(NodeConfig(
                id   = str(n.get("id", f"node-{i + 1}")),
                host = str(n["host"]),
                user = str(n.get("user", "root")),
                key  = key,
                port = int(n.get("port", 22)),
            ))
        except KeyError as e:
            console.print(f"[red][!] Node {i + 1} is missing required field: {e}[/red]")
            sys.exit(1)

    return nodes


# ─── SSH helpers ──────────────────────────────────────────────────────────────

def _connect(node: NodeConfig) -> "paramiko.SSHClient":
    """Open a key-authenticated SSH connection. Raises on failure."""
    if not Path(node.key).exists():
        raise FileNotFoundError(f"SSH key not found: {node.key}")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname      = node.host,
        port          = node.port,
        username      = node.user,
        key_filename  = node.key,
        timeout       = CONN_TIMEOUT,
        banner_timeout= BANNER_TIMEOUT,
        look_for_keys = False,
        allow_agent   = False,
    )
    return client


def _exec(
    client: "paramiko.SSHClient",
    cmd: str,
    on_line=None,
    timeout: Optional[int] = None,
) -> tuple[int, str]:
    """
    Execute cmd over SSH. Streams each stdout+stderr line to on_line(line).
    Returns (exit_code, full_output_string).
    timeout applies per recv() call (seconds of silence before raising).
    """
    transport = client.get_transport()
    chan = transport.open_session()
    chan.set_combine_stderr(True)
    chan.exec_command(cmd)
    if timeout is not None:
        chan.settimeout(timeout)

    buf = ""
    full_output: list[str] = []

    while True:
        try:
            chunk = chan.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        text = chunk.decode("utf-8", errors="replace")
        buf += text
        lines = buf.split("\n")
        buf = lines.pop()           # last (possibly incomplete) line
        for line in lines:
            full_output.append(line)
            if on_line:
                on_line(line)

    if buf:                         # flush remaining buffer
        full_output.append(buf)
        if on_line:
            on_line(buf)

    exit_code = chan.recv_exit_status()
    return exit_code, "\n".join(full_output)


# ─── SFTP helpers ─────────────────────────────────────────────────────────────

def _sftp_mkdir_p(sftp: "paramiko.SFTPClient", remote_path: str) -> None:
    """Create remote directory tree, silently ignoring existing dirs."""
    parts = [p for p in remote_path.split("/") if p]
    current = ""
    for part in parts:
        current += "/" + part
        try:
            sftp.mkdir(current)
        except IOError:
            pass


def _sftp_upload_dir(
    sftp: "paramiko.SFTPClient",
    local_root: Path,
    remote_root: str,
) -> int:
    """
    Recursively upload local_root/* to remote_root/ via SFTP.
    Skips __pycache__, .git, reports/, nodes.yaml, *.pyc, etc.
    Returns number of files uploaded.
    """
    count = 0
    _sftp_mkdir_p(sftp, remote_root)

    for local_path in sorted(local_root.rglob("*")):
        rel_parts = local_path.relative_to(local_root).parts
        if any(part in SKIP_NAMES for part in rel_parts):
            continue
        if local_path.suffix in SKIP_EXTS:
            continue

        rel = str(local_path.relative_to(local_root)).replace(os.sep, "/")
        remote_path = f"{remote_root}/{rel}"

        if local_path.is_dir():
            _sftp_mkdir_p(sftp, remote_path)
        elif local_path.is_file():
            _sftp_mkdir_p(sftp, remote_path.rsplit("/", 1)[0])
            sftp.put(str(local_path), remote_path)
            count += 1

    return count


# ─── Live display ─────────────────────────────────────────────────────────────

def _build_fleet_table(
    results: list[NodeResult],
    target: str,
    elapsed: float,
) -> Table:
    done   = sum(1 for r in results if r.status == "DONE")
    failed = sum(1 for r in results if r.status == "FAILED")

    table = Table(
        title=(
            f"[bold]BotStrike Distributed[/bold]  ·  [cyan]{target}[/cyan]  ·  "
            f"{len(results)} nodes  ·  {done} done  ·  {failed} failed  ·  {elapsed:.0f}s"
        ),
        box=box.ROUNDED, expand=True, header_style="bold cyan",
    )
    table.add_column("Node",      style="white",   width=16)
    table.add_column("Status",                     width=17)
    table.add_column("Phase",     style="cyan",    width=17)
    table.add_column("Requests",  justify="right", width=10)
    table.add_column("Blocked%",  justify="right", width=10)
    table.add_column("Score",     justify="center",width=10)
    table.add_column("Elapsed",   justify="right", width=8)
    table.add_column("Last Activity", style="dim")

    for r in results:
        node_elapsed = (
            int(r.end_time - r.start_time) if r.end_time
            else int(time.time() - r.start_time)
        )
        score_str = (
            f"[bold green]{r.grade}[/bold green] ({r.score})"
            if r.status == "DONE" and r.score else "—"
        )
        bp = r.blocked_pct
        bp_str = (
            f"[{'red' if bp > 50 else 'yellow' if bp > 20 else 'green'}]{bp:.1f}%[/]"
            if bp > 0 else "—"
        )
        activity = (
            r.error[:58] if r.status == "FAILED" and r.error
            else r.last_line[:58] if r.last_line else ""
        )
        table.add_row(
            r.node_id,
            STATUS_ICONS.get(r.status, r.status),
            r.phase,
            f"{r.requests:,}" if r.requests else "—",
            bp_str,
            score_str,
            f"{node_elapsed}s",
            activity,
        )

    return table


# ─── Metrics extraction ───────────────────────────────────────────────────────

def _parse_metrics(result: NodeResult, jdata: dict) -> None:
    """Pull key numbers from a downloaded JSON report into NodeResult."""
    score_data = jdata.get("score", {})
    result.update(
        score = score_data.get("score", 0),
        grade = score_data.get("grade", "—"),
    )
    scraping    = jdata.get("scraping", {})
    stealth_pct = scraping.get("stealth",    {}).get("blocked_pct", 0.0)
    agg_pct     = scraping.get("aggressive", {}).get("blocked_pct", 0.0)
    total_req   = (
        scraping.get("stealth",    {}).get("total_requests", 0) +
        scraping.get("aggressive", {}).get("total_requests", 0)
    )
    if total_req:
        result.update(requests=total_req)
    if stealth_pct or agg_pct:
        result.update(blocked_pct=round((stealth_pct + agg_pct) / 2, 1))


# ─── Node setup (first-time bootstrap) ───────────────────────────────────────

def setup_node(node: NodeConfig, local_root: Path, result: NodeResult) -> bool:
    """
    Connect → upload → pip install → smoke-test one node.
    Updates result.status throughout. Returns True on success.
    """
    client = None
    sftp   = None
    try:
        result.update(status="CONNECTING")
        client = _connect(node)

        _, home_out = _exec(client, "echo $HOME")
        home        = home_out.strip()
        remote_root = f"{home}/{REMOTE_BASE}"

        # Verify Python 3.9+
        code, ver_out = _exec(client, "python3 --version 2>&1")
        result.append_log(f"Python: {ver_out.strip()}")
        if code != 0:
            raise RuntimeError("python3 not found on remote node — install Python 3.9+")

        # Upload source
        result.update(status="UPLOADING")
        result.append_log(f"Uploading to {node.host}:{remote_root} ...")
        sftp = client.open_sftp()
        fc   = _sftp_upload_dir(sftp, local_root, remote_root)
        result.append_log(f"Uploaded {fc} files.")

        # Install deps
        result.update(status="INSTALLING")
        result.append_log("Running pip install ...")
        pip_cmd = (
            f"python3 -m pip install -r {remote_root}/requirements.txt -q 2>&1 | tail -4"
        )
        code, pip_out = _exec(client, pip_cmd, timeout=PIP_TIMEOUT)
        if code != 0:
            raise RuntimeError(f"pip install failed:\n{pip_out[-300:]}")
        result.append_log("Dependencies installed.")

        # Smoke test
        code, _ = _exec(client, f"python3 {remote_root}/botstrike.py --help > /dev/null 2>&1")
        if code != 0:
            raise RuntimeError("Smoke test failed — botstrike.py did not start correctly")

        result.append_log(f"Node ready  {node.user}@{node.host}")
        result.update(status="DONE", end_time=time.time())
        return True

    except Exception as e:
        err = str(e)[:200]
        result.update(status="FAILED", error=err, end_time=time.time())
        result.append_log(f"FAILED: {err}")
        return False
    finally:
        if sftp:
            try: sftp.close()
            except: pass
        if client:
            try: client.close()
            except: pass


# ─── Remote command builder ────────────────────────────────────────────────────

def _build_remote_cmd(node: NodeConfig, url: str, args, home: str) -> str:
    """Construct the botstrike.py command to run on the remote node."""
    remote_root = f"{home}/{REMOTE_BASE}"
    flags = [
        f"--url '{url}'",
        f"--mode {getattr(args, 'mode', 'scrape')}",
        "--yes",
        f"--operator '{node.id}@{node.host}'",
        f"--profile {getattr(args, 'profile', 'medium') or 'medium'}",
    ]
    if getattr(args, "confirm_authorized", False):
        flags.append("--confirm-authorized")
    if getattr(args, "rps", None) is not None:
        flags.append(f"--rps {args.rps}")
    if getattr(args, "duration", None) is not None:
        flags.append(f"--duration {args.duration}")
    if getattr(args, "connections", None) is not None:
        flags.append(f"--connections {args.connections}")

    return f"cd {remote_root} && python3 botstrike.py {' '.join(flags)}"


# ─── Node worker (one thread per node) ───────────────────────────────────────

def run_node_worker(
    node:       NodeConfig,
    url:        str,
    args,
    cfg:        dict,
    result:     NodeResult,
    local_root: Path,
    output_dir: Path,
) -> None:
    """
    Full lifecycle for one node:
      connect → upload → install → run botstrike → download report → parse metrics
    Designed to run in a daemon thread. Updates result in-place throughout.
    """
    client = None
    sftp   = None
    try:
        # ── Connect ──────────────────────────────────────────────────────────
        result.update(status="CONNECTING")
        client = _connect(node)

        _, home_out = _exec(client, "echo $HOME")
        home        = home_out.strip()
        remote_root = f"{home}/{REMOTE_BASE}"

        # ── Upload ───────────────────────────────────────────────────────────
        result.update(status="UPLOADING")
        result.append_log(f"Uploading BotStrike to {node.host}:{remote_root} ...")
        sftp = client.open_sftp()
        fc   = _sftp_upload_dir(sftp, local_root, remote_root)
        result.append_log(f"Uploaded {fc} files.")

        # ── Install deps ─────────────────────────────────────────────────────
        result.update(status="INSTALLING")
        result.append_log("Installing Python dependencies ...")
        code, pip_out = _exec(
            client,
            f"python3 -m pip install -r {remote_root}/requirements.txt -q 2>&1 | tail -4",
            timeout=PIP_TIMEOUT,
        )
        if code != 0:
            raise RuntimeError(f"pip install failed on {node.host}: {pip_out[-200:]}")
        result.append_log("Dependencies ready.")

        # ── Timestamp marker (used to locate the new report after the run) ──
        marker = f"/tmp/.bs_{int(time.time())}_{node.id.replace('-', '_')}"
        _exec(client, f"touch {marker}")

        # ── Run BotStrike ─────────────────────────────────────────────────────
        result.update(status="RUNNING")
        remote_cmd = _build_remote_cmd(node, url, args, home)
        result.append_log(f"Starting BotStrike ...")

        _exec(
            client,
            f"{remote_cmd} 2>&1",
            on_line=result.append_log,
            timeout=None,           # no per-recv timeout — run can take 30+ min
        )

        # ── Locate report ────────────────────────────────────────────────────
        result.update(phase="Reporting")
        result.append_log("Locating report file ...")
        _, find_out = _exec(
            client,
            f"find {remote_root}/reports -name '*.json' -newer {marker} 2>/dev/null | sort | tail -1",
            timeout=30,
        )
        json_remote = find_out.strip()

        node_out = output_dir / node.id
        node_out.mkdir(parents=True, exist_ok=True)

        if json_remote:
            # Download JSON
            local_json = node_out / Path(json_remote).name
            sftp.get(json_remote, str(local_json))
            result.update(json_path=local_json)
            result.append_log(f"Downloaded: {local_json.name}")

            # Try to download HTML too
            try:
                html_remote = json_remote.replace(".json", ".html")
                local_html  = node_out / Path(html_remote).name
                sftp.get(html_remote, str(local_html))
                result.update(html_path=local_html)
                result.append_log(f"Downloaded: {local_html.name}")
            except IOError:
                pass

            # Parse key metrics for the live table
            try:
                with open(local_json, encoding="utf-8") as jf:
                    jdata = json.load(jf)
                result.update(json_data=jdata)
                _parse_metrics(result, jdata)
            except Exception:
                pass
        else:
            result.append_log("[!] No JSON report found — check remote botstrike logs")

        result.update(status="DONE", end_time=time.time())

    except FileNotFoundError as e:
        result.update(status="FAILED", error=str(e), end_time=time.time())
        result.append_log(f"FAILED: {e}")
    except Exception as e:
        err = str(e)[:200]
        result.update(status="FAILED", error=err, end_time=time.time())
        result.append_log(f"FAILED: {err}")
    finally:
        if sftp:
            try: sftp.close()
            except: pass
        if client:
            try: client.close()
            except: pass


# ─── Report merging ───────────────────────────────────────────────────────────

def merge_results(node_results: list[NodeResult], target_url: str) -> dict:
    """
    Aggregate per-node JSON data into a single fleet-level report dict.
    Successful nodes with downloaded JSON are included in aggregation.
    """
    ok = [r for r in node_results if r.status == "DONE" and r.json_data]

    def _wavg_blocked(phase_key: str) -> float:
        total, wsum = 0, 0.0
        for r in ok:
            d    = r.json_data.get("scraping", {}).get(phase_key, {})
            reqs = d.get("total_requests", 0)
            pct  = d.get("blocked_pct", 0.0)
            total += reqs
            wsum  += reqs * pct
        return round(wsum / total, 1) if total else 0.0

    total_stealth = sum(r.json_data.get("scraping", {}).get("stealth",    {}).get("total_requests", 0) for r in ok)
    total_agg     = sum(r.json_data.get("scraping", {}).get("aggressive", {}).get("total_requests", 0) for r in ok)
    total_items   = sum(r.json_data.get("scraping", {}).get("stealth",    {}).get("items_extracted", 0) for r in ok)

    # Aggregate DDoS vectors: sum requests, sum RPS (nodes run in parallel), avg blocked%
    ddos_agg: dict = {}
    for r in ok:
        for vec, vdata in r.json_data.get("ddos", {}).items():
            if not isinstance(vdata, dict):
                continue
            if vec not in ddos_agg:
                ddos_agg[vec] = {"total_requests": 0, "rps_combined": 0.0,
                                 "blocked_pct_avg": 0.0, "latency_avg_ms": 0.0, "_n": 0}
            ddos_agg[vec]["total_requests"]  += vdata.get("total_requests", 0)
            ddos_agg[vec]["rps_combined"]    += vdata.get("rps_avg", 0.0)
            ddos_agg[vec]["blocked_pct_avg"] += vdata.get("blocked_pct", 0.0)
            ddos_agg[vec]["latency_avg_ms"]  += vdata.get("latency_avg_ms", 0.0)
            ddos_agg[vec]["_n"]              += 1
    for v in ddos_agg.values():
        n = v.pop("_n", 1) or 1
        v["blocked_pct_avg"] = round(v["blocked_pct_avg"] / n, 1)
        v["latency_avg_ms"]  = round(v["latency_avg_ms"]  / n, 1)
        v["rps_combined"]    = round(v["rps_combined"], 1)

    # Score: average across nodes (same target, should be similar)
    scores = [r.json_data.get("score", {}).get("score", 0) for r in ok]
    avg_score = round(sum(scores) / len(scores)) if scores else 0
    if avg_score >= 90:   avg_grade = "A"
    elif avg_score >= 80: avg_grade = "B"
    elif avg_score >= 65: avg_grade = "C"
    elif avg_score >= 50: avg_grade = "D"
    else:                 avg_grade = "F"

    # Recommendations: union, deduplicated by title
    seen: set[str] = set()
    recs: list[dict] = []
    for r in ok:
        for rec in r.json_data.get("recommendations", []):
            t = rec.get("title", "")
            if t not in seen:
                seen.add(t)
                recs.append(rec)

    return {
        "distributed": {
            "node_count":   len(node_results),
            "nodes_ok":     len(ok),
            "nodes_failed": len(node_results) - len(ok),
            "target":       target_url,
            "generated_at": now_utc(),
            "tool_version": TOOL_VERSION,
        },
        "aggregated": {
            "total_requests_stealth":     total_stealth,
            "total_requests_aggressive":  total_agg,
            "total_requests_all":         total_stealth + total_agg,
            "items_extracted_total":      total_items,
            "stealth_blocked_pct_avg":    _wavg_blocked("stealth"),
            "aggressive_blocked_pct_avg": _wavg_blocked("aggressive"),
            "ddos_vectors":               ddos_agg,
            "score":                      avg_score,
            "grade":                      avg_grade,
            "recommendations":            recs,
        },
        "per_node": [
            {
                "node_id":    r.node_id,
                "host":       r.host,
                "status":     r.status,
                "score":      r.score,
                "grade":      r.grade,
                "blocked_pct": r.blocked_pct,
                "requests":   r.requests,
                "error":      r.error,
                "html_report": str(r.html_path) if r.html_path else None,
                "json_report": str(r.json_path) if r.json_path else None,
                "log_tail":   r.log_lines[-30:],
                "data":       r.json_data,
            }
            for r in node_results
        ],
    }


# ─── Main orchestrator ────────────────────────────────────────────────────────

def run_distributed(target_url: str, args, cfg: dict) -> None:
    """Entry point when --distributed is passed. Runs all nodes in parallel."""
    if not HAS_PARAMIKO:
        console.print("[bold red][!] paramiko is required for distributed mode.[/bold red]")
        console.print("    Run:  pip install paramiko")
        sys.exit(1)

    nodes_path = getattr(args, "nodes", "nodes.yaml") or "nodes.yaml"
    nodes      = load_nodes(nodes_path)

    phase_banner("DISTRIBUTED MODE")
    console.print(f"  [bold]Target:[/bold] [cyan]{target_url}[/cyan]")
    console.print(f"  [bold]Fleet: [/bold] {len(nodes)} node(s)\n")
    for n in nodes:
        console.print(f"    [cyan]{n.id:<16}[/cyan] {n.user}@{n.host}:{n.port}  key: {n.key}")
    console.print()

    # Output directory for this distributed run
    from datetime import datetime as _dt
    ts         = _dt.now().strftime("%Y%m%d_%H%M%S")
    local_root = Path(__file__).parent.parent.resolve()
    output_dir = local_root / "reports" / f"distributed_{ts}"
    output_dir.mkdir(parents=True, exist_ok=True)

    results = [NodeResult(node_id=n.id, host=n.host) for n in nodes]

    # Launch one thread per node (all run simultaneously)
    threads = []
    for node, result in zip(nodes, results):
        t = threading.Thread(
            target=run_node_worker,
            args=(node, target_url, args, cfg, result, local_root, output_dir),
            daemon=True,
        )
        t.start()
        threads.append(t)

    # Live status table — refreshes every 500ms
    start = time.time()
    with Live(console=console, refresh_per_second=2, screen=False) as live:
        while any(t.is_alive() for t in threads):
            live.update(_build_fleet_table(results, target_url, time.time() - start))
            time.sleep(0.5)
        live.update(_build_fleet_table(results, target_url, time.time() - start))

    for t in threads:
        t.join()

    # ── Final summary ────────────────────────────────────────────────────────
    done   = sum(1 for r in results if r.status == "DONE")
    failed = sum(1 for r in results if r.status == "FAILED")
    console.print()
    console.rule("[bold cyan]DISTRIBUTED RUN COMPLETE[/bold cyan]")
    console.print(
        f"\n  Completed: [green]{done}/{len(results)}[/green]  "
        f"Failed: [red]{failed}[/red]  "
        f"Total time: [cyan]{int(time.time() - start)}s[/cyan]\n"
    )

    # Merge and save
    merged     = merge_results(results, target_url)
    merged_path = output_dir / "merged_report.json"
    with open(merged_path, "w", encoding="utf-8") as f:
        json.dump(merged, f, indent=2, default=str)

    agg = merged.get("aggregated", {})
    console.print(f"  [bold]Aggregated score:[/bold]  {agg.get('grade', '—')} ({agg.get('score', 0)})")
    console.print(f"  [bold]Total requests:  [/bold]  {agg.get('total_requests_all', 0):,}")
    console.print(f"  [bold]Items extracted: [/bold]  {agg.get('items_extracted_total', 0):,}")

    console.print(f"\n  [bold green]Merged report:[/bold green] {merged_path}")
    console.print("\n  [bold]Per-node reports:[/bold]")
    for r in results:
        icon = "[green]✓[/green]" if r.status == "DONE" else "[red]✗[/red]"
        path = str(r.html_path or r.json_path or "no report")
        console.print(f"    {icon}  [cyan]{r.node_id:<16}[/cyan]  {path}")

    console.print(f"\n  [dim]All output in:[/dim] {output_dir}\n")


# ─── --setup-nodes command ────────────────────────────────────────────────────

def cmd_setup_nodes(nodes_path: str) -> None:
    """Bootstrap all nodes in parallel: upload + install deps + smoke-test."""
    if not HAS_PARAMIKO:
        console.print("[bold red][!] paramiko is required.[/bold red]  Run: pip install paramiko")
        sys.exit(1)

    nodes      = load_nodes(nodes_path)
    local_root = Path(__file__).parent.parent.resolve()

    phase_banner("NODE SETUP")
    console.print(f"  Bootstrapping {len(nodes)} node(s) in parallel ...\n")

    results = [NodeResult(node_id=n.id, host=n.host) for n in nodes]
    threads = []
    for node, result in zip(nodes, results):
        t = threading.Thread(target=setup_node, args=(node, local_root, result), daemon=True)
        t.start()
        threads.append(t)

    start = time.time()
    with Live(console=console, refresh_per_second=2, screen=False) as live:
        while any(t.is_alive() for t in threads):
            live.update(_build_fleet_table(results, "node setup", time.time() - start))
            time.sleep(0.5)
        live.update(_build_fleet_table(results, "node setup", time.time() - start))

    for t in threads:
        t.join()

    done   = sum(1 for r in results if r.status == "DONE")
    failed = sum(1 for r in results if r.status == "FAILED")
    console.rule("[bold]SETUP COMPLETE[/bold]")
    console.print(f"\n  Ready: [green]{done}/{len(results)}[/green]   Failed: [red]{failed}[/red]\n")

    if failed:
        for r in results:
            if r.status == "FAILED":
                console.print(f"  [red]✗ {r.node_id:<14}[/red] {r.error}")
        console.print()

    if done > 0:
        console.print("  [green]Nodes are ready. Run:[/green]")
        console.print(f"    python botstrike.py --url <TARGET> --distributed --nodes {nodes_path}\n")
