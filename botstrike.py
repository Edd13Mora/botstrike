#!/usr/bin/env python3
"""
BotStrike v1.0 — Bot Protection Effectiveness Tester
For authorized security testing only.
"""
import argparse
import importlib.util
import logging
import subprocess
import sys
import signal
from pathlib import Path
from typing import Optional

# Force UTF-8 output so Unicode status icons render on all platforms
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ─── Dependency check must run before any third-party imports ────────────────

REQUIRED_PACKAGES = [
    ("requests",        "requests"),
    ("rich",            "rich"),
    ("bs4",             "beautifulsoup4"),
    ("lxml",            "lxml"),
    ("yaml",            "pyyaml"),
    ("aiohttp",         "aiohttp"),
    ("fake_useragent",  "fake-useragent"),
    ("jinja2",          "jinja2"),
    ("urllib3",         "urllib3"),
]


def _check_python() -> None:
    if sys.version_info < (3, 9):
        print(f"[ERROR] Python >= 3.9 required. Found: {sys.version}")
        print("        Install: https://www.python.org/downloads/")
        sys.exit(1)


def _check_deps() -> None:
    import shutil

    rows: list[tuple[str, str, str]] = []
    failed: list[str] = []

    for import_name, pip_name in REQUIRED_PACKAGES:
        if importlib.util.find_spec(import_name) is not None:
            rows.append((pip_name, "already installed", "ok"))
        else:
            print(f"  [↓] {pip_name:<22} installing...", end="", flush=True)
            result = subprocess.run(
                [sys.executable, "-m", "pip", "install", pip_name, "--quiet"],
                capture_output=True, text=True
            )
            if result.returncode == 0:
                rows.append((pip_name, "installed", "installed"))
                print(" done")
            else:
                rows.append((pip_name, "FAILED", "failed"))
                failed.append(pip_name)
                print(" FAILED")

    print()
    for pkg, status, state in rows:
        icon = {"ok": "✔", "installed": "↓", "failed": "✘"}.get(state, "?")
        print(f"  [{icon}] {pkg:<22} {status}")

    # ── External tools ────────────────────────────────────────────────────────
    print()
    print("  External tools:")
    katana_path = shutil.which("katana")
    if katana_path:
        print(f"  [✔] katana                 found ({katana_path})")
    else:
        print("  [i] katana                 not found — will auto-install on first recon")
    print()

    if failed:
        print("[ERROR] Some dependencies failed to install:")
        for pkg in failed:
            print(f"  run: pip3 install {pkg}")
        sys.exit(1)


_check_python()
_check_deps()

# ─── Now safe to import third-party ─────────────────────────────────────────

import yaml
from rich.prompt import Confirm

from modules import preflight, recon, scraper, ddos, reporter, goodbot, openapi as openapi_mod, endpoint_probe
from modules.utils import (
    console, log, print_banner, new_session_id, make_report_dir,
    setup_file_logger, now_utc, phase_banner, TOOL_VERSION,
)

# ─── Globals for graceful CTRL+C ─────────────────────────────────────────────

_session_data: dict = {}
_preflight_data: dict = {}
_goodbot_data: dict = {}
_openapi_data: dict = {}
_endpoint_data: dict = {}
_recon_data: dict = {}
_scraping_data: dict = {"stealth": {}, "aggressive": {}}
_ddos_data: dict = {}
_report_dir: Optional[Path] = None
_logger: Optional[logging.Logger] = None
_interrupted = False


def _save_partial_and_exit(sig, frame) -> None:
    global _interrupted, _session_data, _preflight_data, _goodbot_data, _openapi_data
    global _endpoint_data, _recon_data, _scraping_data, _ddos_data, _report_dir, _logger
    _interrupted = True
    console.print("\n\n[bold yellow][!] Interrupted — saving partial report...[/bold yellow]")

    if _report_dir and _session_data:
        _session_data["end_time"] = now_utc()
        _session_data["interrupted"] = True
        try:
            json_path = reporter.build_json_report(
                _session_data, _preflight_data, _recon_data,
                _scraping_data, _ddos_data, _report_dir,
                goodbot_data=_goodbot_data,
                openapi_data=_openapi_data,
                endpoint_data=_endpoint_data,
            )
            html_path = reporter.build_html_report(
                _session_data, _preflight_data, _recon_data,
                _scraping_data, _ddos_data, _report_dir,
                goodbot_data=_goodbot_data,
                openapi_data=_openapi_data,
                endpoint_data=_endpoint_data,
            )
            log_path = _report_dir / f"botstrike_{_session_data['id']}.log"
            reporter.print_final_summary(
                _session_data, _preflight_data, _scraping_data, _ddos_data,
                json_path, html_path, log_path if log_path.exists() else None
            )
        except Exception as e:
            console.print(f"[red]Partial report error: {e}[/red]")

    sys.exit(0)


signal.signal(signal.SIGINT, _save_partial_and_exit)


# ─── CLI ─────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    description = (
        f"BotStrike v{TOOL_VERSION} — Bot Protection Effectiveness Tester\n"
        "─────────────────────────────────────────────────────────────────\n"
        "Authorized tool for comparing bot-protection stacks (DataDome,\n"
        "CrowdSec, Cloudflare, etc.) against realistic attack patterns.\n"
        "\n"
        "Runs three sequential phases:\n"
        "  0 · Pre-flight    WAF/CDN fingerprinting & probe analysis\n"
        "  1 · Recon         robots.txt, sitemap, homepage crawl\n"
        "  2 · Scraping      Stealth mode then Aggressive mode\n"
        "  3 · DDoS          4-vector HTTP stress test (auth required)\n"
        "\n"
        "Reports are saved to:  reports/<host>_<YYYYMMDD>_<HHMMSS>/\n"
        "  · botstrike_<sessionid>.json   machine-readable full results\n"
        "  · botstrike_<sessionid>.html   dark-themed dashboard w/ charts\n"
        "  · botstrike_<sessionid>.log    timestamped raw activity log"
    )

    epilog = (
        "────────────────────────────── EXAMPLES ──────────────────────────────\n"
        "\n"
        "  Scraping only (no DDoS, no auth flag needed):\n"
        "    python botstrike.py --url https://shop.example.com --mode scrape\n"
        "\n"
        "  Full test with DDoS at default settings:\n"
        "    python botstrike.py --url https://shop.example.com \\\n"
        "                        --mode full --confirm-authorized\n"
        "\n"
        "  Full test, faster (30s vectors instead of 60s):\n"
        "    python botstrike.py --url https://shop.example.com \\\n"
        "                        --mode full --confirm-authorized --duration 30\n"
        "\n"
        "  High-volume HTTP flood benchmark (200 RPS, 2 min):\n"
        "    python botstrike.py --url https://shop.example.com \\\n"
        "                        --mode ddos --confirm-authorized \\\n"
        "                        --rps 200 --duration 120\n"
        "\n"
        "  Non-interactive CI/CD run with custom operator tag:\n"
        "    python botstrike.py --url https://shop.example.com \\\n"
        "                        --mode full --confirm-authorized \\\n"
        "                        --operator \"pentester@company.com\" --yes\n"
        "\n"
        "  Use a custom config file:\n"
        "    python botstrike.py --url https://shop.example.com \\\n"
        "                        --config /path/to/my_config.yaml --mode scrape\n"
        "\n"
        "──────────────────────────── DDoS VECTORS ────────────────────────────\n"
        "\n"
        "  Vector 1 · HTTP Flood     High-volume GET flood with ramp-up\n"
        "  Vector 2 · Slowloris      Many slow connections, partial headers\n"
        "  Vector 3 · POST Flood     Random payloads to checkout/login/search\n"
        "  Vector 4 · Cache Buster   Unique query strings bypass CDN caches\n"
        "\n"
        "  Vectors run sequentially with a 10s pause between each.\n"
        "\n"
        "──────────────────────────── LEGAL NOTICE ────────────────────────────\n"
        "\n"
        "  This tool is for AUTHORIZED security testing only.\n"
        "  Unauthorized use against systems you do not own or have explicit\n"
        "  written permission to test is illegal. --confirm-authorized is a\n"
        "  binding declaration that you hold such authorization.\n"
    )

    p = argparse.ArgumentParser(
        prog="python botstrike.py",
        description=description,
        epilog=epilog,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=True,
    )

    # ── Target ──────────────────────────────────────────────────────────────
    g_target = p.add_argument_group("target")
    g_target.add_argument(
        "--url",
        required=False,
        default=None,
        metavar="URL",
        help=(
            "Full URL of the target web application.\n"
            "Must include scheme (https:// recommended).\n"
            "Example: https://shop.rexel.fr"
        ),
    )

    # ── Test control ────────────────────────────────────────────────────────
    g_mode = p.add_argument_group("test control")
    g_mode.add_argument(
        "--mode",
        choices=["scrape", "ddos", "full"],
        default="full",
        metavar="MODE",
        help=(
            "Which test modules to run.\n"
            "  scrape  Recon + stealth scraping + aggressive scraping only\n"
            "  ddos    Recon + 4-vector DDoS simulation only\n"
            "  full    All phases end-to-end  (default)\n"
            "Note: ddos and full require --confirm-authorized."
        ),
    )
    g_mode.add_argument(
        "--confirm-authorized",
        action="store_true",
        help=(
            "Safety gate required to unlock the DDoS module.\n"
            "By passing this flag you declare that you have explicit\n"
            "written authorization from the target system owner.\n"
            "Without this flag, --mode ddos exits; --mode full falls\n"
            "back to scrape-only."
        ),
    )
    g_mode.add_argument(
        "--yes",
        action="store_true",
        help=(
            "Skip all interactive confirmation prompts (non-interactive / CI mode).\n"
            "The pre-flight 'Proceed?' prompt will be auto-accepted."
        ),
    )

    # ── DDoS tuning ─────────────────────────────────────────────────────────
    g_ddos = p.add_argument_group("ddos tuning  (only relevant with --mode ddos or full)")
    g_ddos.add_argument(
        "--rps",
        type=int,
        default=100,
        metavar="N",
        help=(
            "Target requests-per-second for the HTTP Flood vector.\n"
            "Ramps from 0 to N over the first 30s, then sustains.\n"
            "Default: 100"
        ),
    )
    g_ddos.add_argument(
        "--duration",
        type=int,
        default=60,
        metavar="SECONDS",
        help=(
            "How long each DDoS vector runs, in seconds.\n"
            "Applies to all 4 vectors equally.\n"
            "Use 30 for a quicker run, 120+ for sustained pressure.\n"
            "Default: 60"
        ),
    )
    g_ddos.add_argument(
        "--connections",
        type=int,
        default=200,
        metavar="N",
        help=(
            "Number of concurrent connections for the Slowloris vector.\n"
            "Each connection sends partial headers every 10s to keep\n"
            "the server socket open.\n"
            "Default: 200"
        ),
    )

    # ── Authentication ──────────────────────────────────────────────────────
    g_auth = p.add_argument_group("authentication")
    g_auth.add_argument(
        "--basic-auth",
        default=None,
        metavar="USER:PASS",
        dest="basic_auth",
        help=(
            "HTTP Basic Auth credentials for sites protected by htaccess / staging auth.\n"
            "Format: username:password\n"
            "Applied to every request across all modules.\n"
            "Example: --basic-auth staging:secret123"
        ),
    )

    # ── Output & metadata ───────────────────────────────────────────────────
    g_out = p.add_argument_group("output & metadata")
    g_out.add_argument(
        "--operator",
        default="",
        metavar="NAME",
        help=(
            "Operator identifier embedded in the report (name or email).\n"
            "Appears in JSON, HTML footer, and log for accountability.\n"
            "Example: --operator \"j.doe@company.com\""
        ),
    )
    g_out.add_argument(
        "--config",
        default="config.yaml",
        metavar="FILE",
        help=(
            "Path to a YAML config file for advanced settings.\n"
            "CLI flags always override config file values.\n"
            "See config.yaml for all available keys.\n"
            "Default: config.yaml  (in the botstrike directory)"
        ),
    )

    # ── Behaviour presets ────────────────────────────────────────────────────
    g_preset = p.add_argument_group("behaviour presets")
    g_preset.add_argument(
        "--profile",
        choices=["light", "medium", "heavy", "stealth"],
        default="medium",
        metavar="PROFILE",
        help=(
            "Load a named configuration preset (overridden by explicit CLI flags).\n"
            "  light    Quick scan — 30s vectors, 30 RPS, 2 scraping threads\n"
            "  medium   Balanced defaults — 60s vectors, 100 RPS  (default)\n"
            "  heavy    Sustained pressure — 120s vectors, 300 RPS, 20 threads\n"
            "  stealth  Maximum evasion — 1 thread, 5-12s delays, 10 RPS\n"
            "Useful shorthand: --profile heavy instead of specifying every flag."
        ),
    )
    g_preset.add_argument(
        "--proxy",
        default=None,
        metavar="URL",
        help=(
            "Route all HTTP traffic through this proxy.\n"
            "Supports HTTP and SOCKS5 proxies.\n"
            "Examples:\n"
            "  --proxy http://proxyhost:8080\n"
            "  --proxy socks5://127.0.0.1:9050   (Tor)\n"
            "Proxy applies to all modules: preflight, recon, scraping, DDoS."
        ),
    )

    # ── Compare mode ─────────────────────────────────────────────────────────
    g_cmp = p.add_argument_group(
        "compare mode  (DataDome vs CrowdSec side-by-side)",
        description=(
            "Run the same test against two targets and generate a side-by-side\n"
            "comparison report — ideal for DataDome vs CrowdSec engagements."
        ),
    )
    g_cmp.add_argument(
        "--compare",
        action="store_true",
        help=(
            "Enable compare mode. Requires --url-a and --url-b.\n"
            "The --url flag is ignored in this mode.\n"
            "Generates individual reports for each target PLUS a unified\n"
            "comparison dashboard (comparison.html) in reports/compare_<ts>/."
        ),
    )
    g_cmp.add_argument(
        "--url-a",
        default=None,
        metavar="URL",
        help="First target URL for comparison (e.g. the DataDome-protected site).",
    )
    g_cmp.add_argument(
        "--url-b",
        default=None,
        metavar="URL",
        help="Second target URL for comparison (e.g. the CrowdSec-protected site).",
    )
    g_cmp.add_argument(
        "--label-a",
        default="Target A",
        metavar="NAME",
        help=(
            "Human-readable label for Target A shown in the comparison report.\n"
            "Example: --label-a \"DataDome\"  (default: 'Target A')"
        ),
    )
    g_cmp.add_argument(
        "--label-b",
        default="Target B",
        metavar="NAME",
        help=(
            "Human-readable label for Target B shown in the comparison report.\n"
            "Example: --label-b \"CrowdSec\"  (default: 'Target B')"
        ),
    )

    # ── Distributed mode ─────────────────────────────────────────────────────
    g_dist = p.add_argument_group(
        "distributed mode  (multi-VPS fleet execution)",
        description=(
            "Run BotStrike simultaneously across a fleet of Linux VPS nodes.\n"
            "Each node sends traffic from its own IP, bypassing per-IP rate limits.\n"
            "All results are merged into a unified fleet report locally."
        ),
    )
    g_dist.add_argument(
        "--distributed",
        action="store_true",
        help=(
            "Enable distributed execution. Requires --nodes (or nodes.yaml in cwd).\n"
            "All nodes in the fleet run simultaneously against the same --url.\n"
            "Auth key only — configure node IPs and keys in nodes.yaml."
        ),
    )
    g_dist.add_argument(
        "--nodes",
        default="nodes.yaml",
        metavar="FILE",
        help=(
            "Path to fleet config YAML.  Default: nodes.yaml\n"
            "See nodes.yaml.example for format and setup instructions."
        ),
    )
    g_dist.add_argument(
        "--setup-nodes",
        action="store_true",
        dest="setup_nodes",
        help=(
            "Bootstrap all nodes in --nodes, then exit.\n"
            "Uploads BotStrike, installs Python deps, runs a smoke test.\n"
            "Run this once before your first --distributed engagement."
        ),
    )

    return p.parse_args()


# ─── Profile presets ─────────────────────────────────────────────────────────

PROFILES: dict[str, dict] = {
    "light": {
        "scraping": {
            "stealth":    {"threads": 2, "delay_min": 2.5, "delay_max": 6.0, "max_pages": 30},
            "aggressive": {"threads": 4, "max_pages": 50},
        },
        "ddos": {"rps": 30,  "duration": 30,  "connections": 50,  "ramp_up_seconds": 15, "pause_between_vectors": 5},
    },
    "medium": {
        "scraping": {
            "stealth":    {"threads": 3, "delay_min": 1.5, "delay_max": 4.0, "max_pages": 100},
            "aggressive": {"threads": 10, "max_pages": 200},
        },
        "ddos": {"rps": 100, "duration": 60,  "connections": 200, "ramp_up_seconds": 30, "pause_between_vectors": 10},
    },
    "heavy": {
        "scraping": {
            "stealth":    {"threads": 5, "delay_min": 1.0, "delay_max": 2.5, "max_pages": 300},
            "aggressive": {"threads": 20, "max_pages": 500},
        },
        "ddos": {"rps": 300, "duration": 120, "connections": 500, "ramp_up_seconds": 60, "pause_between_vectors": 10},
    },
    "stealth": {
        "scraping": {
            "stealth":    {"threads": 1, "delay_min": 5.0, "delay_max": 12.0, "max_pages": 50},
            "aggressive": {"threads": 1, "max_pages": 20},
        },
        "ddos": {"rps": 10, "duration": 30, "connections": 20, "ramp_up_seconds": 60, "pause_between_vectors": 15},
    },
}


# ─── Config helpers ───────────────────────────────────────────────────────────

def load_config(path: str) -> dict:
    cfg_path = Path(path)
    if cfg_path.exists():
        with open(cfg_path, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    return {}


def merge_cfg(file_cfg: dict, args: argparse.Namespace) -> dict:
    # Start from profile (or medium default)
    profile_name = getattr(args, "profile", "medium") or "medium"
    base = PROFILES.get(profile_name, PROFILES["medium"])

    import copy
    cfg: dict = copy.deepcopy(base)
    cfg["preflight"] = {"timeout": 10}

    # Apply file overrides
    if "scraping" in file_cfg:
        for phase in ("stealth", "aggressive"):
            if phase in file_cfg["scraping"]:
                cfg["scraping"][phase].update(file_cfg["scraping"][phase])
    if "ddos" in file_cfg:
        cfg["ddos"].update(file_cfg["ddos"])

    # CLI flags always win
    if getattr(args, "rps", None) is not None:
        cfg["ddos"]["rps"] = args.rps
    if getattr(args, "duration", None) is not None:
        cfg["ddos"]["duration"] = args.duration
    if getattr(args, "connections", None) is not None:
        cfg["ddos"]["connections"] = args.connections

    return cfg


# ─── Single-target test runner ────────────────────────────────────────────────

def run_one_target(target_url: str, args: argparse.Namespace, cfg: dict,
                   label: str = "") -> dict:
    """
    Run the full pipeline on one target URL and return all collected data
    as a flat dict.  Used by both single-target and --compare modes.
    """
    global _session_data, _preflight_data, _goodbot_data, _openapi_data, _endpoint_data
    global _recon_data, _scraping_data, _ddos_data, _report_dir, _logger

    session_id  = new_session_id()
    report_dir  = make_report_dir(target_url, session_id)
    logger      = setup_file_logger(report_dir, session_id)
    _report_dir = report_dir
    _logger     = logger

    effective_mode = args.mode
    if effective_mode in ("ddos", "full") and not args.confirm_authorized:
        effective_mode = "scrape"

    session_data: dict = {
        "id":           session_id,
        "target":       target_url,
        "label":        label,
        "operator":     args.operator or "Unknown",
        "tool_version": TOOL_VERSION,
        "start_time":   now_utc(),
        "end_time":     "",
        "mode":         effective_mode,
        "authorized":   args.confirm_authorized,
        "interrupted":  False,
    }
    _session_data = session_data

    log(f"[{label or target_url}] Session {session_id} started", "info", logger)

    phase_banner("MODULE 0: PRE-FLIGHT FINGERPRINTING")
    preflight_data = preflight.run(target_url, timeout=cfg["preflight"]["timeout"], logger=logger)
    _preflight_data = preflight_data

    if not preflight_data.get("target_alive"):
        log(f"[{label}] Target unreachable — skipping.", "error", logger)
        session_data["end_time"] = now_utc()
        return {
            "session": session_data, "preflight": preflight_data,
            "recon": {}, "scraping": {"stealth": {}, "aggressive": {}}, "ddos": {},
            "score": {}, "recommendations": [], "report_dir": report_dir,
        }

    goodbot_data = goodbot.run(target_url, cfg, logger)
    _goodbot_data = goodbot_data

    openapi_data = openapi_mod.run(target_url, cfg, logger)
    _openapi_data = openapi_data

    phase_banner("MODULE 1: PASSIVE RECON")
    recon_data = recon.run(target_url, timeout=cfg["preflight"]["timeout"], logger=logger)
    _recon_data = recon_data
    all_urls         = recon_data.get("all_discovered_urls", [target_url])
    classified_flows = recon_data.get("classified_flows", {})

    # Add OpenAPI-discovered endpoint URLs to the attack pool
    api_ep_urls = [ep["url"] for ep in openapi_data.get("swagger_endpoints", []) if ep.get("url")]
    if api_ep_urls:
        all_urls = list(set(all_urls + api_ep_urls))
        classified_flows = recon.classify_flows(all_urls)
        console.print(f"  [cyan]+ {len(api_ep_urls)} URLs from OpenAPI spec added to attack pool[/cyan]")

    if classified_flows:
        flow_names = ", ".join(classified_flows.keys())
        console.print(f"  [bold cyan]Attack flows found:[/bold cyan] {flow_names}")

    endpoint_data = endpoint_probe.run(
        target_url, classified_flows, cfg,
        authorized=args.confirm_authorized,
        logger=logger,
    )
    _endpoint_data = endpoint_data

    scraping_data: dict = {"stealth": {}, "aggressive": {}}
    if effective_mode in ("scrape", "full"):
        scraping_data["stealth"]    = scraper.run_stealth(target_url, all_urls, cfg["scraping"]["stealth"], logger)
        scraping_data["aggressive"] = scraper.run_aggressive(target_url, all_urls, cfg["scraping"]["aggressive"], logger)
    _scraping_data = scraping_data

    ddos_data: dict = {}
    if effective_mode in ("ddos", "full") and args.confirm_authorized:
        phase_banner("MODULE 3: DDOS SIMULATION")
        ddos_data = ddos.run(target_url, all_urls, cfg["ddos"],
                             classified_flows=classified_flows, logger=logger)
    _ddos_data = ddos_data

    session_data["end_time"] = now_utc()

    score_data   = reporter.calculate_protection_score(preflight_data, scraping_data, ddos_data,
                                                       goodbot_data=goodbot_data,
                                                       openapi_data=openapi_data,
                                                       endpoint_data=endpoint_data)
    recs         = reporter.generate_recommendations(preflight_data, scraping_data, ddos_data,
                                                     score_data, goodbot_data=goodbot_data,
                                                     openapi_data=openapi_data,
                                                     endpoint_data=endpoint_data)
    prev_report  = reporter.load_previous_report(target_url, session_id)
    deltas: dict = {}

    if prev_report:
        prev_full = {
            "scraping": prev_report.get("scraping", {}),
            "score":    prev_report.get("score", {}),
        }
        current_full = {"scraping": scraping_data, "score": score_data}
        deltas = reporter.compute_deltas(current_full, prev_full)
        log(f"  Historical delta vs {prev_report['session']['start_time'][:10]}: {deltas}", "info", logger)

    phase_banner("GENERATING REPORTS")
    json_path = reporter.build_json_report(
        session_data, preflight_data, recon_data, scraping_data, ddos_data,
        report_dir, score=score_data, recommendations=recs, deltas=deltas,
        goodbot_data=goodbot_data,
        openapi_data=openapi_data,
        endpoint_data=endpoint_data,
    )
    html_path = reporter.build_html_report(
        session_data, preflight_data, recon_data, scraping_data, ddos_data,
        report_dir, score=score_data, recommendations=recs, deltas=deltas,
        previous_session=prev_report.get("session") if prev_report else None,
        goodbot_data=goodbot_data,
        openapi_data=openapi_data,
        endpoint_data=endpoint_data,
    )
    log_path = report_dir / f"botstrike_{session_id}.log"

    reporter.print_final_summary(
        session_data, preflight_data, scraping_data, ddos_data,
        json_path, html_path,
        score=score_data, log_path=log_path if log_path.exists() else None,
        deltas=deltas,
    )

    return {
        "session":         session_data,
        "preflight":       preflight_data,
        "good_bot_test":   goodbot_data,
        "recon":           recon_data,
        "scraping":        scraping_data,
        "ddos":            ddos_data,
        "score":           score_data,
        "recommendations": recs,
        "report_dir":      report_dir,
        "json_path":       json_path,
        "html_path":       html_path,
        "openapi":         openapi_data,
        "endpoint_map":    endpoint_data,
    }


# ─── Main ────────────────────────────────────────────────────────────────────

def main() -> None:
    global _session_data, _preflight_data, _goodbot_data, _openapi_data, _endpoint_data
    global _recon_data, _scraping_data, _ddos_data, _report_dir, _logger

    print_banner()
    args = parse_args()

    # ── URL validation ──
    needs_url = (
        not getattr(args, "setup_nodes", False)
        and not getattr(args, "compare", False)
    )
    if needs_url and not args.url:
        console.print("[red][!] --url is required (or use --compare / --setup-nodes)[/red]")
        sys.exit(1)

    # ── Proxy setup ──
    if getattr(args, "proxy", None):
        from modules.utils import set_proxy
        set_proxy(args.proxy)
        log(f"[PROXY] Routing via {args.proxy}", "info")

    # ── Basic auth setup ──
    if getattr(args, "basic_auth", None):
        from modules.utils import set_basic_auth
        raw = args.basic_auth
        if ":" not in raw:
            console.print("[red][!] --basic-auth must be in USER:PASS format[/red]")
            sys.exit(1)
        user, password = raw.split(":", 1)
        set_basic_auth(user, password)
        log(f"[AUTH] Basic auth set for user '{user}'", "info")

    # ── Profile info ──
    profile = getattr(args, "profile", "medium") or "medium"
    if profile != "medium":
        console.print(f"  [cyan]Profile:[/cyan] [bold]{profile}[/bold]\n")

    # ── DDoS gate ──
    if args.mode in ("ddos", "full") and not args.confirm_authorized:
        console.print("[bold red][!] DDoS module requires --confirm-authorized flag.[/bold red]")
        console.print("    Re-run with --confirm-authorized to unlock.")
        if args.mode == "ddos":
            sys.exit(1)
        console.print("[yellow]    Falling back to scrape-only mode.[/yellow]\n")
        args.mode = "scrape"

    file_cfg = load_config(args.config)
    cfg = merge_cfg(file_cfg, args)

    # ── Setup-nodes (no target needed) ──
    if getattr(args, "setup_nodes", False):
        from modules.distributor import cmd_setup_nodes
        cmd_setup_nodes(getattr(args, "nodes", "nodes.yaml") or "nodes.yaml")
        return

    # ── Distributed mode ──
    if getattr(args, "distributed", False):
        from modules.distributor import run_distributed
        run_distributed(args.url, args, cfg)
        return

    # ── Compare mode ──
    if getattr(args, "compare", False):
        url_a   = args.url_a
        url_b   = args.url_b
        label_a = getattr(args, "label_a", None) or "Target A"
        label_b = getattr(args, "label_b", None) or "Target B"

        if not url_a or not url_b:
            console.print("[red]--compare requires --url-a and --url-b[/red]")
            sys.exit(1)

        console.print(f"\n[bold cyan]  COMPARE MODE[/bold cyan]")
        console.print(f"  A: [cyan]{url_a}[/cyan]  ({label_a})")
        console.print(f"  B: [cyan]{url_b}[/cyan]  ({label_b})\n")

        if not args.yes:
            from rich.prompt import Confirm
            if not Confirm.ask("[?] Run full test on both targets?", default=True):
                sys.exit(0)

        console.rule(f"[bold cyan]Testing {label_a}[/bold cyan]")
        result_a = run_one_target(url_a, args, cfg, label=label_a)

        console.rule(f"[bold green]Testing {label_b}[/bold green]")
        result_b = run_one_target(url_b, args, cfg, label=label_b)

        # Build comparison report in a dedicated folder
        from datetime import datetime as _dt
        cmp_folder_name = f"compare_{_dt.now().strftime('%Y%m%d_%H%M%S')}"
        cmp_dir = Path(__file__).parent / "reports" / cmp_folder_name
        cmp_dir.mkdir(parents=True, exist_ok=True)

        cmp_path = reporter.build_comparison_html(result_a, result_b, cmp_dir)

        console.print()
        console.rule("[bold cyan]COMPARISON COMPLETE[/bold cyan]")
        console.print(f"\n  [bold green]Comparison Report:[/bold green] {cmp_path}")
        console.print(f"  [dim]Individual reports:[/dim]")
        console.print(f"    A → {result_a.get('html_path', '?')}")
        console.print(f"    B → {result_b.get('html_path', '?')}")
        console.print()
        return

    # ── Single-target mode ──
    if not args.yes:
        # Pre-flight first, then prompt
        from modules.utils import phase_banner as pb
        pb("MODULE 0: PRE-FLIGHT FINGERPRINTING")
        _preflight_data = preflight.run(args.url, timeout=cfg["preflight"]["timeout"])
        if not _preflight_data.get("target_alive"):
            log("[!] Target appears to be down. Aborting.", "error")
            sys.exit(1)
        from rich.prompt import Confirm
        if not Confirm.ask("[?] Pre-flight complete. Proceed with tests?", default=True):
            console.print("[yellow]  Aborted by user.[/yellow]")
            sys.exit(0)

    run_one_target(args.url, args, cfg)
    log("Session complete.", "success")


if __name__ == "__main__":
    main()
