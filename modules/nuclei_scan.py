"""
modules/nuclei_scan.py — Nuclei template-based vulnerability/exposure scanner.
Auto-installs nuclei from GitHub releases if not found.
Runs exposure, misconfig, tech, panel, and WAF-specific templates.
"""
import json
import logging
import os
import platform
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path
from typing import Optional

from .utils import console, log, phase_banner


def _install_nuclei(logger: Optional[logging.Logger] = None) -> Optional[str]:
    """Download latest nuclei binary from GitHub releases (Linux only)."""
    if platform.system() != "Linux":
        return None

    machine = platform.machine().lower()
    arch = {"x86_64": "amd64", "aarch64": "arm64", "armv7l": "386"}.get(machine, machine)

    console.print("  [cyan][nuclei] auto-installing...[/cyan]", end="")
    try:
        req = urllib.request.Request(
            "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest",
            headers={"User-Agent": "botstrike-installer/1.0"},
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            release = json.loads(resp.read())

        all_assets = release.get("assets", [])
        asset_url = asset_name = None

        for ext in (".zip", ".tar.gz"):
            for asset in all_assets:
                name = asset["name"]
                if (f"linux_{arch}" in name and name.endswith(ext)
                        and "checksums" not in name and "sbom" not in name):
                    asset_url = asset["browser_download_url"]
                    asset_name = name
                    break
            if asset_url:
                break

        if not asset_url:
            console.print(" [yellow]no binary found[/yellow]")
            return None

        install_dir = Path(os.path.expanduser("~/.local/bin"))
        install_dir.mkdir(parents=True, exist_ok=True)

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir) / asset_name
            urllib.request.urlretrieve(asset_url, str(tmp_path))

            if asset_name.endswith(".zip"):
                with zipfile.ZipFile(tmp_path) as zf:
                    zf.extractall(tmpdir)
            else:
                with tarfile.open(tmp_path, "r:gz") as tf:
                    tf.extractall(tmpdir)

            binary = Path(tmpdir) / "nuclei"
            if not binary.exists():
                for candidate in Path(tmpdir).rglob("nuclei"):
                    binary = candidate
                    break

            if not binary.exists():
                console.print(" [yellow]binary not in archive[/yellow]")
                return None

            dest = install_dir / "nuclei"
            import shutil as _sh
            _sh.copy2(str(binary), str(dest))
            dest.chmod(0o755)

        path_str = str(install_dir)
        if path_str not in os.environ.get("PATH", ""):
            os.environ["PATH"] = os.environ.get("PATH", "") + f":{path_str}"

        result = shutil.which("nuclei") or (str(dest) if dest.exists() else None)
        if result:
            console.print(" [bold green]done[/bold green]")
        return result

    except Exception as e:
        log(f"  [nuclei] install failed: {e}", "warning", logger)
        console.print(" [yellow]failed[/yellow]")
        return None


def run(target_url: str, logger: Optional[logging.Logger] = None) -> dict:
    """
    Run nuclei template scan against target.
    Templates: exposure, misconfig, tech, panel, waf
    Returns structured findings list + summary stats.
    """
    phase_banner("MODULE: NUCLEI TEMPLATE SCAN")

    result: dict = {
        "findings":     [],
        "total":        0,
        "severities":   {},
        "tech_detected": [],
        "error":        None,
    }

    nuclei_path = shutil.which("nuclei")
    if not nuclei_path:
        log("[nuclei] not found — attempting auto-install...", "warning", logger)
        nuclei_path = _install_nuclei(logger)
        if not nuclei_path:
            log("[nuclei] skipping — could not install", "warning", logger)
            result["error"] = "nuclei not available"
            console.print("  [dim][nuclei] skipped — not installed[/dim]")
            return result

    log(f"[nuclei] Running template scan: exposure, misconfig, tech, panel, waf", "info", logger)
    console.print(f"  [cyan]Running nuclei templates against[/cyan] {target_url}")
    console.print("  [dim](tags: exposure, misconfig, tech, panel, waf — this may take 2-5 min)[/dim]\n")

    cmd = [
        nuclei_path,
        "-u", target_url,
        "-tags", "exposure,misconfig,tech,panel,waf",
        "-silent", "-jsonl",
        "-timeout", "10",
        "-rate-limit", "50",
        "-bulk-size", "25",
        "-no-color",
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=360)

        findings: list[dict] = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                info = item.get("info", {})
                severity = info.get("severity", "unknown").lower()
                findings.append({
                    "template_id": item.get("template-id", ""),
                    "name":        info.get("name", ""),
                    "severity":    severity,
                    "matched_at":  item.get("matched-at", ""),
                    "tags":        info.get("tags", []),
                })
            except json.JSONDecodeError:
                continue

        result["findings"] = findings
        result["total"]    = len(findings)

        sev_count: dict[str, int] = {}
        tech_found: list[str] = []
        for f in findings:
            sev = f["severity"]
            sev_count[sev] = sev_count.get(sev, 0) + 1
            if "tech" in f.get("tags", []):
                tech_found.append(f["name"])

        result["severities"]   = sev_count
        result["tech_detected"] = sorted(set(tech_found))

        if findings:
            from rich.table import Table
            t = Table(title=f"Nuclei Findings ({len(findings)} total)",
                      show_header=True, header_style="bold cyan")
            t.add_column("Severity", style="bold", width=10)
            t.add_column("Template ID", width=36)
            t.add_column("Name", width=42)

            _SEV_ORDER = ["critical", "high", "medium", "low", "info", "unknown"]
            _SEV_COLOR = {
                "critical": "bold red", "high": "red", "medium": "yellow",
                "low": "green", "info": "cyan", "unknown": "dim",
            }

            for f in sorted(findings, key=lambda x: (
                _SEV_ORDER.index(x["severity"]) if x["severity"] in _SEV_ORDER else 99
            )):
                color = _SEV_COLOR.get(f["severity"], "white")
                t.add_row(
                    f"[{color}]{f['severity'].upper()}[/{color}]",
                    f["template_id"][:36],
                    f["name"][:42],
                )
            console.print(t)
        else:
            log("[nuclei] No findings from template scan", "info", logger)
            console.print("  [dim][nuclei] No findings[/dim]")

    except subprocess.TimeoutExpired:
        result["error"] = "timed out (360s)"
        log("[nuclei] scan timed out", "warning", logger)
    except Exception as e:
        result["error"] = str(e)
        log(f"[nuclei] error: {e}", "error", logger)

    return result
