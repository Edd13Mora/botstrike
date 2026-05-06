"""
Per-endpoint protection mapping.

Tests each discovered flow endpoint individually:
  - Stealth UA vs bot UA response comparison
  - Rate limit threshold detection (what RPS triggers blocking)
  - Shadow ban detection (200 OK but degraded/empty response body)
  - CORS misconfiguration check
  - Login timing attack (response time difference → account enumeration)
"""

import statistics
import time
import threading
import logging
from typing import Optional

import requests

from .utils import console, log, phase_banner, stealth_headers, random_ua, get_proxy_dict

BLOCK_CODES = {403, 406, 429, 503}

BOT_UAS = [
    "python-requests/2.31.0",
    "curl/7.88.1",
    "Go-http-client/1.1",
    "Scrapy/2.11.0 (+https://scrapy.org)",
    "Java/1.8.0_292",
]

_RATE_LEVELS = [5, 10, 25, 50, 100, 200]


def _req(url: str, method: str = "GET", ua: str = None, data: dict = None,
         headers_extra: dict = None, timeout: int = 8, proxies: dict = None) -> dict:
    hdrs = stealth_headers()
    if ua:
        hdrs["User-Agent"] = ua
    if headers_extra:
        hdrs.update(headers_extra)
    t0 = time.time()
    try:
        fn = requests.post if method == "POST" else requests.get
        r = fn(url, data=data, headers=hdrs, timeout=timeout,
               allow_redirects=True, verify=False, proxies=proxies)
        return {
            "code": r.status_code, "latency_ms": round((time.time() - t0) * 1000, 1),
            "body_len": len(r.content), "body_snippet": r.text[:300],
            "headers": dict(r.headers),
        }
    except Exception as e:
        return {"code": 0, "latency_ms": round((time.time() - t0) * 1000, 1),
                "body_len": 0, "body_snippet": "", "headers": {}, "error": str(e)}


def _find_rate_limit(url: str, proxies: dict) -> Optional[int]:
    """Step through RPS levels until blocking starts. Returns threshold RPS or None."""
    for rps in _RATE_LEVELS:
        interval = 1.0 / rps
        codes = []
        t_end = time.time() + 2.0
        while time.time() < t_end:
            r = _req(url, timeout=4, proxies=proxies)
            codes.append(r["code"])
            time.sleep(max(interval, 0.01))
        if codes and sum(1 for c in codes if c in BLOCK_CODES) / len(codes) > 0.25:
            return rps
    return None


def _check_shadow_ban(url: str, baseline_len: int, baseline_code: int,
                      proxies: dict) -> dict:
    """Compare bot UA response body against stealth baseline."""
    if baseline_code != 200 or baseline_len == 0:
        return {"detected": False}
    r = _req(url, ua=BOT_UAS[0], timeout=8, proxies=proxies)
    if r["code"] != 200:
        return {"detected": False}
    diff_pct = abs(r["body_len"] - baseline_len) / max(baseline_len, 1) * 100
    if diff_pct > 40:
        return {
            "detected": True,
            "evidence": (
                f"Body changed {baseline_len}→{r['body_len']} bytes "
                f"({diff_pct:.0f}% difference) with bot UA while status stayed 200"
            ),
        }
    return {"detected": False}


def _check_cors(url: str, proxies: dict) -> dict:
    """Check if CORS allows arbitrary origins."""
    origins = ["https://evil.com", "null", "https://attacker.example.org"]
    findings = []
    for origin in origins:
        r = _req(url, headers_extra={"Origin": origin}, timeout=6, proxies=proxies)
        acao = r["headers"].get("Access-Control-Allow-Origin", "")
        acac = r["headers"].get("Access-Control-Allow-Credentials", "")
        if acao in ("*", origin):
            findings.append({
                "origin_sent": origin,
                "acao_returned": acao,
                "credentials_allowed": acac.lower() == "true",
            })
    wildcard    = any(f["acao_returned"] == "*" for f in findings)
    with_creds  = any(f["credentials_allowed"] for f in findings)
    return {
        "vulnerable": bool(findings),
        "wildcard": wildcard,
        "credentials_with_arbitrary_origin": with_creds,
        "findings": findings,
    }


def _timing_attack(login_urls: list[str], proxies: dict,
                   logger: Optional[logging.Logger] = None) -> dict:
    """Measure login response time for random vs common emails (account enumeration)."""
    if not login_urls:
        return {"tested": False, "vulnerable": False, "note": "No login URLs found"}

    url = login_urls[0]
    ts = int(time.time())
    random_emails = [f"nx_user_{ts}_{i}@fakexyz123.invalid" for i in range(6)]
    common_emails = [
        "admin@gmail.com", "info@gmail.com", "contact@yahoo.com",
        "user@hotmail.com", "test@outlook.com", "hello@gmail.com",
    ]

    def measure(email: str) -> float:
        t0 = time.time()
        try:
            requests.post(url, data={"email": email, "password": "WrongPass_123!"},
                          headers=stealth_headers(), timeout=10,
                          allow_redirects=False, verify=False, proxies=proxies)
        except Exception:
            pass
        return (time.time() - t0) * 1000

    random_times = [measure(e) for e in random_emails]
    common_times = [measure(e) for e in common_emails]
    avg_r = statistics.mean(random_times)
    avg_c = statistics.mean(common_times)
    diff  = abs(avg_c - avg_r)
    vuln  = diff > 50

    return {
        "tested": True,
        "url": url,
        "vulnerable": vuln,
        "avg_random_ms": round(avg_r, 1),
        "avg_common_ms": round(avg_c, 1),
        "diff_ms": round(diff, 1),
        "note": (
            f"{'[!] TIMING DIFF DETECTED' if vuln else 'No significant timing difference'}. "
            f"Random emails avg {avg_r:.0f}ms, common emails avg {avg_c:.0f}ms "
            f"(diff {diff:.0f}ms)"
        ),
    }


def _probe_one(flow: str, url: str, timeout: int, proxies: dict,
               check_rate_limit: bool) -> dict:
    """Full per-endpoint analysis."""
    result = {
        "flow": flow, "url": url,
        "stealth_code": None, "stealth_latency_ms": None,
        "bot_blocked": False, "bot_ua_results": [],
        "rate_limit_threshold_rps": None,
        "shadow_ban": {"detected": False},
        "cors": {"vulnerable": False},
    }

    # Baseline stealth
    baseline = _req(url, timeout=timeout, proxies=proxies)
    result["stealth_code"]       = baseline["code"]
    result["stealth_latency_ms"] = baseline["latency_ms"]

    # Bot UA tests
    for ua in BOT_UAS[:3]:
        r = _req(url, ua=ua, timeout=timeout, proxies=proxies)
        r["ua"] = ua
        r["blocked"] = r["code"] in BLOCK_CODES
        result["bot_ua_results"].append(r)
        time.sleep(0.15)
    result["bot_blocked"] = any(r["blocked"] for r in result["bot_ua_results"])

    # Shadow ban
    result["shadow_ban"] = _check_shadow_ban(
        url, baseline["body_len"], baseline["code"], proxies)

    # CORS (for API endpoints)
    if "/api" in url.lower() or flow == "api":
        result["cors"] = _check_cors(url, proxies)

    # Rate limit threshold (only when authorized — this sends many requests)
    if check_rate_limit:
        result["rate_limit_threshold_rps"] = _find_rate_limit(url, proxies)

    return result


def run(target_url: str, classified_flows: dict, cfg: dict,
        authorized: bool = False,
        logger: Optional[logging.Logger] = None) -> dict:
    phase_banner("MODULE 1b: PER-ENDPOINT PROTECTION MAP")

    if not classified_flows:
        console.print("  [dim]No flow endpoints found — skipping.[/dim]")
        return {"endpoint_results": [], "timing_attack": {}, "shadow_bans": [], "cors_issues": []}

    timeout  = cfg.get("preflight", {}).get("timeout", 8)
    proxies  = get_proxy_dict()
    shadow_bans  = []
    cors_issues  = []
    ep_results   = []

    # Collect up to 3 URLs per flow
    targets: list[tuple[str, str]] = []
    for flow, urls in classified_flows.items():
        for url in urls[:3]:
            targets.append((flow, url))

    console.print(f"  Probing [bold]{len(targets)}[/bold] flow endpoints "
                  f"({'with rate-limit scan' if authorized else 'no rate-limit scan — needs --confirm-authorized'})...\n")

    for flow, url in targets:
        console.print(f"  [cyan]→[/cyan] [{flow}] {url}")
        ep = _probe_one(flow, url, timeout, proxies, check_rate_limit=authorized)
        ep_results.append(ep)

        sc_str  = f"[green]{ep['stealth_code']}[/green]" if ep["stealth_code"] == 200 else f"[yellow]{ep['stealth_code']}[/yellow]"
        bot_str = "[green]BLOCKED[/green]" if ep["bot_blocked"] else "[red]ALLOWED[/red]"
        rl      = ep["rate_limit_threshold_rps"]
        rl_str  = f"[yellow]~{rl} RPS[/yellow]" if rl else ("[dim]not tested[/dim]" if not authorized else "[green]>200 RPS[/green]")
        sb_str  = "[bold red]YES[/bold red]" if ep["shadow_ban"]["detected"] else "[dim]no[/dim]"
        cors_v  = ep["cors"].get("vulnerable", False)
        cors_str = "[bold red]EXPOSED[/bold red]" if cors_v else "[dim]ok[/dim]"

        console.print(f"    Stealth:{sc_str}  BotUA:{bot_str}  RateLimit:{rl_str}  ShadowBan:{sb_str}  CORS:{cors_str}")

        if ep["shadow_ban"]["detected"]:
            console.print(f"    [red]Shadow ban:[/red] {ep['shadow_ban']['evidence']}")
            shadow_bans.append(ep)
        if cors_v:
            details = ep["cors"]
            console.print(f"    [red]CORS:[/red] wildcard={details.get('wildcard')} creds={details.get('credentials_with_arbitrary_origin')}")
            cors_issues.append(ep)

    # Timing attack on login
    login_urls = classified_flows.get("login", [])
    console.print(f"\n  [cyan]→[/cyan] Login timing attack (account enumeration check)...")
    timing = _timing_attack(login_urls, proxies, logger)
    if timing["tested"]:
        vuln_str = "[bold red]VULNERABLE[/bold red]" if timing["vulnerable"] else "[green]OK[/green]"
        console.print(f"    {vuln_str} — {timing['note']}")

    return {
        "endpoint_results": ep_results,
        "shadow_bans":      shadow_bans,
        "cors_issues":      cors_issues,
        "timing_attack":    timing,
    }
