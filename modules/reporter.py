import json
import logging
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from jinja2 import Environment, FileSystemLoader, select_autoescape
from rich.table import Table

from .utils import console, log, now_utc, TOOL_VERSION

BLOCK_CODES = {403, 406, 429, 503}

# ─── Protection Score ─────────────────────────────────────────────────────────

def calculate_protection_score(preflight: dict, scraping: dict, ddos: dict,
                               goodbot_data: Optional[dict] = None,
                               openapi_data: Optional[dict] = None,
                               endpoint_data: Optional[dict] = None) -> dict:
    """
    Score the target's bot protection from 0-100 and convert to an A-F grade.
    Each finding deducts points; higher score = better protection.
    """
    score = 100
    findings: list[dict] = []

    waf     = preflight.get("waf_detected", "None detected")
    mode    = preflight.get("blocking_mode", "")
    stealth_pct  = scraping.get("stealth",     {}).get("blocked_pct", 0.0)
    agg_pct      = scraping.get("aggressive",  {}).get("blocked_pct", 0.0)

    # ── WAF presence ──
    if waf == "None detected":
        score -= 35
        findings.append({"sev": "CRITICAL", "msg": "No WAF or bot-protection solution detected"})
    else:
        findings.append({"sev": "PASS", "msg": f"Bot protection detected: {waf}"})

    # ── Blocking mode ──
    if "PASSIVE" in mode:
        score -= 20
        findings.append({"sev": "HIGH", "msg": f"{waf} is in detection-only (passive) mode — not blocking"})
    elif "ACTIVE" in mode:
        findings.append({"sev": "PASS", "msg": "WAF is in active blocking mode"})

    # ── Stealth scraping (human-like bots) ──
    if stealth_pct < 20:
        score -= 20
        findings.append({"sev": "HIGH",
                         "msg": f"Only {stealth_pct}% of human-simulating bots blocked in stealth mode"})
    elif stealth_pct < 50:
        score -= 10
        findings.append({"sev": "MEDIUM",
                         "msg": f"Stealth scraping {stealth_pct}% blocked — room for improvement"})
    else:
        findings.append({"sev": "PASS", "msg": f"Stealth mode {stealth_pct}% blocked"})

    # ── Aggressive/obvious bots ──
    if agg_pct < 50:
        score -= 15
        findings.append({"sev": "HIGH",
                         "msg": f"Only {agg_pct}% of obvious bots (python-requests UA) blocked"})
    elif agg_pct < 80:
        score -= 5
        findings.append({"sev": "LOW",
                         "msg": f"Aggressive mode {agg_pct}% blocked — minor tuning recommended"})
    else:
        findings.append({"sev": "PASS", "msg": f"Aggressive mode {agg_pct}% blocked"})

    # ── DDoS vectors ──
    for vec_name, vec_data in ddos.items():
        if isinstance(vec_data, dict):
            pct = vec_data.get("blocked_pct", 0.0)
            if pct < 30:
                score -= 5
                findings.append({"sev": "MEDIUM",
                                 "msg": f"DDoS vector '{vec_name}' only {pct}% blocked"})

    # ── CDN ──
    if preflight.get("cdn_detected", "None detected") == "None detected":
        score -= 5
        findings.append({"sev": "LOW", "msg": "No CDN detected — origin server directly exposed"})
    else:
        findings.append({"sev": "PASS",
                         "msg": f"CDN layer present: {preflight.get('cdn_detected')}"})

    # ── HSTS ──
    if not preflight.get("hsts"):
        score -= 5
        findings.append({"sev": "LOW", "msg": "HSTS header missing"})

    # ── Good bot over-blocking ──
    if goodbot_data:
        over = goodbot_data.get("over_blocked_count", 0)
        blocked = goodbot_data.get("blocked_bots", [])
        if over > 0:
            score -= 15
            findings.append({"sev": "HIGH",
                             "msg": f"WAF is blocking {over} legitimate crawler(s): {', '.join(blocked)}"})
        else:
            findings.append({"sev": "PASS", "msg": "All legitimate crawlers (Googlebot, Meta, etc.) are allowed"})

    # ── OpenAPI / GraphQL exposure ──
    if openapi_data:
        if openapi_data.get("graphql_introspection_open"):
            score -= 10
            findings.append({"sev": "HIGH", "msg": "GraphQL introspection is open — full schema leaked"})
        if openapi_data.get("swagger_found"):
            findings.append({"sev": "INFO", "msg": f"OpenAPI spec publicly accessible at {openapi_data.get('swagger_url')}"})

    # ── Per-endpoint findings ──
    if endpoint_data:
        shadow_bans = endpoint_data.get("shadow_bans", [])
        cors_issues = endpoint_data.get("cors_issues", [])
        timing      = endpoint_data.get("timing_attack", {})

        if shadow_bans:
            findings.append({"sev": "PASS", "msg": f"Shadow-ban active on {len(shadow_bans)} endpoint(s) — WAF silently degrading bot responses"})

        for ep in cors_issues:
            score -= 10
            cors = ep.get("cors", {})
            findings.append({
                "sev": "HIGH",
                "msg": f"CORS misconfiguration on {ep['url']} — wildcard={cors.get('wildcard')} credentials={cors.get('credentials_with_arbitrary_origin')}",
            })

        if timing.get("vulnerable"):
            score -= 10
            findings.append({"sev": "HIGH", "msg": f"Account enumeration via timing on login — {timing.get('diff_ms', 0):.0f}ms difference"})
        elif timing.get("tested"):
            findings.append({"sev": "PASS", "msg": "Login endpoint shows no timing difference (no account enumeration)"})

        # Endpoints where bot UAs are not blocked
        unprotected = [ep for ep in endpoint_data.get("endpoint_results", []) if not ep.get("bot_blocked")]
        if unprotected:
            score -= min(10, len(unprotected) * 3)
            names = ", ".join(ep["flow"] for ep in unprotected[:3])
            findings.append({"sev": "HIGH", "msg": f"Bot UAs not blocked on {len(unprotected)} endpoint(s): {names}"})

    score = max(0, score)
    if score >= 90:   grade = "A"
    elif score >= 80: grade = "B"
    elif score >= 65: grade = "C"
    elif score >= 50: grade = "D"
    else:             grade = "F"

    return {"score": score, "grade": grade, "findings": findings}


# ─── Recommendations ──────────────────────────────────────────────────────────

def generate_recommendations(preflight: dict, scraping: dict, ddos: dict,
                              score_data: dict,
                              goodbot_data: Optional[dict] = None,
                              openapi_data: Optional[dict] = None,
                              endpoint_data: Optional[dict] = None) -> list[dict]:
    """
    Generate prioritised, actionable recommendations based on test findings.
    Tailored to DataDome and CrowdSec deployment context.
    """
    recs: list[dict] = []
    waf         = preflight.get("waf_detected", "None detected")
    mode        = preflight.get("blocking_mode", "")
    stealth_pct = scraping.get("stealth",    {}).get("blocked_pct", 0.0)
    agg_pct     = scraping.get("aggressive", {}).get("blocked_pct", 0.0)
    cdn         = preflight.get("cdn_detected", "None detected")

    if waf == "None detected":
        recs.append({
            "priority": "CRITICAL",
            "title":    "Deploy a Bot Management Solution",
            "detail":   (
                "No WAF or bot protection was detected. For e-commerce targets we recommend "
                "DataDome (JS tag + server-side module) for behavioral fingerprinting, or "
                "CrowdSec (community blocklists + bouncer) for open-source coverage. "
                "Without protection, scraping, credential stuffing, and DDoS go unchallenged."
            ),
        })

    if "PASSIVE" in mode and waf != "None detected":
        recs.append({
            "priority": "CRITICAL",
            "title":    f"Switch {waf} from Detection-Only to Blocking Mode",
            "detail":   (
                f"{waf} is currently logging threats but NOT blocking them. "
                "Every bot request counted in this report reached your origin server. "
                "Enable blocking/enforcement mode immediately — this is a one-flag change in most deployments."
            ),
        })

    if stealth_pct < 30:
        recs.append({
            "priority": "HIGH",
            "title":    "Improve Human-Like Bot Detection",
            "detail":   (
                f"Only {stealth_pct}% of stealth bots (rotating UAs, realistic headers, "
                "random delays) were blocked. "
                "DataDome recommendation: enable device fingerprinting and JavaScript challenge mode. "
                "CrowdSec recommendation: add behavioral scenario detection (appsec-collection)."
            ),
        })

    if agg_pct < 80:
        recs.append({
            "priority": "HIGH",
            "title":    "Tighten Obvious Bot Detection Rules",
            "detail":   (
                f"Only {agg_pct}% of obvious bots (python-requests/2.31.0 User-Agent, no cookies, "
                "no delays) were blocked. This is the most basic bot signature. "
                "Add a strict UA blocklist. DataDome blocks this by default; if using CrowdSec "
                "ensure the http-bad-user-agents scenario is active."
            ),
        })

    # DDoS vector recommendations
    for vec_name, vec_data in ddos.items():
        if not isinstance(vec_data, dict):
            continue
        pct = vec_data.get("blocked_pct", 0.0)
        rps = vec_data.get("rps_avg", 0.0)
        if pct < 50:
            label = vec_name.replace("_", " ").title()
            recs.append({
                "priority": "MEDIUM",
                "title":    f"Strengthen Rate Limiting — {label}",
                "detail":   (
                    f"Only {pct}% of {label} traffic was mitigated at {rps} avg RPS. "
                    "Review rate-limit thresholds on your WAF and CDN. "
                    "For DataDome, check the rate-limiting policy in the dashboard. "
                    "For CrowdSec, validate the http-crawl-non_statics and http-flood scenarios."
                ),
            })

    if cdn == "None detected":
        recs.append({
            "priority": "MEDIUM",
            "title":    "Add a CDN Layer for DDoS Absorption",
            "detail":   (
                "No CDN was detected in front of your origin. A CDN (Cloudflare, Akamai, Fastly) "
                "absorbs volumetric DDoS traffic before it reaches your infrastructure. "
                "Both DataDome and CrowdSec integrate with major CDNs via edge modules."
            ),
        })

    if not preflight.get("hsts"):
        recs.append({
            "priority": "LOW",
            "title":    "Enable HTTP Strict Transport Security (HSTS)",
            "detail":   (
                "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains' to all "
                "HTTPS responses. This prevents downgrade attacks and is required for many "
                "compliance frameworks (PCI-DSS, GDPR)."
            ),
        })

    if not preflight.get("robots_txt"):
        recs.append({
            "priority": "LOW",
            "title":    "Add a robots.txt File",
            "detail":   (
                "No robots.txt was found. While not a security control, it signals to crawlers "
                "which paths to avoid and can help differentiate legitimate bots from malicious ones "
                "in WAF logs."
            ),
        })

    # ── Good bot over-blocking ──
    if goodbot_data and goodbot_data.get("over_blocked_count", 0) > 0:
        blocked = goodbot_data.get("blocked_bots", [])
        recs.append({
            "priority": "HIGH",
            "title":    "Fix Over-Blocking — Legitimate Crawlers Are Being Blocked",
            "detail":   (
                f"The WAF is blocking {len(blocked)} legitimate crawler(s): {', '.join(blocked)}. "
                "Blocking Googlebot, Bingbot, or Meta harms SEO, social link previews, and "
                "search indexing. "
                "DataDome: check the 'allowed bots' list in the dashboard and ensure major search "
                "engine crawlers are whitelisted by UA + IP range verification. "
                "CrowdSec: add explicit allow rules for verified crawler IP ranges "
                "(Google, Bing, Meta publish their IP ranges publicly)."
            ),
        })

    # ── OpenAPI / GraphQL ──
    if openapi_data:
        if openapi_data.get("graphql_introspection_open"):
            recs.append({
                "priority": "HIGH",
                "title":    "Disable GraphQL Introspection in Production",
                "detail":   (
                    "GraphQL introspection is enabled, exposing your full API schema including "
                    "all queries, mutations, types, and field names. This gives attackers a complete "
                    "roadmap of your API surface. Disable introspection in your GraphQL server config "
                    "for all non-development environments."
                ),
            })
        if openapi_data.get("swagger_found"):
            recs.append({
                "priority": "MEDIUM",
                "title":    "Restrict Access to API Documentation Endpoint",
                "detail":   (
                    f"The OpenAPI/Swagger spec is publicly accessible at {openapi_data.get('swagger_url')}. "
                    "This reveals every endpoint, parameter, and data model. "
                    "Restrict access to authenticated users or internal network only, "
                    "or remove it from production entirely."
                ),
            })

    # ── Per-endpoint ──
    if endpoint_data:
        if endpoint_data.get("timing_attack", {}).get("vulnerable"):
            timing = endpoint_data["timing_attack"]
            recs.append({
                "priority": "HIGH",
                "title":    "Fix Account Enumeration Timing Vulnerability on Login",
                "detail":   (
                    f"The login endpoint at {timing.get('url', '?')} responds "
                    f"{timing.get('diff_ms', 0):.0f}ms faster for random emails than for common ones. "
                    "This allows attackers to enumerate valid accounts. "
                    "Ensure the login handler takes constant time regardless of whether the email exists "
                    "(use a constant-time comparison or always run the password hash even for unknown emails)."
                ),
            })

        for ep in endpoint_data.get("cors_issues", []):
            cors = ep.get("cors", {})
            recs.append({
                "priority": "HIGH",
                "title":    f"Fix CORS Misconfiguration on {ep.get('flow', '').title()} Endpoint",
                "detail":   (
                    f"Endpoint {ep['url']} returns Access-Control-Allow-Origin for arbitrary origins. "
                    + ("Credentials are also allowed, making this exploitable for cross-origin data theft. " if cors.get("credentials_with_arbitrary_origin") else "")
                    + "Restrict CORS to known trusted origins only."
                ),
            })

        unprotected = [ep for ep in endpoint_data.get("endpoint_results", []) if not ep.get("bot_blocked")]
        if unprotected:
            urls = ", ".join(ep["url"] for ep in unprotected[:3])
            recs.append({
                "priority": "HIGH",
                "title":    "Bot UAs Not Blocked on Sensitive Flow Endpoints",
                "detail":   (
                    f"{len(unprotected)} sensitive endpoint(s) allow obvious bot User-Agents (python-requests, curl, Scrapy): {urls}. "
                    "These should be blocked immediately. "
                    "DataDome: verify the JS tag is loading on these pages and enforcement mode is active. "
                    "CrowdSec: confirm the http-bad-user-agents scenario is enabled."
                ),
            })

        shadow_bans = endpoint_data.get("shadow_bans", [])
        if shadow_bans:
            recs.append({
                "priority": "LOW",
                "title":    "Shadow Ban Detected — Consider Transparency",
                "detail":   (
                    f"The WAF appears to be shadow-banning bots on {len(shadow_bans)} endpoint(s): "
                    "returning HTTP 200 but with degraded/empty response bodies. "
                    "This is a valid technique to confuse scrapers, but verify it does not "
                    "accidentally affect legitimate users with unusual network configurations."
                ),
            })

    priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    return sorted(recs, key=lambda r: priority_order.get(r["priority"], 9))


# ─── Historical delta ─────────────────────────────────────────────────────────

def load_previous_report(target_url: str, current_session_id: str) -> Optional[dict]:
    """Find and load the most recent previous JSON report for the same hostname."""
    hostname = urlparse(target_url).hostname or ""
    slug = hostname.replace(".", "_")
    reports_dir = Path(__file__).parent.parent / "reports"
    if not reports_dir.exists():
        return None

    candidates: list[Path] = []
    for folder in reports_dir.iterdir():
        if folder.is_dir() and slug in folder.name:
            for jf in folder.glob("botstrike_*.json"):
                candidates.append(jf)

    candidates.sort(key=lambda f: f.stat().st_mtime, reverse=True)
    for candidate in candidates:
        try:
            data = json.loads(candidate.read_text(encoding="utf-8"))
            if data.get("session", {}).get("id") != current_session_id:
                return data
        except Exception:
            continue
    return None


def compute_deltas(current: dict, previous: dict) -> dict:
    """Return a flat dict of metric deltas (positive = improvement)."""
    deltas: dict = {}
    cs = current.get("scraping", {})
    ps = previous.get("scraping", {})
    for phase in ("stealth", "aggressive"):
        c = cs.get(phase, {}).get("blocked_pct")
        p = ps.get(phase, {}).get("blocked_pct")
        if c is not None and p is not None:
            deltas[f"{phase}_blocked_pct"] = round(c - p, 1)

    c_score = current.get("score", {}).get("score")
    p_score = previous.get("score", {}).get("score")
    if c_score is not None and p_score is not None:
        deltas["score"] = c_score - p_score

    return deltas


# ─── Evidence collection ──────────────────────────────────────────────────────

def _collect_evidence(scraping: dict, ddos: dict) -> list[dict]:
    evidence = []
    for phase_key in ("stealth", "aggressive"):
        for r in scraping.get(phase_key, {}).get("raw_results", []):
            if r.get("http_code") in BLOCK_CODES:
                evidence.append({
                    "timestamp":        r.get("timestamp", ""),
                    "phase":            f"scrape_{phase_key}",
                    "url":              r.get("url", ""),
                    "http_code":        r.get("http_code", 0),
                    "block_type":       r.get("block_type", "HARD_BLOCK"),
                    "response_headers": r.get("response_headers", {}),
                    "body_snippet":     r.get("body_snippet", "")[:300],
                })
    return evidence[:500]


def _total_requests(scraping: dict, ddos: dict) -> int:
    total = 0
    for phase in ("stealth", "aggressive"):
        total += scraping.get(phase, {}).get("total_requests", 0)
    for vec in ddos.values():
        if isinstance(vec, dict):
            total += vec.get("total_requests", 0)
    return total


def _overall_blocked_pct(scraping: dict, ddos: dict) -> float:
    totals, blocked = 0, 0
    for phase in ("stealth", "aggressive"):
        pd = scraping.get(phase, {})
        n = pd.get("total_requests", 0)
        totals += n
        blocked += int(n * pd.get("blocked_pct", 0) / 100)
    for vec in ddos.values():
        if isinstance(vec, dict):
            n = vec.get("total_requests", 0)
            totals += n
            blocked += int(n * vec.get("blocked_pct", 0) / 100)
    return round(blocked / totals * 100, 1) if totals else 0.0


# ─── Report builders ──────────────────────────────────────────────────────────

def build_json_report(session: dict, preflight: dict, recon: dict,
                      scraping: dict, ddos: dict, report_dir: Path,
                      score: Optional[dict] = None,
                      recommendations: Optional[list] = None,
                      deltas: Optional[dict] = None,
                      goodbot_data: Optional[dict] = None,
                      openapi_data: Optional[dict] = None,
                      endpoint_data: Optional[dict] = None) -> Path:
    evidence = _collect_evidence(scraping, ddos)
    scraping_out = {
        "stealth":    {k: v for k, v in scraping.get("stealth",    {}).items() if k != "raw_results"},
        "aggressive": {k: v for k, v in scraping.get("aggressive", {}).items() if k != "raw_results"},
    }
    report = {
        "session":            session,
        "score":              score or {},
        "preflight":          preflight,
        "good_bot_test":      goodbot_data or {},
        "scraping":           scraping_out,
        "ddos":               ddos,
        "recommendations":    recommendations or [],
        "detection_evidence": evidence,
        "deltas":             deltas or {},
        "openapi":            openapi_data or {},
        "endpoint_map":       endpoint_data or {},
    }
    sid      = session.get("id", "unknown")
    out_path = report_dir / f"botstrike_{sid}.json"
    out_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return out_path


def build_html_report(session: dict, preflight: dict, recon: dict,
                      scraping: dict, ddos: dict, report_dir: Path,
                      score: Optional[dict] = None,
                      recommendations: Optional[list] = None,
                      deltas: Optional[dict] = None,
                      previous_session: Optional[dict] = None,
                      goodbot_data: Optional[dict] = None,
                      openapi_data: Optional[dict] = None,
                      endpoint_data: Optional[dict] = None) -> Path:
    evidence       = _collect_evidence(scraping, ddos)
    total_reqs     = _total_requests(scraping, ddos)
    overall_blocked = _overall_blocked_pct(scraping, ddos)
    stealth        = scraping.get("stealth", {})
    aggressive     = scraping.get("aggressive", {})

    ddos_vectors = [
        {"name": name.replace("_", " ").title(), **data}
        for name, data in ddos.items()
        if isinstance(data, dict)
    ]

    template_dir = Path(__file__).parent.parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html", "j2"]),
    )
    template = env.get_template("report.html.j2")

    html = template.render(
        session=session,
        preflight=preflight,
        recon=recon,
        stealth=stealth,
        aggressive=aggressive,
        ddos_vectors=ddos_vectors,
        evidence=evidence,
        total_requests=total_reqs,
        overall_blocked_pct=overall_blocked,
        score=score or {"score": 0, "grade": "?", "findings": []},
        recommendations=recommendations or [],
        deltas=deltas or {},
        previous_session=previous_session,
        goodbot=goodbot_data or {},
        openapi=openapi_data or {},
        endpoint_map=endpoint_data or {},
        tool_version=TOOL_VERSION,
        generated_at=now_utc(),
    )

    sid      = session.get("id", "unknown")
    out_path = report_dir / f"botstrike_{sid}.html"
    out_path.write_text(html, encoding="utf-8")
    return out_path


def build_comparison_html(result_a: dict, result_b: dict, report_dir: Path) -> Path:
    """Generate a side-by-side comparison report for two targets."""
    template_dir = Path(__file__).parent.parent / "templates"
    env = Environment(
        loader=FileSystemLoader(str(template_dir)),
        autoescape=select_autoescape(["html", "j2"]),
    )
    template = env.get_template("comparison.html.j2")

    html = template.render(
        a=result_a,
        b=result_b,
        tool_version=TOOL_VERSION,
        generated_at=now_utc(),
    )
    out_path = report_dir / "botstrike_comparison.html"
    out_path.write_text(html, encoding="utf-8")
    return out_path


# ─── Final summary table ──────────────────────────────────────────────────────

def print_final_summary(
    session: dict, preflight: dict, scraping: dict, ddos: dict,
    json_path: Path, html_path: Path,
    score: Optional[dict] = None,
    log_path: Optional[Path] = None,
    deltas: Optional[dict] = None,
) -> None:
    table = Table(
        title="[bold cyan]BotStrike — Test Complete[/bold cyan]",
        show_header=True, header_style="bold white",
    )
    table.add_column("Phase",      style="bold white", width=28)
    table.add_column("Requests",   justify="right")
    table.add_column("Blocked %",  justify="right")
    table.add_column("Delta",      justify="right")
    table.add_column("Items",      justify="right")

    for phase in ("stealth", "aggressive"):
        pd    = scraping.get(phase, {})
        label = "Scraping — Stealth" if phase == "stealth" else "Scraping — Aggressive"
        pct   = pd.get("blocked_pct", 0)
        color = "red" if pct > 70 else "yellow" if pct > 30 else "green"
        delta_key = f"{phase}_blocked_pct"
        delta_str = ""
        if deltas and delta_key in deltas:
            d = deltas[delta_key]
            delta_str = f"[green]+{d}%[/green]" if d > 0 else f"[red]{d}%[/red]" if d < 0 else "±0%"
        table.add_row(
            label,
            str(pd.get("total_requests", 0)),
            f"[{color}]{pct}%[/{color}]",
            delta_str,
            str(pd.get("items_extracted", 0)),
        )

    for name, data in ddos.items():
        if isinstance(data, dict):
            pct   = data.get("blocked_pct", 0)
            color = "red" if pct > 70 else "yellow" if pct > 30 else "green"
            table.add_row(
                f"DDoS — {name.replace('_', ' ').title()}",
                str(data.get("total_requests", 0)),
                f"[{color}]{pct}%[/{color}]",
                "—",
                "—",
            )

    console.print(table)
    console.print()

    if score:
        grade = score.get("grade", "?")
        s     = score.get("score", 0)
        grade_color = {
            "A": "bold green", "B": "green", "C": "yellow",
            "D": "red", "F": "bold red",
        }.get(grade, "white")
        console.print(
            f"  [bold white]Protection Score:[/bold white]  "
            f"[{grade_color}]{grade}  ({s}/100)[/{grade_color}]"
        )

    console.print(f"\n  [bold cyan]WAF:[/bold cyan] {preflight.get('waf_detected', 'N/A')}")
    console.print(f"  [bold cyan]Blocking Mode:[/bold cyan] {preflight.get('blocking_mode', 'N/A')}")
    console.print(f"  [bold cyan]CDN:[/bold cyan] {preflight.get('cdn_detected', 'N/A')}")
    console.print()
    console.print(f"  [bold green]JSON Report:[/bold green] {json_path}")
    console.print(f"  [bold green]HTML Report:[/bold green] {html_path}")
    if log_path:
        console.print(f"  [bold green]Log File:[/bold green]  {log_path}")
    console.print()
