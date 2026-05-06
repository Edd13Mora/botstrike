"""
Good bot preservation test.

Sends requests with the User-Agent strings of well-known legitimate crawlers
(Googlebot, Bingbot, Meta, etc.) and verifies they are NOT blocked.

Caveat: UA-level testing only. WAFs that verify Googlebot via reverse-DNS
will correctly allow real Google crawlers even if this test shows a 403 —
that is the correct behavior. Flag UA-level blocks as findings when the WAF
cannot do IP verification, which is the case for most SaaS deployments.

A sanity check (python-requests UA) is also sent — it SHOULD be blocked.
"""

import time
import logging
from typing import Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from .utils import console, log, phase_banner, get_proxy_dict

GOOD_BOTS: list[tuple[str, str]] = [
    ("Googlebot",       "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"),
    ("Google Image",    "Googlebot-Image/1.0"),
    ("Bingbot",         "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"),
    ("DuckDuckBot",     "DuckDuckBot/1.0; (+http://duckduckgo.com/duckduckbot.html)"),
    ("Applebot",        "Mozilla/5.0 (compatible; Applebot/0.3; +http://www.apple.com/go/applebot)"),
    ("Meta/Facebook",   "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)"),
    ("Twitterbot",      "Twitterbot/1.0"),
    ("LinkedInBot",     "LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient/4.5.13)"),
    ("Yahoo Slurp",     "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)"),
]

SANITY_BOT_NAME = "python-requests (bad bot — should be blocked)"
SANITY_BOT_UA   = "python-requests/2.31.0"

BLOCK_CODES = {403, 406, 429, 503}


def run(target_url: str, cfg: dict, logger: Optional[logging.Logger] = None) -> dict:
    phase_banner("MODULE 0b: GOOD BOT PRESERVATION TEST")
    timeout = cfg.get("preflight", {}).get("timeout", 10)
    proxies = get_proxy_dict()
    results: list[dict] = []
    blocked_bots: list[str] = []

    log("[GOODBOT] Checking that legitimate crawlers are not blocked...", "info", logger)

    session = requests.Session()

    for name, ua in GOOD_BOTS:
        entry: dict = {"name": name, "ua": ua, "status_code": None, "blocked": None}
        try:
            r = session.get(
                target_url,
                headers={"User-Agent": ua, "Accept": "text/html,application/xhtml+xml,*/*"},
                timeout=timeout,
                proxies=proxies,
                allow_redirects=True,
                verify=False,
            )
            entry["status_code"] = r.status_code
            entry["blocked"] = r.status_code in BLOCK_CODES
            if entry["blocked"]:
                blocked_bots.append(name)
                log(f"  [!] {name:<22} BLOCKED ({r.status_code})", "warning", logger)
                console.print(f"  [bold red][BLOCKED][/bold red] {name:<22} HTTP {r.status_code}")
            else:
                log(f"  [✓] {name:<22} allowed ({r.status_code})", "success", logger)
                console.print(f"  [bold green][ALLOWED][/bold green] {name:<22} HTTP {r.status_code}")
        except Exception as e:
            entry["error"] = str(e)
            log(f"  [?] {name:<22} error: {e}", "warning", logger)
            console.print(f"  [yellow][ERROR  ][/yellow] {name:<22} {e}")
        results.append(entry)
        time.sleep(0.3)

    # Sanity check: a known-bad bot UA should be blocked
    sanity: dict = {"name": SANITY_BOT_NAME, "ua": SANITY_BOT_UA, "status_code": None, "blocked": None}
    try:
        r = session.get(
            target_url,
            headers={"User-Agent": SANITY_BOT_UA},
            timeout=timeout,
            proxies=proxies,
            allow_redirects=True,
            verify=False,
        )
        sanity["status_code"] = r.status_code
        sanity["blocked"] = r.status_code in BLOCK_CODES
        indicator = "[bold green][SANITY OK  ][/bold green]" if sanity["blocked"] else "[bold yellow][SANITY WARN][/bold yellow]"
        note = f"bad-bot UA blocked ({r.status_code})" if sanity["blocked"] else f"bad-bot UA NOT blocked ({r.status_code}) — WAF may be passive"
        console.print(f"  {indicator} python-requests UA — {note}")
    except Exception as e:
        sanity["error"] = str(e)

    over_blocked = len(blocked_bots)
    console.print()
    if over_blocked:
        console.print(f"  [bold red][!] {over_blocked} legitimate crawler(s) were blocked: {', '.join(blocked_bots)}[/bold red]")
        console.print("  [dim]Note: UA-level test only. IP-verified WAFs may correctly allow real crawlers despite this result.[/dim]")
    else:
        console.print(f"  [bold green][✓] All {len(GOOD_BOTS)} legitimate crawlers allowed — good bot preservation intact.[/bold green]")

    return {
        "results":                results,
        "blocked_bots":           blocked_bots,
        "over_blocked_count":     over_blocked,
        "sanity_bad_bot_blocked": sanity.get("blocked"),
        "note": (
            "UA-level test only. WAFs that verify Googlebot/Bingbot via reverse-DNS "
            "correctly allow real crawlers regardless of this result."
        ),
    }
