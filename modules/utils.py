import base64
import os
import re
import random
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.theme import Theme

TOOL_VERSION = "1.0"

custom_theme = Theme({
    "success":  "bold green",
    "warning":  "bold yellow",
    "error":    "bold red",
    "info":     "bold cyan",
    "dim":      "dim white",
})

console = Console(theme=custom_theme)

# ─── Proxy config (module-level, set once at startup) ────────────────────────

_PROXY_URL: Optional[str] = None


def set_proxy(url: str) -> None:
    global _PROXY_URL
    _PROXY_URL = url


def get_proxy_dict() -> Optional[dict]:
    if not _PROXY_URL:
        return None
    return {"http": _PROXY_URL, "https": _PROXY_URL}


# ─── Basic auth config (module-level, set once at startup) ───────────────────

_BASIC_AUTH: Optional[tuple[str, str]] = None


def set_basic_auth(username: str, password: str) -> None:
    global _BASIC_AUTH
    _BASIC_AUTH = (username, password)


def get_basic_auth() -> Optional[tuple[str, str]]:
    """Return (username, password) tuple or None. Pass directly to requests auth=."""
    return _BASIC_AUTH


# ─── Scan tag (client-visible identification header) ─────────────────────────

_SCAN_TAG: Optional[str] = None


def set_scan_tag(tag: str) -> None:
    global _SCAN_TAG
    _SCAN_TAG = tag.strip()


def get_scan_tag() -> Optional[str]:
    return _SCAN_TAG


# ─── User-Agent pool ─────────────────────────────────────────────────────────

_ua_pool: list[str] = []
_ua_pool_loaded = False

ACCEPT_LANGUAGES = [
    "en-US,en;q=0.9",
    "fr-FR,fr;q=0.9,en;q=0.8",
    "de-DE,de;q=0.9,en;q=0.8",
    "es-ES,es;q=0.9,en;q=0.8",
    "it-IT,it;q=0.9,en;q=0.8",
    "pt-BR,pt;q=0.9,en;q=0.8",
    "nl-NL,nl;q=0.9,en;q=0.8",
    "pl-PL,pl;q=0.9,en;q=0.8",
    "ja-JP,ja;q=0.9,en;q=0.8",
    "zh-CN,zh;q=0.9,en;q=0.8",
]

REFERRERS = [
    "https://www.google.com/",
    "https://www.google.fr/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
    "https://www.google.de/",
    "",
    "",
    "",
]


def load_useragents() -> list[str]:
    global _ua_pool, _ua_pool_loaded
    if _ua_pool_loaded:
        return _ua_pool
    ua_path = Path(__file__).parent.parent / "wordlists" / "useragents.txt"
    if ua_path.exists():
        lines = ua_path.read_text(encoding="utf-8").splitlines()
        _ua_pool = [l.strip() for l in lines if l.strip()]
    if not _ua_pool:
        _ua_pool = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
        ]
    _ua_pool_loaded = True
    return _ua_pool


def random_ua() -> str:
    return random.choice(load_useragents())


# ─── Browser fingerprint consistency (sec-ch-ua) ─────────────────────────────

def _parse_sec_ch_ua(ua: str) -> dict:
    """
    Generate matching sec-ch-ua client hint headers for a given User-Agent string.
    Firefox and Safari intentionally omit these headers — we mirror that behaviour.
    """
    extra: dict[str, str] = {}

    is_mobile = any(kw in ua for kw in ("Mobile", "Android", "iPhone", "iPad"))
    extra["Sec-CH-UA-Mobile"] = "?1" if is_mobile else "?0"

    if "Windows" in ua:
        extra["Sec-CH-UA-Platform"] = '"Windows"'
    elif "Macintosh" in ua or "Mac OS X" in ua:
        extra["Sec-CH-UA-Platform"] = '"macOS"'
    elif "Android" in ua:
        extra["Sec-CH-UA-Platform"] = '"Android"'
    elif "iPhone" in ua or "iPad" in ua:
        extra["Sec-CH-UA-Platform"] = '"iOS"'
    elif "Linux" in ua:
        extra["Sec-CH-UA-Platform"] = '"Linux"'
    else:
        extra["Sec-CH-UA-Platform"] = '"Unknown"'

    # Firefox / pure Safari → no sec-ch-ua
    is_firefox = "Firefox" in ua
    is_pure_safari = "Safari" in ua and "Chrome" not in ua and "CriOS" not in ua
    if is_firefox or is_pure_safari:
        return {}

    # Microsoft Edge
    edge_m = re.search(r"Edg(?:e)?/(\d+)", ua)
    if edge_m:
        v = edge_m.group(1)
        extra["Sec-CH-UA"] = (
            f'"Chromium";v="{v}", "Microsoft Edge";v="{v}", "Not-A.Brand";v="99"'
        )
        return extra

    # Samsung Internet
    samsung_m = re.search(r"SamsungBrowser/(\d+)", ua)
    if samsung_m:
        sv = samsung_m.group(1)
        chrome_m = re.search(r"Chrome/(\d+)", ua)
        cv = chrome_m.group(1) if chrome_m else "121"
        extra["Sec-CH-UA"] = (
            f'"Chromium";v="{cv}", "Samsung Internet";v="{sv}", "Not-A.Brand";v="99"'
        )
        return extra

    # Chrome / CriOS (Chrome on iOS)
    chrome_m = re.search(r"(?:Chrome|CriOS)/(\d+)", ua)
    if chrome_m:
        v = chrome_m.group(1)
        extra["Sec-CH-UA"] = (
            f'"Chromium";v="{v}", "Google Chrome";v="{v}", "Not-A.Brand";v="99"'
        )
        return extra

    return {}


def stealth_headers(base_url: str = "") -> dict:
    ua = random_ua()
    headers: dict[str, str] = {
        "User-Agent": ua,
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;"
            "q=0.9,image/avif,image/webp,*/*;q=0.8"
        ),
        "Accept-Language": random.choice(ACCEPT_LANGUAGES),
        "Accept-Encoding": "gzip, deflate, br",
        "Connection": "keep-alive",
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
    }

    # Inject matching sec-ch-ua headers (browser fingerprint consistency)
    headers.update(_parse_sec_ch_ua(ua))

    ref = random.choice(REFERRERS)
    if ref:
        headers["Referer"] = ref

    # Inject Basic Auth header if credentials were provided
    if _BASIC_AUTH:
        creds = base64.b64encode(f"{_BASIC_AUTH[0]}:{_BASIC_AUTH[1]}".encode()).decode()
        headers["Authorization"] = f"Basic {creds}"

    # Always inject BotStrike identification so client can filter WAF dashboard
    headers["X-BotStrike-Scan"] = "1"
    headers["X-BotStrike-Version"] = TOOL_VERSION
    if _SCAN_TAG:
        headers["X-BotStrike-Tag"] = _SCAN_TAG

    # Shuffle header order to avoid fingerprinting on ordering
    items = list(headers.items())
    random.shuffle(items)
    return dict(items)


def aggressive_headers() -> dict:
    h = {
        "User-Agent": "python-requests/2.31.0",
        "X-BotStrike-Scan": "1",
        "X-BotStrike-Version": TOOL_VERSION,
    }
    if _SCAN_TAG:
        h["X-BotStrike-Tag"] = _SCAN_TAG
    return h


# ─── Response classification ──────────────────────────────────────────────────

_CAPTCHA_KW = (
    "captcha", "recaptcha", "hcaptcha", "px-captcha", "challenge",
    "verify you are human", "are you a robot", "prove you're human",
    "datadome captcha", "please verify", "security check",
    "i am not a robot", "click to verify",
)

_HARD_BLOCK_KW = (
    "access denied", "blocked", "forbidden", "not acceptable",
    "your ip", "your request has been blocked", "request unsuccessful",
    "the requested url was rejected",
)


def classify_response(status_code: int, headers: dict, body: str) -> str:
    """
    Classify a WAF/bot-protection response into one of five categories:
      CAPTCHA_CHALLENGE  — human verification offered
      RATE_LIMIT         — 429 threshold hit, not necessarily bot-specific
      SOFT_REDIRECT      — redirect to block/challenge page
      HARD_BLOCK         — 403/406/503 with no recovery path
      PASSED             — request succeeded
    """
    body_lower = body.lower() if body else ""

    if any(kw in body_lower for kw in _CAPTCHA_KW):
        return "CAPTCHA_CHALLENGE"

    if status_code == 429:
        return "RATE_LIMIT"

    if status_code in (301, 302, 307, 308):
        location = headers.get("Location", headers.get("location", "")).lower()
        if any(kw in location for kw in ("block", "deny", "verify", "challenge", "captcha")):
            return "SOFT_REDIRECT"
        return "REDIRECT"

    if status_code in (403, 406, 503):
        return "HARD_BLOCK"

    if status_code in (200, 201, 202, 204):
        return "PASSED"

    return "OTHER"


# ─── Timestamp / session helpers ─────────────────────────────────────────────

def now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_session_id() -> str:
    return str(uuid.uuid4())


def make_report_dir(target_url: str, session_id: str) -> Path:
    host = target_url.replace("https://", "").replace("http://", "")
    for ch in [".", "/", ":", "?", "#", "@", "=", "&", "%"]:
        host = host.replace(ch, "_")
    host = host.strip("_")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    folder_name = f"{host}_{ts}"
    base = Path(__file__).parent.parent / "reports" / folder_name
    if base.exists():
        short = session_id[:4]
        base = base.parent / f"{folder_name}_{short}"
    base.mkdir(parents=True, exist_ok=True)
    return base


def setup_file_logger(report_dir: Path, session_id: str) -> logging.Logger:
    log_path = report_dir / f"botstrike_{session_id}.log"
    logger = logging.getLogger(f"botstrike.{session_id}")
    logger.setLevel(logging.DEBUG)
    if not logger.handlers:
        fh = logging.FileHandler(log_path, encoding="utf-8")
        fh.setLevel(logging.DEBUG)
        fmt = logging.Formatter(
            "%(asctime)s [%(levelname)s] %(message)s",
            datefmt="%Y-%m-%dT%H:%M:%SZ",
        )
        fh.setFormatter(fmt)
        logger.addHandler(fh)
    return logger


# ─── Console helpers ──────────────────────────────────────────────────────────

def log(msg: str, level: str = "info", logger: Optional[logging.Logger] = None) -> None:
    ts = now_utc()
    style_map = {
        "info": "info", "success": "success",
        "warning": "warning", "error": "error", "dim": "dim",
    }
    style = style_map.get(level, "info")
    console.print(f"[{ts}] {msg}", style=style)
    if logger:
        log_fn = getattr(
            logger,
            level if level in ("info", "warning", "error", "debug") else "info",
        )
        log_fn(msg)


def phase_banner(title: str) -> None:
    width = 60
    bar = "═" * ((width - len(title) - 2) // 2)
    console.print(f"\n[bold cyan]{bar} {title} {bar}[/bold cyan]\n")


def print_banner() -> None:
    banner = r"""
 ____        _   ____  _        _ _
| __ )  ___ | |_/ ___|| |_ _ __(_) | _____
|  _ \ / _ \| __\___ \| __| '__| | |/ / _ \
| |_) | (_) | |_ ___) | |_| |  | |   <  __/
|____/ \___/ \__|____/ \__|_|  |_|_|\_\___|
"""
    console.print(f"[bold cyan]{banner}[/bold cyan]")
    console.print(
        f"[bold white]  BotStrike v{TOOL_VERSION}[/bold white]  |  "
        "[dim]Bot Protection Effectiveness Tester[/dim]"
    )
    console.print("  [dim]DataDome · CrowdSec · Cloudflare comparison platform[/dim]")
    console.print()
    console.rule("[bold red]LEGAL DISCLAIMER[/bold red]")
    console.print(
        "[yellow]  For authorized security testing only. Unauthorized use against systems\n"
        "  you do not own or have explicit permission to test is illegal and may\n"
        "  result in criminal prosecution. By using this tool you confirm you have\n"
        "  written authorization from the target system owner.[/yellow]"
    )
    console.rule()
    console.print()
