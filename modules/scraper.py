import logging
import random
import time
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from .utils import (
    console, log, now_utc, stealth_headers, aggressive_headers,
    random_ua, phase_banner, classify_response, get_proxy_dict, get_basic_auth,
)

BLOCK_CODES = {403, 406, 429, 503}

GUESS_PATHS = [
    "/api/products",
    "/api/catalog",
    "/api/prices",
    "/api/items",
    "/api/v1/products",
    "/api/v2/catalog",
    "/search?q=*",
    "/search?query=test",
    "/products",
    "/catalog",
    "/shop",
    "/store",
]


def _extract_product_data(html: str, url: str) -> dict:
    # XML documents (sitemaps, feeds) contain no extractable product HTML — skip them
    if html.lstrip().startswith("<?xml") or url.endswith(".xml"):
        return {"url": url, "name": None, "price": None, "description": None, "images": []}
    soup = BeautifulSoup(html, "lxml")
    data: dict = {"url": url, "name": None, "price": None, "description": None, "images": []}

    for sel in ["h1", "[class*=product-title]", "[class*=product-name]", "[itemprop=name]"]:
        el = soup.select_one(sel)
        if el and el.text.strip():
            data["name"] = el.text.strip()
            break

    for sel in ["[class*=price]", "[itemprop=price]", "[class*=amount]", ".price"]:
        el = soup.select_one(sel)
        if el and el.text.strip():
            data["price"] = el.text.strip()
            break

    for sel in ["[itemprop=description]", "[class*=description]", "[class*=product-desc]"]:
        el = soup.select_one(sel)
        if el and el.text.strip():
            data["description"] = el.text.strip()[:300]
            break

    for img in soup.find_all("img", src=True):
        src = img.get("src", "")
        if any(kw in src.lower() for kw in ["product", "item", "catalog"]):
            data["images"].append(urljoin(url, src))
            if len(data["images"]) >= 3:
                break

    return data


def _fetch_stealth(url: str, session: requests.Session, delay_min: float, delay_max: float) -> dict:
    time.sleep(random.uniform(delay_min, delay_max))
    hdrs = stealth_headers(url)
    ts = now_utc()
    try:
        r = session.get(url, headers=hdrs, timeout=15, allow_redirects=True)
        body = r.text or ""
        block_type = classify_response(r.status_code, dict(r.headers), body)
        return {
            "timestamp":        ts,
            "phase":            "scrape_stealth",
            "url":              url,
            "http_code":        r.status_code,
            "block_type":       block_type,
            "response_headers": dict(r.headers),
            "body_snippet":     body[:300],
            "html":             body if r.status_code == 200 else "",
            "error":            None,
        }
    except Exception as e:
        return {
            "timestamp":        ts,
            "phase":            "scrape_stealth",
            "url":              url,
            "http_code":        0,
            "block_type":       "ERROR",
            "response_headers": {},
            "body_snippet":     str(e),
            "html":             "",
            "error":            str(e),
        }


def _fetch_aggressive(url: str, proxies: Optional[dict] = None) -> dict:
    hdrs = aggressive_headers()
    ts = now_utc()
    try:
        r = requests.get(url, headers=hdrs, timeout=10, allow_redirects=False, proxies=proxies)
        body = r.text or ""
        block_type = classify_response(r.status_code, dict(r.headers), body)
        return {
            "timestamp":        ts,
            "phase":            "scrape_aggressive",
            "url":              url,
            "http_code":        r.status_code,
            "block_type":       block_type,
            "response_headers": dict(r.headers),
            "body_snippet":     body[:300],
            "html":             body if r.status_code == 200 else "",
            "error":            None,
        }
    except Exception as e:
        return {
            "timestamp":        ts,
            "phase":            "scrape_aggressive",
            "url":              url,
            "http_code":        0,
            "block_type":       "ERROR",
            "response_headers": {},
            "body_snippet":     str(e),
            "html":             "",
            "error":            str(e),
        }


def _tally(results: list[dict]) -> dict:
    tally: dict = {"200": 0, "301": 0, "302": 0, "403": 0, "429": 0, "503": 0, "other": 0, "error": 0}
    for r in results:
        code = r.get("http_code", 0)
        key = str(code)
        if key in tally:
            tally[key] += 1
        elif code == 0:
            tally["error"] += 1
        else:
            tally["other"] += 1
    total = len(results)
    blocked = sum(1 for r in results if r.get("http_code") in BLOCK_CODES)
    return {
        "responses": tally,
        "blocked_pct": round(blocked / total * 100, 2) if total else 0.0,
    }


def run_stealth(
    target_url: str,
    discovered_urls: list[str],
    cfg: dict,
    logger: Optional[logging.Logger] = None,
) -> dict:
    phase_banner("PHASE 2A: STEALTH SCRAPING")

    threads = cfg.get("threads", 3)
    delay_min = cfg.get("delay_min", 1.5)
    delay_max = cfg.get("delay_max", 4.0)
    max_pages = cfg.get("max_pages", 100)

    urls = list(dict.fromkeys([target_url] + discovered_urls))[:max_pages]
    proxies = get_proxy_dict()
    session = requests.Session()
    if proxies:
        session.proxies.update(proxies)

    raw_results: list[dict] = []
    items_extracted: list[dict] = []

    log(f"[SCRAPE:STEALTH] Targeting {len(urls)} URLs | threads={threads} | delay={delay_min}-{delay_max}s",
        "info", logger)

    start = time.time()
    with Progress(
        SpinnerColumn(),
        TextColumn("[cyan][STEALTH][/cyan] {task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Scraping...", total=len(urls))

        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(_fetch_stealth, u, session, delay_min, delay_max): u for u in urls}
            for future in as_completed(futures):
                res = future.result()
                raw_results.append(res)
                if res["http_code"] == 200 and res.get("html"):
                    product = _extract_product_data(res["html"], res["url"])
                    if product["name"] or product["price"]:
                        items_extracted.append(product)
                progress.advance(task)

    duration = time.time() - start
    tally = _tally(raw_results)

    log(f"[SCRAPE:STEALTH] Done — {len(raw_results)} requests | "
        f"{tally['blocked_pct']}% blocked | {len(items_extracted)} items extracted",
        "success", logger)

    return {
        "duration_s": round(duration, 1),
        "total_requests": len(raw_results),
        "responses": tally["responses"],
        "blocked_pct": tally["blocked_pct"],
        "items_extracted": len(items_extracted),
        "pages_crawled": len(urls),
        "sample_items": items_extracted[:20],
        "raw_results": raw_results,
    }


def run_aggressive(
    target_url: str,
    discovered_urls: list[str],
    cfg: dict,
    logger: Optional[logging.Logger] = None,
) -> dict:
    phase_banner("PHASE 2B: AGGRESSIVE SCRAPING")

    threads = cfg.get("threads", 10)
    max_pages = cfg.get("max_pages", 200)

    parsed = urlparse(target_url)
    base = f"{parsed.scheme}://{parsed.netloc}"

    guessed = [base.rstrip("/") + p for p in GUESS_PATHS]
    urls = list(dict.fromkeys([target_url] + discovered_urls + guessed))[:max_pages]

    raw_results: list[dict] = []
    items_extracted: list[dict] = []

    log(f"[SCRAPE:AGGRESSIVE] Targeting {len(urls)} URLs | threads={threads} | no delays", "info", logger)

    start = time.time()
    with Progress(
        SpinnerColumn(),
        TextColumn("[red][AGGRESSIVE][/red] {task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Hammering...", total=len(urls))

        proxies = get_proxy_dict()
        with ThreadPoolExecutor(max_workers=threads) as ex:
            futures = {ex.submit(_fetch_aggressive, u, proxies): u for u in urls}
            for future in as_completed(futures):
                res = future.result()
                raw_results.append(res)
                if res["http_code"] == 200 and res.get("html"):
                    product = _extract_product_data(res["html"], res["url"])
                    if product["name"] or product["price"]:
                        items_extracted.append(product)
                progress.advance(task)

    duration = time.time() - start
    tally = _tally(raw_results)

    log(f"[SCRAPE:AGGRESSIVE] Done — {len(raw_results)} requests | "
        f"{tally['blocked_pct']}% blocked | {len(items_extracted)} items extracted",
        "success" if tally["blocked_pct"] < 50 else "warning", logger)

    return {
        "duration_s": round(duration, 1),
        "total_requests": len(raw_results),
        "responses": tally["responses"],
        "blocked_pct": tally["blocked_pct"],
        "items_extracted": len(items_extracted),
        "pages_crawled": len(urls),
        "sample_items": items_extracted[:20],
        "raw_results": raw_results,
    }


# ── Nuclear UA list ───────────────────────────────────────────────────────────

NUCLEAR_UAS = [
    "python-requests/2.31.0",
    "curl/7.88.1",
    "Wget/1.21.3",
    "Go-http-client/1.1",
    "Java/1.8.0_292",
    "Scrapy/2.11.0 (+https://scrapy.org)",
    "Nikto/2.1.6",
    "sqlmap/1.7 (https://sqlmap.org)",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "HeadlessChrome/124.0.0.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36; Selenium/4.0.0",
    "Mozilla/5.0 (Unknown; Linux x86_64) AppleWebKit/534.34 (KHTML, like Gecko) PhantomJS/1.9.8 Safari/534.34",
    "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)",
    "",
]


def run_nuclear(
    target_url: str,
    discovered_urls: list,
    cfg: dict,
    logger=None,
) -> dict:
    phase_banner("PHASE 2C: NUCLEAR SCRAPING")

    max_pages = cfg.get("max_pages", 9999)
    # Cap URL list but do NOT deduplicate — every URL will be hit with every UA
    urls = ([target_url] + discovered_urls)[:max_pages]

    # Build full task list: (url, ua) for every combination
    tasks = [(url, ua) for url in urls for ua in NUCLEAR_UAS]

    log(
        f"[SCRAPE:NUCLEAR] {len(urls)} URLs x {len(NUCLEAR_UAS)} UAs = "
        f"{len(tasks)} total requests | 200 threads | no delays",
        "info", logger,
    )

    proxies = get_proxy_dict()
    auth    = get_basic_auth()

    import threading as _threading

    # Per-UA tracking: {ua: {"requests": 0, "blocked": 0}}
    ua_stats: dict = {ua: {"requests": 0, "blocked": 0} for ua in NUCLEAR_UAS}
    ua_lock = _threading.Lock()

    nuclear_block_codes = {403, 406, 429, 503}

    def _fetch_nuclear(url: str, ua: str) -> dict:
        hdrs = {"User-Agent": ua} if ua else {}
        ts = now_utc()
        try:
            r = requests.get(
                url,
                headers=hdrs,
                timeout=10,
                allow_redirects=False,
                proxies=proxies,
                auth=auth,
                verify=False,
            )
            blocked = r.status_code in nuclear_block_codes
            with ua_lock:
                ua_stats[ua]["requests"] += 1
                if blocked:
                    ua_stats[ua]["blocked"] += 1
            body = r.text or ""
            block_type = classify_response(r.status_code, dict(r.headers), body)
            return {
                "timestamp":  ts,
                "phase":      "scrape_nuclear",
                "url":        url,
                "ua":         ua,
                "http_code":  r.status_code,
                "block_type": block_type,
                "error":      None,
            }
        except Exception as e:
            with ua_lock:
                ua_stats[ua]["requests"] += 1
            return {
                "timestamp":  ts,
                "phase":      "scrape_nuclear",
                "url":        url,
                "ua":         ua,
                "http_code":  0,
                "block_type": "ERROR",
                "error":      str(e),
            }

    raw_results: list = []

    start = time.time()
    with Progress(
        SpinnerColumn(),
        TextColumn("[bold red][NUCLEAR][/bold red] {task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task("Nuking...", total=len(tasks))

        with ThreadPoolExecutor(max_workers=200) as ex:
            futures = {ex.submit(_fetch_nuclear, url, ua): (url, ua) for url, ua in tasks}
            for future in as_completed(futures):
                res = future.result()
                raw_results.append(res)
                progress.advance(task_id)

    duration = time.time() - start

    # ── Build tally ──
    tally: dict = {"200": 0, "301": 0, "302": 0, "403": 0, "429": 0, "503": 0, "other": 0, "error": 0}
    for r in raw_results:
        code = r.get("http_code", 0)
        key  = str(code)
        if key in tally:
            tally[key] += 1
        elif code == 0:
            tally["error"] += 1
        else:
            tally["other"] += 1

    total_reqs   = len(raw_results)
    total_block  = sum(1 for r in raw_results if r.get("http_code") in nuclear_block_codes)
    blocked_pct  = round(total_block / total_reqs * 100, 2) if total_reqs else 0.0

    # ── Per-UA results ──
    ua_results = []
    for ua in NUCLEAR_UAS:
        stats   = ua_stats[ua]
        reqs    = stats["requests"]
        blocked = stats["blocked"]
        pct     = round(blocked / reqs * 100, 2) if reqs else 0.0
        if pct >= 80:
            verdict = "GOOD"
        elif pct >= 30:
            verdict = "PARTIAL"
        else:
            verdict = "LEAKING"
        ua_results.append({
            "ua":        ua or "(empty)",
            "requests":  reqs,
            "blocked":   blocked,
            "block_pct": pct,
            "verdict":   verdict,
        })

    # ── Print UA results table ──
    tbl = Table(title="Nuclear UA Results", show_header=True, header_style="bold magenta")
    tbl.add_column("User-Agent",  style="white",  max_width=55)
    tbl.add_column("Requests",    justify="right")
    tbl.add_column("Blocked",     justify="right")
    tbl.add_column("Block%",      justify="right")
    tbl.add_column("Verdict",     justify="center")

    for row in ua_results:
        pct_s = f"{row['block_pct']:.1f}%"
        if row["verdict"] == "GOOD":
            verdict_fmt = "[bold green]GOOD[/bold green]"
        elif row["verdict"] == "PARTIAL":
            verdict_fmt = "[bold yellow]PARTIAL[/bold yellow]"
        else:
            verdict_fmt = "[bold red]LEAKING[/bold red]"
        tbl.add_row(
            row["ua"],
            str(row["requests"]),
            str(row["blocked"]),
            pct_s,
            verdict_fmt,
        )

    console.print(tbl)

    log(
        f"[SCRAPE:NUCLEAR] Done — {total_reqs} requests in {duration:.1f}s | "
        f"{blocked_pct}% overall blocked",
        "success" if blocked_pct >= 50 else "warning", logger,
    )

    return {
        "duration_s":     round(duration, 1),
        "total_requests": total_reqs,
        "blocked_pct":    blocked_pct,
        "ua_results":     ua_results,
        "responses":      tally,
    }
