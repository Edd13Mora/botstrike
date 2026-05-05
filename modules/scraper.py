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
    random_ua, phase_banner, classify_response, get_proxy_dict,
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
