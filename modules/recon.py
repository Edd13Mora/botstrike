import logging
from collections import defaultdict
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from rich.table import Table

from .utils import console, log, now_utc, stealth_headers, get_proxy_dict

URL_CATEGORIES = {
    "product": ["/product", "/item", "/p/", "/detail", "/produit", "/artikel"],
    "category": ["/category", "/cat/", "/c/", "/collection", "/catalog", "/categorie"],
    "search": ["/search", "/recherche", "/suche", "/buscar", "?q=", "?search=", "?s="],
    "cart": ["/cart", "/basket", "/panier", "/warenkorb", "/checkout"],
    "api": ["/api/", "/graphql", "/v1/", "/v2/", "/rest/"],
    "static": [".css", ".js", ".png", ".jpg", ".svg", ".ico", ".woff"],
}

GUESS_PATHS = [
    "/api/products",
    "/api/catalog",
    "/api/prices",
    "/api/items",
    "/api/v1/products",
    "/api/v2/products",
    "/search?q=*",
    "/sitemap.xml",
    "/robots.txt",
    "/wp-json/wc/v3/products",
    "/.well-known/security.txt",
]


def _categorize(url: str) -> str:
    lower = url.lower()
    for cat, patterns in URL_CATEGORIES.items():
        for p in patterns:
            if p in lower:
                return cat
    return "other"


def _is_internal(url: str, base_host: str) -> bool:
    try:
        parsed = urlparse(url)
        return parsed.hostname == base_host or parsed.hostname is None
    except Exception:
        return False


def _extract_links(html: str, base_url: str, base_host: str) -> list[str]:
    soup = BeautifulSoup(html, "lxml")
    links = []
    for tag in soup.find_all("a", href=True):
        href = tag["href"].strip()
        if not href or href.startswith("#") or href.startswith("mailto:") or href.startswith("tel:"):
            continue
        full = urljoin(base_url, href)
        parsed = urlparse(full)
        if parsed.scheme not in ("http", "https"):
            continue
        if _is_internal(full, base_host):
            links.append(full)
    return list(set(links))


def run(target_url: str, timeout: int = 10, logger: Optional[logging.Logger] = None) -> dict:
    result: dict = {
        "robots_txt_content": "",
        "disallowed_paths": [],
        "allowed_paths": [],
        "sitemap_urls": [],
        "crawled_urls": [],
        "url_categories": defaultdict(list),
        "all_discovered_urls": [],
    }

    parsed_base = urlparse(target_url)
    base_host = parsed_base.hostname or ""
    proxies = get_proxy_dict()
    session = requests.Session()
    session.headers.update(stealth_headers())
    if proxies:
        session.proxies.update(proxies)

    log("[RECON] Fetching robots.txt...", "info", logger)
    robots_url = target_url.rstrip("/") + "/robots.txt"
    try:
        r = session.get(robots_url, timeout=timeout)
        if r.status_code == 200:
            result["robots_txt_content"] = r.text
            for line in r.text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    path = line[9:].strip()
                    if path:
                        result["disallowed_paths"].append(path)
                elif line.lower().startswith("allow:"):
                    path = line[6:].strip()
                    if path:
                        result["allowed_paths"].append(path)
            log(f"  robots.txt → {len(result['disallowed_paths'])} disallowed, "
                f"{len(result['allowed_paths'])} allowed paths", "success", logger)
        else:
            log(f"  robots.txt → HTTP {r.status_code}", "warning", logger)
    except Exception as e:
        log(f"  robots.txt error: {e}", "warning", logger)

    log("[RECON] Fetching sitemap.xml...", "info", logger)
    sitemap_url = target_url.rstrip("/") + "/sitemap.xml"
    try:
        r = session.get(sitemap_url, timeout=timeout)
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "lxml-xml") if "xml" in r.headers.get("Content-Type", "") \
                else BeautifulSoup(r.text, "lxml")
            locs = soup.find_all("loc")
            result["sitemap_urls"] = [loc.text.strip() for loc in locs]
            log(f"  sitemap.xml → {len(result['sitemap_urls'])} URLs extracted", "success", logger)
        else:
            log(f"  sitemap.xml → HTTP {r.status_code}", "warning", logger)
    except Exception as e:
        log(f"  sitemap.xml error: {e}", "warning", logger)

    log("[RECON] Crawling homepage for internal links...", "info", logger)
    discovered: set[str] = set()
    discovered.update(result["sitemap_urls"])

    try:
        r = session.get(target_url, timeout=timeout)
        if r.status_code == 200:
            home_links = _extract_links(r.text, target_url, base_host)
            result["crawled_urls"] = home_links
            discovered.update(home_links)
            log(f"  Homepage crawl → {len(home_links)} links found", "success", logger)
    except Exception as e:
        log(f"  Homepage crawl error: {e}", "warning", logger)

    discovered.add(target_url)
    result["all_discovered_urls"] = list(discovered)

    categorized: dict[str, list] = defaultdict(list)
    for url in result["all_discovered_urls"]:
        cat = _categorize(url)
        categorized[cat].append(url)
    result["url_categories"] = dict(categorized)

    _print_recon_summary(result)
    return result


def _print_recon_summary(r: dict) -> None:
    table = Table(title="Passive Recon Summary", show_header=True, header_style="bold cyan")
    table.add_column("Source", style="bold white", width=20)
    table.add_column("Count", justify="right")

    table.add_row("robots.txt disallowed", str(len(r["disallowed_paths"])))
    table.add_row("sitemap.xml URLs", str(len(r["sitemap_urls"])))
    table.add_row("Homepage links", str(len(r["crawled_urls"])))
    table.add_row("Total unique URLs", str(len(r["all_discovered_urls"])))

    cats = r.get("url_categories", {})
    for cat, urls in cats.items():
        table.add_row(f"  → {cat}", str(len(urls)))

    console.print(table)
    console.print()
