import logging
import threading
from collections import defaultdict
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from .utils import console, log, now_utc, stealth_headers, get_proxy_dict

FLOW_PATTERNS: dict[str, list[str]] = {
    "login":          ["/login", "/signin", "/sign-in", "/auth/login", "/account/login", "/user/login", "/session/new"],
    "signup":         ["/signup", "/register", "/sign-up", "/create-account", "/join", "/account/create", "/enroll"],
    "password_reset": ["/forgot", "/reset", "/password-reset", "/recover", "/account/recover", "/lost-password"],
    "checkout":       ["/checkout", "/cart", "/basket", "/bag", "/order/new", "/purchase"],
    "sales":          ["/pricing", "/plans", "/buy", "/quote", "/request-demo", "/contact-sales"],
    "api":            ["/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/rpc/"],
}


def classify_flows(urls: list[str]) -> dict[str, list[str]]:
    """
    Classify discovered URLs into named attack-flow categories.
    Returns only categories with at least one matching URL.
    """
    flows: dict[str, list[str]] = {k: [] for k in FLOW_PATTERNS}
    for url in urls:
        path = url.lower()
        for flow_name, patterns in FLOW_PATTERNS.items():
            if any(p in path for p in patterns):
                flows[flow_name].append(url)
                break
    return {k: v for k, v in flows.items() if v}


URL_CATEGORIES = {
    "product": ["/product", "/item", "/p/", "/detail", "/produit", "/artikel"],
    "category": ["/category", "/cat/", "/c/", "/collection", "/catalog", "/categorie"],
    "search": ["/search", "/recherche", "/suche", "/buscar", "?q=", "?search=", "?s="],
    "cart": ["/cart", "/basket", "/panier", "/warenkorb", "/checkout"],
    "api": ["/api/", "/graphql", "/v1/", "/v2/", "/rest/"],
    "static": [".css", ".js", ".png", ".jpg", ".svg", ".ico", ".woff"],
}

_PATHS_FILE = Path(__file__).parent.parent / "wordlists" / "paths.txt"
_PROBE_THREADS = 30
_PROBE_TIMEOUT = 5
# Any status code other than these is treated as "path exists"
_DEAD_CODES = {404, 410}


def _load_guess_paths() -> list[str]:
    """Load path wordlist from file, stripping comments and blank lines."""
    if not _PATHS_FILE.exists():
        return []
    paths = []
    for line in _PATHS_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            paths.append(line)
    return paths


def _probe_paths(base_url: str, paths: list[str], timeout: int,
                 logger: Optional[logging.Logger] = None) -> list[dict]:
    """
    Probe each path with a HEAD request in parallel.
    Returns list of {url, status_code} for paths that responded (non-404).
    """
    parsed = urlparse(base_url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    proxies = get_proxy_dict()
    hdrs = {"User-Agent": stealth_headers().get("User-Agent", "Mozilla/5.0")}

    results: list[dict] = []
    lock = threading.Lock()
    sem = threading.Semaphore(_PROBE_THREADS)

    def probe(path: str) -> None:
        url = base + path
        with sem:
            try:
                r = requests.head(url, headers=hdrs, timeout=timeout,
                                  proxies=proxies, allow_redirects=True, verify=False)
                if r.status_code not in _DEAD_CODES:
                    with lock:
                        results.append({"url": url, "status_code": r.status_code})
            except Exception:
                pass

    threads = [threading.Thread(target=probe, args=(p,), daemon=True) for p in paths]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    return results


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

    # ── Guessed path probing ──────────────────────────────────────────────────
    guess_paths = _load_guess_paths()
    if guess_paths:
        log(f"[RECON] Probing {len(guess_paths)} guessed paths ({_PROBE_THREADS} threads)...", "info", logger)
        console.print(f"  [cyan]Probing {len(guess_paths)} common paths...[/cyan]", end="")
        probed = _probe_paths(target_url, guess_paths, _PROBE_TIMEOUT, logger)
        live_guessed = [r["url"] for r in probed]
        discovered.update(live_guessed)
        result["guessed_paths_probed"]    = len(guess_paths)
        result["guessed_paths_live"]      = len(live_guessed)
        result["guessed_paths_results"]   = probed
        console.print(f" [bold green]{len(live_guessed)} live[/bold green] / {len(guess_paths)} probed")
        log(f"  Guessed paths — {len(live_guessed)} live out of {len(guess_paths)}", "success", logger)
    else:
        result["guessed_paths_probed"]  = 0
        result["guessed_paths_live"]    = 0
        result["guessed_paths_results"] = []

    result["all_discovered_urls"] = list(discovered)

    categorized: dict[str, list] = defaultdict(list)
    for url in result["all_discovered_urls"]:
        cat = _categorize(url)
        categorized[cat].append(url)
    result["url_categories"] = dict(categorized)

    result["classified_flows"] = classify_flows(result["all_discovered_urls"])

    _print_recon_summary(result)
    return result


def _print_recon_summary(r: dict) -> None:
    table = Table(title="Passive Recon Summary", show_header=True, header_style="bold cyan")
    table.add_column("Source", style="bold white", width=20)
    table.add_column("Count", justify="right")

    table.add_row("robots.txt disallowed", str(len(r["disallowed_paths"])))
    table.add_row("sitemap.xml URLs", str(len(r["sitemap_urls"])))
    table.add_row("Homepage links", str(len(r["crawled_urls"])))
    live = r.get("guessed_paths_live", 0)
    total_guessed = r.get("guessed_paths_probed", 0)
    if total_guessed:
        table.add_row(f"Guessed paths (live/{total_guessed})", str(live))
    table.add_row("Total unique URLs", str(len(r["all_discovered_urls"])))

    cats = r.get("url_categories", {})
    for cat, urls in cats.items():
        table.add_row(f"  → {cat}", str(len(urls)))

    flows = r.get("classified_flows", {})
    if flows:
        table.add_row("", "")
        table.add_row("[bold cyan]Attack Flows Found[/bold cyan]", "")
        for flow, urls in flows.items():
            table.add_row(f"  ★ {flow}", str(len(urls)))

    console.print(table)
    console.print()
