import logging
import re
import shutil
import subprocess
import threading
from collections import defaultdict
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from rich.table import Table

from .utils import console, log, now_utc, stealth_headers, get_proxy_dict

# ── Flow classification ───────────────────────────────────────────────────────

FLOW_PATTERNS: dict[str, list[str]] = {
    "login":          ["/login", "/signin", "/sign-in", "/auth/login", "/account/login", "/user/login", "/session/new"],
    "signup":         ["/signup", "/register", "/sign-up", "/create-account", "/join", "/account/create", "/enroll"],
    "password_reset": ["/forgot", "/reset", "/password-reset", "/recover", "/account/recover", "/lost-password"],
    "checkout":       ["/checkout", "/cart", "/basket", "/bag", "/order/new", "/purchase"],
    "sales":          ["/pricing", "/plans", "/buy", "/quote", "/request-demo", "/contact-sales"],
    "api":            ["/api/", "/v1/", "/v2/", "/v3/", "/graphql", "/rest/", "/rpc/"],
}


def classify_flows(urls: list[str]) -> dict[str, list[str]]:
    flows: dict[str, list[str]] = {k: [] for k in FLOW_PATTERNS}
    for url in urls:
        path = url.lower()
        for flow_name, patterns in FLOW_PATTERNS.items():
            if any(p in path for p in patterns):
                flows[flow_name].append(url)
                break
    return {k: v for k, v in flows.items() if v}


# ── URL categorisation (for reporting) ───────────────────────────────────────

URL_CATEGORIES = {
    "product":  ["/product", "/item", "/p/", "/detail", "/produit", "/artikel"],
    "category": ["/category", "/cat/", "/c/", "/collection", "/catalog", "/categorie"],
    "search":   ["/search", "/recherche", "/suche", "/buscar", "?q=", "?search=", "?s="],
    "cart":     ["/cart", "/basket", "/panier", "/warenkorb", "/checkout"],
    "api":      ["/api/", "/graphql", "/v1/", "/v2/", "/rest/"],
    "static":   [".css", ".js", ".png", ".jpg", ".svg", ".ico", ".woff"],
}


def _categorize(url: str) -> str:
    lower = url.lower()
    for cat, patterns in URL_CATEGORIES.items():
        for p in patterns:
            if p in lower:
                return cat
    return "other"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _is_internal(url: str, base_host: str) -> bool:
    try:
        return urlparse(url).hostname == base_host
    except Exception:
        return False


_STATIC_EXTS = frozenset({
    ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".webp", ".pdf",
    ".zip", ".tar", ".gz", ".map",
})


def _is_static(url: str) -> bool:
    path = urlparse(url).path.lower()
    return any(path.endswith(ext) for ext in _STATIC_EXTS)


# ── Deep HTML extraction ──────────────────────────────────────────────────────

def _extract_from_html(html: str, base_url: str, base_host: str) -> tuple[list[str], list[str], list[str]]:
    """
    Extract URLs from HTML more deeply than just <a href>.
    Returns (page_urls, js_file_urls, inline_js_paths).

    Sources:
      - <a href>
      - <form action>  (POST endpoints)
      - data-href, data-url, data-action, data-src, data-endpoint
      - <script src>   (collected for JS parsing)
      - <link href>    (non-static)
      - inline <script> content (parsed for API paths)
    """
    soup = BeautifulSoup(html, "lxml")
    page_urls: set[str] = set()
    js_urls:   set[str] = set()

    def _add(raw: str, source_url: str = base_url) -> None:
        raw = raw.strip()
        if not raw or raw.startswith(("#", "javascript:", "mailto:", "tel:", "data:")):
            return
        full = urljoin(source_url, raw)
        p = urlparse(full)
        if p.scheme not in ("http", "https"):
            return
        if _is_internal(full, base_host) and not _is_static(full):
            page_urls.add(full)

    # <a href>
    for tag in soup.find_all("a", href=True):
        _add(tag["href"])

    # <form action> — these are POST endpoints, valuable for flood targeting
    for tag in soup.find_all("form"):
        action = tag.get("action", "")
        if action:
            _add(action)

    # data-* attributes
    data_attrs = ("data-href", "data-url", "data-action", "data-src",
                  "data-endpoint", "data-target", "data-link", "data-path")
    for tag in soup.find_all(True):
        for attr in data_attrs:
            val = tag.get(attr, "")
            if val:
                _add(val)

    # <script src> — external JS files for parsing
    for tag in soup.find_all("script", src=True):
        src = tag["src"].strip()
        if src:
            full = urljoin(base_url, src)
            p = urlparse(full)
            if p.scheme in ("http", "https") and full.split("?")[0].endswith(".js"):
                js_urls.add(full)

    # Inline <script> — parse content directly for API paths
    inline_paths: set[str] = set()
    for tag in soup.find_all("script", src=False):
        content = tag.get_text()
        if content and len(content) > 20:
            for path in _extract_from_js(content, base_url):
                inline_paths.add(path)

    return list(page_urls), list(js_urls), list(inline_paths)


# ── JavaScript parsing ────────────────────────────────────────────────────────

# Patterns that find URL paths inside JavaScript source code
_JS_PATTERNS: list[re.Pattern] = [
    # fetch('/api/...') and fetch(`/api/${v}/...`)
    re.compile(r'''fetch\s*\(\s*['"`]([/][^'"`\s\)]{2,100})'''),
    # axios.get/post/put/patch/delete('/path')
    re.compile(r'''axios\s*\.\s*(?:get|post|put|patch|delete|head|request)\s*\(\s*['"`]([/][^'"`\s\)]{2,100})'''),
    # $.get/post/ajax(url)
    re.compile(r'''\$\s*\.\s*(?:get|post|ajax|put|delete)\s*\(\s*['"`]([/][^'"`\s\)]{2,100})'''),
    # {url: '/path'}  — used in $.ajax, axios config, etc.
    re.compile(r'''['"]url['"]\s*:\s*['"`]([/][^'"`\s,\)]{2,100})'''),
    # XMLHttpRequest .open('METHOD', '/path')
    re.compile(r'''\.open\s*\(\s*['"`]\w+['"`]\s*,\s*['"`]([/][^'"`\s\)]{2,100})'''),
    # this.$http.get/post  (Vue)
    re.compile(r'''\.\$http\s*\.\s*(?:get|post|put|delete|patch)\s*\(\s*['"`]([/][^'"`\s\)]{2,100})'''),
    # API string literals — paths starting with /api, /v1, /v2, /rest, /graphql
    re.compile(r'''['"`]([/](?:api|v\d+|rest|graphql|rpc|auth|account|user|product|order|cart|checkout|search|admin|catalog)[^'"`\s]{0,80})['"`]'''),
    # Vue/React/Angular route path: '/checkout'
    re.compile(r'''path\s*:\s*['"`]([/][^'"`\s]{1,80})['"`]'''),
    # next.js / react-router <Route path="/...">
    re.compile(r'''<Route[^>]+path\s*=\s*['"`]([/][^'"`\s]{1,80})['"`]'''),
]

_JS_STATIC = frozenset({".png", ".jpg", ".svg", ".css", ".woff", ".woff2", ".ico", ".gif"})


def _extract_from_js(js_content: str, base_url: str) -> list[str]:
    """Extract API paths and route definitions from JavaScript source."""
    found: set[str] = set()
    for pattern in _JS_PATTERNS:
        for m in pattern.finditer(js_content):
            path = m.group(1)
            # Strip template literal variables like ${version}
            path = re.sub(r'\$\{[^}]+\}', '', path).rstrip("/")
            if not path or not path.startswith("/"):
                continue
            if any(path.lower().endswith(ext) for ext in _JS_STATIC):
                continue
            if len(path) > 120:
                continue
            found.add(path)
    return list(found)


def _fetch_js_files(js_urls: list[str], session: requests.Session,
                    timeout: int, base_url: str,
                    logger: Optional[logging.Logger] = None) -> list[str]:
    """Fetch each JS file and extract API paths from it. Returns raw paths (not full URLs)."""
    all_paths: set[str] = set()
    lock = threading.Lock()

    def fetch_one(url: str) -> None:
        try:
            r = session.get(url, timeout=timeout, verify=False)
            if r.status_code == 200 and len(r.text) < 5_000_000:  # skip huge bundles >5MB
                paths = _extract_from_js(r.text, base_url)
                with lock:
                    all_paths.update(paths)
        except Exception:
            pass

    threads = [threading.Thread(target=fetch_one, args=(u,), daemon=True) for u in js_urls[:30]]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    log(f"  JS parsing → {len(all_paths)} paths extracted from {len(js_urls)} files", "success", logger)
    return list(all_paths)


# ── Path fuzzing ──────────────────────────────────────────────────────────────

def _fuzz_paths(discovered_paths: list[str]) -> list[str]:
    """
    Generate path variations from already-discovered API paths.
    Only fuzzes paths that look like API endpoints.
    """
    api_paths = [p for p in discovered_paths if re.search(r'/(?:api|v\d+|graphql|rest)', p.lower())]
    fuzzed: set[str] = set()

    for path in api_paths:
        # Version bumping: /v1/ → /v2/, /v3/
        for v in ("v1", "v2", "v3", "v4"):
            fuzzed.add(re.sub(r'/v\d+/', f'/{v}/', path))

        # JSON format hints
        if not re.search(r'\.(json|xml|html|csv)$', path):
            fuzzed.add(path + ".json")
            fuzzed.add(path + "?format=json")
            fuzzed.add(path + "?_format=json")

        # Common collection sub-resources
        base = path.rstrip("/")
        for suffix in ("/list", "/all", "/search", "/count", "/export",
                       "/1", "/me", "/status", "/schema"):
            fuzzed.add(base + suffix)

    # Remove paths already in the discovered set
    return list(fuzzed - set(discovered_paths))


# ── Parallel path prober ──────────────────────────────────────────────────────

_PATHS_FILE    = Path(__file__).parent.parent / "wordlists" / "paths.txt"
_PROBE_THREADS = 40
_PROBE_TIMEOUT = 5
_DEAD_CODES    = {404, 410}


def _load_guess_paths() -> list[str]:
    if not _PATHS_FILE.exists():
        return []
    paths = []
    for line in _PATHS_FILE.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            paths.append(line)
    return paths


def _probe_paths(base_url: str, paths: list[str], timeout: int,
                 label: str = "paths",
                 logger: Optional[logging.Logger] = None) -> list[dict]:
    """
    HEAD-probe a list of paths in parallel.
    Returns list of {url, status_code} for every path that responded (non-404/410).
    """
    parsed  = urlparse(base_url)
    base    = f"{parsed.scheme}://{parsed.netloc}"
    proxies = get_proxy_dict()
    hdrs    = {"User-Agent": stealth_headers().get("User-Agent", "Mozilla/5.0")}

    results: list[dict] = []
    lock = threading.Lock()
    sem  = threading.Semaphore(_PROBE_THREADS)

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


# ── Katana integration (optional external enrichment) ─────────────────────────

_KATANA_TIMEOUT = 120  # max seconds to wait for katana to finish


def _detect_distro() -> str:
    """Return lowercase distro ID from /etc/os-release, e.g. 'kali', 'ubuntu', 'debian'."""
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if line.startswith("ID="):
                return line.split("=", 1)[1].strip().strip('"').lower()
    except Exception:
        pass
    return ""


def _install_katana(logger: Optional[logging.Logger] = None) -> bool:
    """
    Auto-install katana using the best method available for this environment.

    Priority:
      1. apt          — Kali Linux (katana is in the official Kali repo)
      2. go install   — any distro that has Go on PATH
      3. Binary dl    — download prebuilt tarball/zip from GitHub releases

    Returns True if katana is usable after the attempt, False otherwise.
    On non-Linux systems, prints a hint and returns False immediately.
    """
    import json
    import os
    import platform
    import tarfile
    import tempfile
    import urllib.request
    import zipfile

    if platform.system() != "Linux":
        console.print(
            "  [dim]Katana not found. Install from projectdiscovery/katana "
            "(go install or apt on Kali).[/dim]"
        )
        return False

    distro  = _detect_distro()
    machine = platform.machine().lower()
    arch    = {"x86_64": "amd64", "aarch64": "arm64", "armv7l": "386"}.get(machine, machine)

    console.print(
        f"  [cyan]Katana not found — auto-installing "
        f"(distro=[bold]{distro or 'unknown'}[/bold], arch=[bold]{arch}[/bold])...[/cyan]"
    )
    log(f"  Katana not found — auto-install: distro={distro} arch={arch}", "info", logger)

    # ── Method 1: apt (Kali only — katana is in the Kali repo) ───────────────
    if distro == "kali" and shutil.which("apt"):
        console.print("  [cyan]→[/cyan] Trying: sudo apt install -y katana")
        try:
            proc = subprocess.run(
                ["sudo", "apt", "install", "-y", "katana"],
                capture_output=True, text=True, timeout=120,
            )
            if proc.returncode == 0 and shutil.which("katana"):
                console.print("  [bold green]✓ Installed via apt[/bold green]")
                log("  Katana installed via apt", "success", logger)
                return True
            log(f"  apt failed (rc={proc.returncode}): {proc.stderr[:300]}", "warning", logger)
        except Exception as e:
            log(f"  apt install error: {e}", "warning", logger)

    # ── Method 2: go install (any distro with Go on PATH) ────────────────────
    if shutil.which("go"):
        console.print("  [cyan]→[/cyan] Trying: go install katana@latest")
        try:
            gopath_proc = subprocess.run(
                ["go", "env", "GOPATH"],
                capture_output=True, text=True, timeout=10,
            )
            gopath = gopath_proc.stdout.strip() or os.path.expanduser("~/go")
            env = {**os.environ, "PATH": os.environ.get("PATH", "") + f":{gopath}/bin"}

            proc = subprocess.run(
                ["go", "install", "github.com/projectdiscovery/katana/cmd/katana@latest"],
                capture_output=True, text=True, timeout=180, env=env,
            )
            if proc.returncode == 0:
                os.environ["PATH"] = env["PATH"]
                if shutil.which("katana"):
                    console.print("  [bold green]✓ Installed via go install[/bold green]")
                    log("  Katana installed via go install", "success", logger)
                    return True
            log(f"  go install failed (rc={proc.returncode}): {proc.stderr[:300]}", "warning", logger)
        except Exception as e:
            log(f"  go install error: {e}", "warning", logger)

    # ── Method 3: prebuilt binary from GitHub releases ────────────────────────
    console.print("  [cyan]→[/cyan] Trying: download prebuilt binary from GitHub releases")
    try:
        api_url = "https://api.github.com/repos/projectdiscovery/katana/releases/latest"
        req = urllib.request.Request(api_url, headers={"User-Agent": "botstrike-installer/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            release = json.loads(resp.read())

        # Prefer zip, fall back to tar.gz
        asset_url  = None
        asset_name = None
        for ext in ("zip", "tar.gz"):
            candidate = f"katana_linux_{arch}.{ext}"
            for asset in release.get("assets", []):
                if asset["name"] == candidate:
                    asset_url  = asset["browser_download_url"]
                    asset_name = asset["name"]
                    break
            if asset_url:
                break

        if not asset_url:
            raise ValueError(f"No prebuilt binary for linux_{arch} in latest release")

        install_dir = Path(os.path.expanduser("~/.local/bin"))
        install_dir.mkdir(parents=True, exist_ok=True)

        console.print(f"  [cyan]  Downloading {asset_name}...[/cyan]", end="", flush=True)
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir) / asset_name
            urllib.request.urlretrieve(asset_url, str(tmp_path))

            if asset_name.endswith(".zip"):
                with zipfile.ZipFile(tmp_path) as zf:
                    zf.extractall(tmpdir)
            else:
                with tarfile.open(tmp_path, "r:gz") as tf:
                    tf.extractall(tmpdir)

            binary = Path(tmpdir) / "katana"
            if not binary.exists():
                raise FileNotFoundError("katana binary not found in archive")

            import shutil as _sh
            dest = install_dir / "katana"
            _sh.copy2(str(binary), str(dest))
            dest.chmod(0o755)

        # Expose ~/.local/bin in this process's PATH
        local_bin = str(install_dir)
        if local_bin not in os.environ.get("PATH", ""):
            os.environ["PATH"] = os.environ.get("PATH", "") + f":{local_bin}"

        if shutil.which("katana"):
            console.print(f" [bold green]✓ Installed to {dest}[/bold green]")
            log(f"  Katana installed via binary download → {dest}", "success", logger)
            return True

        raise RuntimeError("Binary placed but still not found on PATH")

    except Exception as e:
        log(f"  Binary download failed: {e}", "warning", logger)

    console.print("  [yellow]Could not auto-install Katana — skipping.[/yellow]")
    console.print(
        "  [dim]Manual install: sudo apt install katana  (Kali)  "
        "| go install github.com/projectdiscovery/katana/cmd/katana@latest[/dim]"
    )
    log("  Katana auto-install exhausted all methods — skipping", "warning", logger)
    return False


def _run_katana(target_url: str, base_host: str,
                logger: Optional[logging.Logger] = None) -> list[str]:
    """
    Ensure katana is installed, then run it and return discovered URLs
    filtered to the same domain.

    Flags:
      -d 3     crawl 3 levels deep
      -jc      parse JS files for additional endpoints
      -ps      passive mode — Wayback Machine + CommonCrawl
      -silent  URL-per-line stdout output
      -timeout 10  per-request timeout (seconds)
    """
    if not shutil.which("katana"):
        if not _install_katana(logger):
            return []

    log("[RECON] Katana — running headless JS crawl + passive sources...", "info", logger)
    console.print("  [bold cyan][katana][/bold cyan] Crawling (JS + passive)...", end="", flush=True)

    try:
        proc = subprocess.run(
            ["katana", "-u", target_url, "-d", "3", "-jc", "-ps", "-silent", "-timeout", "10"],
            capture_output=True, text=True, timeout=_KATANA_TIMEOUT,
        )
        urls: list[str] = []
        for line in proc.stdout.splitlines():
            line = line.strip()
            if line.startswith("http") and _is_internal(line, base_host) and not _is_static(line):
                urls.append(line)
        console.print(f" [bold green]{len(urls)} URLs[/bold green]")
        log(f"  Katana → {len(urls)} URLs discovered", "success", logger)
        return urls

    except subprocess.TimeoutExpired:
        console.print(f" [yellow]timed out after {_KATANA_TIMEOUT}s[/yellow]")
        log(f"  Katana timed out after {_KATANA_TIMEOUT}s", "warning", logger)
        return []
    except FileNotFoundError:
        return []
    except Exception as e:
        console.print(f" [dim]error: {e}[/dim]")
        log(f"  Katana error: {e}", "warning", logger)
        return []


# ── Main recon runner ─────────────────────────────────────────────────────────

def run(target_url: str, timeout: int = 10, logger: Optional[logging.Logger] = None) -> dict:
    result: dict = {
        "robots_txt_content":    "",
        "disallowed_paths":      [],
        "allowed_paths":         [],
        "sitemap_urls":          [],
        "crawled_urls":          [],
        "katana_urls":           0,
        "js_paths_extracted":    0,
        "guessed_paths_probed":  0,
        "guessed_paths_live":    0,
        "fuzzed_paths_probed":   0,
        "fuzzed_paths_live":     0,
        "url_categories":        {},
        "all_discovered_urls":   [],
        "classified_flows":      {},
    }

    parsed_base = urlparse(target_url)
    base_host   = parsed_base.hostname or ""
    proxies     = get_proxy_dict()
    session     = requests.Session()
    session.headers.update(stealth_headers())
    if proxies:
        session.proxies.update(proxies)

    discovered: set[str] = set()
    all_js_urls: set[str] = set()

    # ── 0. Katana (optional — enriches with headless JS + passive sources) ────
    katana_urls = _run_katana(target_url, base_host, logger)
    if katana_urls:
        discovered.update(katana_urls)
        result["katana_urls"] = len(katana_urls)

    # ── 1. robots.txt ─────────────────────────────────────────────────────────
    log("[RECON] Fetching robots.txt...", "info", logger)
    try:
        r = session.get(target_url.rstrip("/") + "/robots.txt", timeout=timeout)
        if r.status_code == 200:
            result["robots_txt_content"] = r.text
            for line in r.text.splitlines():
                line = line.strip()
                if line.lower().startswith("disallow:"):
                    p = line[9:].strip()
                    if p:
                        result["disallowed_paths"].append(p)
                elif line.lower().startswith("allow:"):
                    p = line[6:].strip()
                    if p:
                        result["allowed_paths"].append(p)
            log(f"  robots.txt → {len(result['disallowed_paths'])} disallowed, "
                f"{len(result['allowed_paths'])} allowed", "success", logger)
        else:
            log(f"  robots.txt → HTTP {r.status_code}", "warning", logger)
    except Exception as e:
        log(f"  robots.txt error: {e}", "warning", logger)

    # ── 2. sitemap.xml ────────────────────────────────────────────────────────
    log("[RECON] Fetching sitemap.xml...", "info", logger)
    try:
        r = session.get(target_url.rstrip("/") + "/sitemap.xml", timeout=timeout)
        if r.status_code == 200:
            ct = r.headers.get("Content-Type", "")
            soup = BeautifulSoup(r.text, "lxml-xml" if "xml" in ct else "lxml")
            locs = [loc.text.strip() for loc in soup.find_all("loc")]
            result["sitemap_urls"] = locs
            discovered.update(locs)
            log(f"  sitemap.xml → {len(locs)} URLs", "success", logger)
        else:
            log(f"  sitemap.xml → HTTP {r.status_code}", "warning", logger)
    except Exception as e:
        log(f"  sitemap.xml error: {e}", "warning", logger)

    # ── 3. Deep HTML extraction (homepage) ────────────────────────────────────
    log("[RECON] Crawling homepage (deep HTML extraction)...", "info", logger)
    try:
        r = session.get(target_url, timeout=timeout)
        if r.status_code == 200:
            page_urls, js_urls, inline_paths = _extract_from_html(r.text, target_url, base_host)
            result["crawled_urls"] = page_urls
            discovered.update(page_urls)
            all_js_urls.update(js_urls)
            result["inline_js_paths"] = len(inline_paths)
            # Probe inline-script paths to confirm they exist
            if inline_paths:
                inline_probed = _probe_paths(target_url, list(inline_paths), _PROBE_TIMEOUT, logger)
                discovered.update(e["url"] for e in inline_probed)
            log(f"  Homepage → {len(page_urls)} URLs, {len(js_urls)} JS files, {len(inline_paths)} inline paths", "success", logger)
    except Exception as e:
        log(f"  Homepage crawl error: {e}", "warning", logger)

    discovered.add(target_url)

    # ── 4. JavaScript parsing ─────────────────────────────────────────────────
    if all_js_urls:
        log(f"[RECON] Parsing {len(all_js_urls)} JS files for hidden endpoints...", "info", logger)
        console.print(f"  [cyan]Parsing {len(all_js_urls)} JS files...[/cyan]", end="")
        raw_js_paths = _fetch_js_files(list(all_js_urls), session, timeout, target_url, logger)
        result["js_paths_extracted"] = len(raw_js_paths)

        # Probe JS-extracted paths to check which actually exist
        if raw_js_paths:
            js_probed = _probe_paths(target_url, raw_js_paths, _PROBE_TIMEOUT, "JS paths", logger)
            js_live = [e["url"] for e in js_probed]
            discovered.update(js_live)
            console.print(f" [bold green]{len(js_live)} live[/bold green] / {len(raw_js_paths)} extracted")
            log(f"  JS paths — {len(js_live)} live from {len(raw_js_paths)} extracted", "success", logger)
        else:
            console.print(" [dim]none found[/dim]")
    else:
        log("[RECON] No JS files found to parse.", "info", logger)

    # ── 5. Wordlist path probing ───────────────────────────────────────────────
    guess_paths = _load_guess_paths()
    if guess_paths:
        log(f"[RECON] Probing {len(guess_paths)} wordlist paths ({_PROBE_THREADS} threads)...", "info", logger)
        console.print(f"  [cyan]Probing {len(guess_paths)} wordlist paths...[/cyan]", end="")
        probed = _probe_paths(target_url, guess_paths, _PROBE_TIMEOUT, "wordlist", logger)
        live_guessed = [e["url"] for e in probed]
        discovered.update(live_guessed)
        result["guessed_paths_probed"] = len(guess_paths)
        result["guessed_paths_live"]   = len(live_guessed)
        console.print(f" [bold green]{len(live_guessed)} live[/bold green] / {len(guess_paths)} probed")
        log(f"  Wordlist — {len(live_guessed)} live / {len(guess_paths)} probed", "success", logger)

    # ── 6. Fuzzing discovered API paths ───────────────────────────────────────
    all_paths_so_far = [urlparse(u).path for u in discovered]
    fuzz_candidates  = _fuzz_paths(all_paths_so_far)
    if fuzz_candidates:
        log(f"[RECON] Fuzzing {len(fuzz_candidates)} path variations...", "info", logger)
        console.print(f"  [cyan]Fuzzing {len(fuzz_candidates)} path variations...[/cyan]", end="")
        fuzz_probed = _probe_paths(target_url, fuzz_candidates, _PROBE_TIMEOUT, "fuzz", logger)
        fuzz_live   = [e["url"] for e in fuzz_probed]
        discovered.update(fuzz_live)
        result["fuzzed_paths_probed"] = len(fuzz_candidates)
        result["fuzzed_paths_live"]   = len(fuzz_live)
        console.print(f" [bold green]{len(fuzz_live)} live[/bold green] / {len(fuzz_candidates)} fuzzed")
        log(f"  Fuzzing — {len(fuzz_live)} live / {len(fuzz_candidates)} tried", "success", logger)

    # ── 7. Finalise ───────────────────────────────────────────────────────────
    result["all_discovered_urls"] = list(discovered)

    categorized: dict[str, list] = defaultdict(list)
    for url in result["all_discovered_urls"]:
        cat = _categorize(url)
        categorized[cat].append(url)
    result["url_categories"] = dict(categorized)
    result["classified_flows"] = classify_flows(result["all_discovered_urls"])

    _print_recon_summary(result)
    return result


# ── Summary table ─────────────────────────────────────────────────────────────

def _print_recon_summary(r: dict) -> None:
    table = Table(title="Recon Summary", show_header=True, header_style="bold cyan")
    table.add_column("Source",  style="bold white", width=32)
    table.add_column("Count",   justify="right")

    if r.get("katana_urls"):
        table.add_row("[bold cyan]Katana (JS + passive)[/bold cyan]", f"[bold cyan]{r['katana_urls']}[/bold cyan]")
    table.add_row("robots.txt disallowed",    str(len(r["disallowed_paths"])))
    table.add_row("sitemap.xml URLs",         str(len(r["sitemap_urls"])))
    table.add_row("Homepage links (deep HTML)", str(len(r["crawled_urls"])))
    if r.get("inline_js_paths"):
        table.add_row("Inline script paths", str(r["inline_js_paths"]))
    table.add_row("JS files → live endpoints", str(r.get("js_paths_extracted", 0)))

    live_g = r.get("guessed_paths_live", 0)
    tot_g  = r.get("guessed_paths_probed", 0)
    if tot_g:
        table.add_row(f"Wordlist paths (live/{tot_g})", str(live_g))

    live_f = r.get("fuzzed_paths_live", 0)
    tot_f  = r.get("fuzzed_paths_probed", 0)
    if tot_f:
        table.add_row(f"Fuzzed paths (live/{tot_f})", str(live_f))

    table.add_row("[bold]Total unique URLs[/bold]", f"[bold]{len(r['all_discovered_urls'])}[/bold]")

    cats = r.get("url_categories", {})
    if cats:
        table.add_row("", "")
        for cat, urls in cats.items():
            table.add_row(f"  → {cat}", str(len(urls)))

    flows = r.get("classified_flows", {})
    if flows:
        table.add_row("", "")
        table.add_row("[bold cyan]Attack Flows Identified[/bold cyan]", "")
        for flow, urls in flows.items():
            table.add_row(f"  ★ {flow}", str(len(urls)))

    console.print(table)
    console.print()
