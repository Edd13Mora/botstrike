# BotStrike v1.0

**Bot Protection Effectiveness Tester**

BotStrike is a modular, command-line tool built for security consultants running bot-protection comparison engagements — primarily **DataDome vs CrowdSec** side-by-side assessments. It simulates the full spectrum of bot behavior against a target web application: from patient, human-like scrapers to aggressive HTTP floods. Results are scored, graded A–F, and delivered as a standalone dark-themed HTML dashboard and a machine-readable JSON report.

> **Authorized use only.** BotStrike is for security professionals testing systems they own or have explicit written permission to test. The `--confirm-authorized` flag is a binding declaration of that authorization. Unauthorized use is illegal.

---

## Table of Contents

- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Profile Presets](#profile-presets)
- [Test Modules](#test-modules)
  - [Module 0 — Pre-Flight Fingerprinting](#module-0--pre-flight-fingerprinting)
  - [Module 1 — Passive Recon](#module-1--passive-recon)
  - [Module 2A — Stealth Scraping](#module-2a--stealth-scraping)
  - [Module 2B — Aggressive Scraping](#module-2b--aggressive-scraping)
  - [Module 3 — Application-Layer Bot Flood](#module-3--application-layer-bot-flood)
- [Protection Scoring](#protection-scoring)
- [Recommendations Engine](#recommendations-engine)
- [Reporting](#reporting)
- [Compare Mode](#compare-mode)
- [Proxy Support](#proxy-support)
- [Config File](#config-file)
- [Project Structure](#project-structure)
- [Dependencies](#dependencies)
- [Legal Notice](#legal-notice)

---

## How It Works

BotStrike runs four sequential phases against a single target URL (or two targets in compare mode):

```
Phase 0 · Pre-Flight      DNS check → WAF fingerprint → 8 probe requests
Phase 1 · Recon           robots.txt + sitemap.xml crawl → URL discovery
Phase 2 · Scraping        Stealth mode (human-like) → Aggressive mode (naked bots)
Phase 3 · Bot Flood       4 attack vectors with live metrics (requires --confirm-authorized)
           └─ HTTP Flood · Slowloris · POST Flood · Cache Buster
```

At the end, collected data flows through a **scoring engine** (0–100, grade A–F) and a **recommendations engine** (CRITICAL → LOW), then everything is rendered into HTML and JSON reports saved to `reports/<hostname>_<date>_<time>/`.

CTRL+C at any point triggers a **graceful interrupt**: partial data collected so far is immediately saved to a report before the process exits.

---

## Architecture

```
botstrike/
├── botstrike.py            Entry point — CLI parsing, orchestration, CTRL+C handler
├── config.yaml             Default configuration (overridden by CLI flags)
├── wordlists/
│   └── useragents.txt      200+ real browser UA strings (Chrome, Firefox, Safari, Edge, mobile)
├── modules/
│   ├── utils.py            Shared utilities: UA pool, stealth headers, response classifier, proxy
│   ├── preflight.py        WAF/CDN fingerprinting + 8 probe payloads
│   ├── recon.py            robots.txt + sitemap.xml parser + homepage link extractor
│   ├── scraper.py          Stealth and aggressive scraping + product data extraction
│   ├── ddos.py             4-vector bot flood engine with live Rich dashboard
│   └── reporter.py         Scoring, recommendations, JSON + HTML report generation
└── templates/
    ├── report.html.j2      Per-target HTML report (dark theme, Chart.js)
    └── comparison.html.j2  Side-by-side comparison report
```

**Data flow:**

```
botstrike.py
    │
    ├─ run_one_target(url, args, cfg)
    │       │
    │       ├─ preflight.run()     → preflight_data dict
    │       ├─ recon.run()         → recon_data dict + all_discovered_urls
    │       ├─ scraper.run_stealth()   → scraping_data["stealth"]
    │       ├─ scraper.run_aggressive() → scraping_data["aggressive"]
    │       ├─ ddos.run()          → ddos_data dict (4 vector results)
    │       │
    │       ├─ reporter.calculate_protection_score()
    │       ├─ reporter.generate_recommendations()
    │       ├─ reporter.load_previous_report()   (historical delta)
    │       ├─ reporter.compute_deltas()
    │       ├─ reporter.build_json_report()
    │       └─ reporter.build_html_report()
    │
    └─ [compare mode] reporter.build_comparison_html(result_a, result_b)
```

---

## Installation

**Requirements:** Python ≥ 3.9 — tested on Python 3.14.

```bash
git clone https://github.com/yourorg/botstrike.git
cd botstrike
pip install -r requirements.txt
```

BotStrike will also **auto-install** any missing dependency at runtime before the first import, printing a dependency status table on first run.

### Kali Linux (recommended platform)

```bash
sudo apt update && sudo apt install python3-pip -y
pip3 install -r requirements.txt
python3 botstrike.py --help
```

### Windows

```powershell
pip install -r requirements.txt
python botstrike.py --help
```

---

## Quick Start

```bash
# Scraping only — no authorization flag needed
python botstrike.py --url https://shop.example.com --mode scrape

# Full test with bot flood — requires written authorization
python botstrike.py --url https://shop.example.com --mode full --confirm-authorized

# Non-interactive full test (CI / scripted runs)
python botstrike.py --url https://shop.example.com \
    --mode full --confirm-authorized --yes \
    --operator "j.doe@company.com"

# DataDome vs CrowdSec side-by-side comparison
python botstrike.py --compare \
    --url-a https://site-with-datadome.com --label-a "DataDome" \
    --url-b https://site-with-crowdsec.com --label-b "CrowdSec" \
    --mode full --confirm-authorized
```

---

## CLI Reference

```
python botstrike.py [OPTIONS]
```

### target

| Flag | Type | Description |
|---|---|---|
| `--url URL` | string | Full target URL including scheme. Required unless using `--compare`. |

### test control

| Flag | Default | Description |
|---|---|---|
| `--mode MODE` | `full` | `scrape` — recon + scraping only. `ddos` — recon + bot flood only. `full` — all phases end-to-end. |
| `--confirm-authorized` | off | **Safety gate.** Required to unlock the bot flood module. Declares you hold written authorization from the target owner. Without this flag, `--mode ddos` exits and `--mode full` silently falls back to scrape-only. |
| `--yes` | off | Skip all interactive confirmation prompts. Useful for CI/CD pipelines and scripted engagements. |

### ddos tuning

| Flag | Default | Description |
|---|---|---|
| `--rps N` | `100` | Target requests-per-second for the HTTP Flood vector. Ramps from 0 to N over the first 30 seconds (configurable via `config.yaml`), then sustains. |
| `--duration SECONDS` | `60` | How long each bot flood vector runs. Applies equally to all 4 vectors. Use `30` for a quick check, `120+` for sustained pressure. |
| `--connections N` | `200` | Number of concurrent TCP connections for the Slowloris vector. Each holds its socket open by sending a partial header every 10 seconds. |

### output & metadata

| Flag | Default | Description |
|---|---|---|
| `--operator NAME` | `""` | Operator identifier embedded in the report (name or email). Appears in the JSON envelope, HTML footer, and log file for accountability. |
| `--config FILE` | `config.yaml` | Path to a YAML configuration file. CLI flags always take precedence over config file values. |

### behaviour presets

| Flag | Default | Description |
|---|---|---|
| `--profile PROFILE` | `medium` | Named configuration bundle: `light`, `medium`, `heavy`, or `stealth`. See [Profile Presets](#profile-presets) for exact values. |
| `--proxy URL` | none | Route all HTTP traffic through this proxy. Supports HTTP and SOCKS5. Applied to every module: preflight, recon, scraping, and bot flood. |

### compare mode

| Flag | Default | Description |
|---|---|---|
| `--compare` | off | Enable compare mode. Requires `--url-a` and `--url-b`. Generates individual reports per target plus a unified side-by-side comparison dashboard. |
| `--url-a URL` | — | First target URL (e.g. the DataDome-protected site). |
| `--url-b URL` | — | Second target URL (e.g. the CrowdSec-protected site). |
| `--label-a NAME` | `Target A` | Human-readable label for Target A in the comparison report. |
| `--label-b NAME` | `Target B` | Human-readable label for Target B in the comparison report. |

---

## Profile Presets

Presets are named configuration bundles. Any explicit CLI flag (`--rps`, `--duration`, `--connections`) overrides the preset value.

| Preset | Stealth threads | Stealth delay | Aggressive threads | Max pages | RPS | Duration | Slowloris |
|---|---|---|---|---|---|---|---|
| `light` | 2 | 2.5–6.0 s | 4 | 30 / 50 | 30 | 30 s | 50 |
| `medium` *(default)* | 3 | 1.5–4.0 s | 10 | 100 / 200 | 100 | 60 s | 200 |
| `heavy` | 5 | 1.0–2.5 s | 20 | 300 / 500 | 300 | 120 s | 500 |
| `stealth` | 1 | 5.0–12.0 s | 1 | 50 / 20 | 10 | 30 s | 20 |

- **light** — Quick reconnaissance pass. Minimal noise. Good for a first look.
- **medium** — Balanced defaults suitable for most engagements.
- **heavy** — Sustained pressure. Use when you need to confirm rate-limit thresholds or measure degradation under load.
- **stealth** — Maximum evasion. Single thread, long inter-request delays, minimal volume. Designed to mimic a patient human scraper and defeat behavioral detection that relies on velocity.

---

## Test Modules

### Module 0 — Pre-Flight Fingerprinting

**File:** `modules/preflight.py`

The pre-flight phase runs before anything else. It tells you what is protecting the target before BotStrike starts making noise.

**Steps:**

1. **DNS resolution** — Confirms the hostname resolves. Exits early if it does not.
2. **Liveness check** — Sends a HEAD request with stealth headers to confirm the target responds.
3. **CDN detection** — Inspects response headers against signatures for 7 CDN providers.
4. **Tech stack detection** — Reads `Server`, `X-Powered-By`, and `X-Generator` headers.
5. **HTTPS / HSTS check** — Confirms scheme and checks for `Strict-Transport-Security`.
6. **Rate-limit header detection** — Looks for `X-RateLimit-Limit`, `Retry-After`, `RateLimit-Reset`.
7. **robots.txt / sitemap.xml** — Checks existence (200 OK) of both files.
8. **8 WAF probe requests** — Sends crafted requests that any WAF should react to.

**WAF probes:**

| Probe | Technique | What it tests |
|---|---|---|
| SQLi Probe | `?id=1' OR '1'='1` | Query string injection — triggers rule-based WAFs |
| XSS UA Probe | `User-Agent: <script>alert(1)</script>` | Header inspection depth |
| Path Traversal | `/../../../etc/passwd` | Directory traversal signature |
| XFF Spoof | `X-Forwarded-For: 127.0.0.1` | Localhost IP bypass via proxy header |
| Empty User-Agent | `User-Agent: (empty)` | Strong bot signal for DataDome and CrowdSec |
| Known Bot UA | `User-Agent: python-requests/2.31.0` | Most basic bot tell — both DD and CS block this |
| Scanner UA | `User-Agent: Nikto/2.1.6` on `/wp-admin/` | Security scanner UA + admin path double trigger |
| Header Injection | `X-Custom-IP-Authorization: 127.0.0.1` | Internal IP bypass via custom header |

**WAF detection covers 13 vendors:**

DataDome · CrowdSec · Cloudflare · PerimeterX · Akamai Bot Manager · AWS WAF · Imperva/Incapsula · F5 BIG-IP ASM · ModSecurity · Sucuri · Radware AppWall · Reblaze · Barracuda WAF

Detection uses three signal sources combined across all probe responses:
- **Response headers** — vendor-specific header names (e.g. `x-datadome`, `cf-ray`, `x-px-block-score`)
- **Response body keywords** — text patterns in block pages (e.g. `datadome.co`, `cloudflare`, `incapsula`)
- **Set-Cookie headers** — vendor cookies (e.g. `datadome`, `__cf_bm`, `incap_ses`, `_px`)

**Blocking mode detection:** If any probe returns a `403`, `406`, `429`, or `503`, the WAF is flagged as `ACTIVE`. Otherwise it is flagged `PASSIVE (detection-only)` — a critical finding because the WAF is watching but not stopping anything.

---

### Module 1 — Passive Recon

**File:** `modules/recon.py`

Discovers URLs to feed into the scraping and bot flood phases.

- Fetches and parses `robots.txt` to extract `Allow` and `Disallow` paths.
- Fetches and parses `sitemap.xml` (and nested sitemaps) to extract all `<loc>` URLs.
- Crawls the homepage and extracts all `<a href>` links.
- Deduplicates, normalizes, and filters all discovered URLs to the same hostname.
- Returns `all_discovered_urls` — the master URL list passed to scraping and bot flood.

---

### Module 2A — Stealth Scraping

**File:** `modules/scraper.py` → `run_stealth()`

Simulates a patient, human-like bot. This is the hardest bot type for behavioral detection to catch because it mimics legitimate browsing patterns.

**Evasion techniques:**

- **User-Agent rotation** — randomly selects from 200+ real browser UA strings (Chrome, Firefox, Safari, Edge on Windows/Mac/Linux, plus iOS and Android mobile UAs).
- **`Sec-CH-UA` fingerprint consistency** — if a Chrome or Edge UA is selected, the matching `Sec-CH-UA`, `Sec-CH-UA-Mobile`, and `Sec-CH-UA-Platform` headers are injected. Firefox and Safari intentionally omit these headers (matching real browser behavior). A Chrome 124 UA without a matching `sec-ch-ua` is a strong bot signal to DataDome.
- **Realistic header set** — includes `Accept`, `Accept-Language`, `Accept-Encoding`, `Referer` (from a pool of search engine URLs), `DNT`, `Upgrade-Insecure-Requests`.
- **Randomized header order** — modern bot detectors fingerprint the order of request headers in addition to their values.
- **Random inter-request delay** — configurable `delay_min` to `delay_max` seconds (default 1.5–4.0 s).
- **Session persistence** — uses a `requests.Session` with cookie jar so session cookies from page 1 are sent on page 2.
- **Throttled thread pool** — defaults to 3 concurrent threads so the request pattern looks more like 3 tabs open rather than a flood.

**Product data extraction:** For every 200 OK HTML response, the scraper attempts to extract structured product data using CSS selectors:
- Name: `h1`, `[itemprop=name]`, `[class*=product-title]`
- Price: `[itemprop=price]`, `[class*=price]`, `.price`
- Description: `[itemprop=description]`, `[class*=description]`
- Images: `<img>` with `src` containing "product", "item", or "catalog"

Extracted items appear in the report to demonstrate what a scraper actually harvests. XML documents (sitemaps, feeds) are automatically excluded from product extraction.

**Result dict includes:** `total_requests`, `blocked_pct`, `items_extracted`, `pages_crawled`, `duration_s`, `responses` (code breakdown), `sample_items` (up to 20 extracted products), `raw_results`.

---

### Module 2B — Aggressive Scraping

**File:** `modules/scraper.py` → `run_aggressive()`

Simulates an unsophisticated bot — the kind a script kiddie or a naive API consumer would write. No delays, no session, no realistic headers. Any WAF worth deploying should block these immediately.

- **No inter-request delays** — fires as fast as the thread pool allows.
- **No session** — fresh connection each request, no cookies.
- **Minimal headers** — just a rotating UA from the pool; no `Accept-Language`, no `Referer`, no `Sec-CH-UA`.
- **Path guessing** — appends a list of common API and content paths to the discovered URL list:
  `/api/products`, `/api/catalog`, `/api/prices`, `/api/items`, `/api/v1/products`, `/api/v2/catalog`, `/search?q=*`, `/search?query=test`, `/products`, `/catalog`, `/shop`, `/store`
- **Higher thread count** — defaults to 10 concurrent threads.

If `aggressive_blocked_pct` is low (below 50%), it means the WAF is not blocking even the most obvious bot signatures, which scores as a HIGH severity finding.

---

### Module 3 — Application-Layer Bot Flood

**File:** `modules/ddos.py`

**Requires:** `--confirm-authorized`

Runs 4 distinct attack vectors sequentially, with a configurable pause between each. A live Rich terminal dashboard updates every 500ms showing real-time RPS, latency percentiles, and response code breakdown.

> **Scope note:** These vectors simulate single-source, application-layer (L7) bot floods from one IP address. They measure per-IP rate limiting effectiveness, detection latency, and application resilience under load. They are **not** representative of volumetric distributed DDoS (L3/L4 from a botnet). For client-facing reports, this module is accurately described as "Application-Layer Bot Flood Stress Test."

#### Vector 1 — HTTP Flood

High-volume GET flood with a ramp-up phase. Worker threads are distributed across target URL, product URLs, and search URLs discovered during recon. Each worker applies a linear ramp from 0 to the target RPS over `ramp_up_seconds` to avoid an instant spike that would look nothing like real attack patterns.

#### Vector 2 — Slowloris

Opens many simultaneous TCP connections (default 200) and sends a partial HTTP request on each — just enough headers to keep the server's socket open, but never completing the request. Every 10 seconds each connection sends another junk header to reset the server's idle timeout. The goal is to exhaust the server's connection pool without sending much data. SSL/TLS is handled transparently (`ssl.create_default_context()`).

#### Vector 3 — POST Flood

Sends random POST payloads (128–4096 bytes of random ASCII) to form submission endpoints: `/checkout`, `/cart`, `/search`, `/login`, `/account`, and any equivalents discovered in recon. Targets state-creating endpoints that are typically more expensive for the server to process than GET requests.

#### Vector 4 — Cache Buster

Appends unique query strings (`cb=<uuid>&ts=<millisecond-timestamp>`) to every request, preventing CDN and reverse proxy caches from serving cached responses. Forces every request to hit the origin server. Targets all discovered URLs simultaneously.

**Per-vector metrics collected:**

| Metric | Description |
|---|---|
| `total_requests` | Total HTTP requests sent |
| `rps_avg` | Average requests per second (from 1-second sampling windows) |
| `rps_peak` | Highest 1-second RPS observed |
| `latency_avg_ms` | Mean response latency |
| `latency_p50_ms` | Median latency |
| `latency_p95_ms` | 95th percentile latency |
| `latency_p99_ms` | 99th percentile latency |
| `latency_peak_ms` | Worst single response latency |
| `blocked_pct` | % of responses that were 403, 429, or 503 |
| `responses` | Full code breakdown: 200 / 403 / 429 / 503 / error |

---

## Protection Scoring

**File:** `modules/reporter.py` → `calculate_protection_score()`

Every engagement produces a single 0–100 numeric score and an A–F letter grade. The score starts at 100 and deductions are applied per finding.

| Finding | Deduction | Severity |
|---|---|---|
| No WAF detected | −35 | CRITICAL |
| WAF in passive/detection-only mode | −20 | HIGH |
| Stealth scraping < 20% blocked | −20 | HIGH |
| Stealth scraping 20–49% blocked | −10 | MEDIUM |
| Aggressive bots < 50% blocked | −15 | HIGH |
| Aggressive bots 50–79% blocked | −5 | LOW |
| Each bot flood vector < 30% blocked | −5 | MEDIUM |
| No CDN detected | −5 | LOW |
| HSTS header missing | −5 | LOW |

**Grade bands:**

| Grade | Score |
|---|---|
| A | ≥ 90 |
| B | ≥ 80 |
| C | ≥ 65 |
| D | ≥ 50 |
| F | < 50 |

---

## Recommendations Engine

**File:** `modules/reporter.py` → `generate_recommendations()`

Generates prioritized, actionable remediation recommendations. All recommendations are context-aware for DataDome and CrowdSec deployments. Each recommendation includes a `priority` (CRITICAL / HIGH / MEDIUM / LOW), a `title`, and a detailed `description` with product-specific guidance.

**Examples:**

- *CRITICAL* — "Deploy a Bot Management Solution" — recommends DataDome (JS tag + server-side module) or CrowdSec (community blocklists + bouncer) with rationale.
- *CRITICAL* — "Switch DataDome from Detection-Only to Blocking Mode" — flags that the WAF is logging but not stopping requests.
- *HIGH* — "Improve Human-Like Bot Detection" — DataDome: enable device fingerprinting + JS challenge. CrowdSec: add appsec-collection behavioral scenarios.
- *HIGH* — "Tighten Obvious Bot Detection Rules" — notes that `python-requests/2.31.0` UA should be blocked by default; references `http-bad-user-agents` scenario for CrowdSec.
- *MEDIUM* — "Strengthen Rate Limiting — Http Flood" — references rate-limiting policy dashboard (DataDome) and `http-crawl-non_statics` / `http-flood` scenarios (CrowdSec).
- *MEDIUM* — "Add a CDN Layer for DDoS Absorption" — notes DataDome and CrowdSec both offer edge modules for Cloudflare, Akamai, Fastly.
- *LOW* — "Enable HSTS" — includes the exact header value and compliance framework references (PCI-DSS, GDPR).

Recommendations are sorted CRITICAL → HIGH → MEDIUM → LOW and rendered as priority-colored cards in the HTML report.

---

## Reporting

**Files:** `modules/reporter.py`, `templates/report.html.j2`, `templates/comparison.html.j2`

All reports are written to `reports/<hostname>_<YYYYMMDD>_<HHMMSS>/`.

### JSON Report

`botstrike_<sessionid>.json` — Machine-readable full output. Top-level structure:

```json
{
  "session":         { "id", "target", "label", "operator", "tool_version", "start_time", "end_time", "mode", "authorized", "interrupted" },
  "preflight":       { "waf_detected", "waf_match_reason", "waf_notes", "blocking_mode", "cdn_detected", "tech_stack", "hsts", "probe_results", ... },
  "recon":           { "robots_allowed", "robots_disallowed", "sitemap_urls", "homepage_links", "all_discovered_urls" },
  "scraping": {
    "stealth":       { "total_requests", "blocked_pct", "items_extracted", "sample_items", "responses", "raw_results", ... },
    "aggressive":    { ... }
  },
  "ddos": {
    "http_flood":    { "vector", "total_requests", "rps_avg", "rps_peak", "latency_p50_ms", "latency_p95_ms", "latency_p99_ms", "blocked_pct", "responses" },
    "slowloris":     { ... },
    "post_flood":    { ... },
    "cache_buster":  { ... }
  },
  "score":           { "score", "grade", "findings" },
  "recommendations": [ { "priority", "title", "detail" }, ... ],
  "deltas":          { "stealth_blocked_pct_delta", "aggressive_blocked_pct_delta", "score_delta" }
}
```

### HTML Report

`botstrike_<sessionid>.html` — Standalone dark-themed dashboard. Self-contained (no external dependencies at render time, CDN links embedded). Sections:

- **Protection Score hero** — grade circle, numeric score, deduction summary pills
- **Historical delta indicators** — ▲/▼ vs. the previous run on the same hostname
- **Pre-flight fingerprint** — WAF vendor, blocking mode, CDN, tech stack, HSTS, probe results table with block type column
- **Recommendations** — priority-colored cards (red/orange/yellow/blue)
- **Scraping results** — donut chart (response code breakdown), items extracted, sample products table, block type breakdown (HARD_BLOCK / CAPTCHA_CHALLENGE / RATE_LIMIT / SOFT_REDIRECT / PASSED)
- **Bot flood results** — per-vector cards with RPS, latency percentiles (p50/p95/p99), stacked area chart over time
- **Raw log** — full request-level detail

### Log File

`botstrike_<sessionid>.log` — Timestamped plain-text log of all operations for audit trail.

### Historical Deltas

Before writing the report, BotStrike scans the `reports/` directory for previous JSON reports with the same hostname. If found, it computes:

- `stealth_blocked_pct_delta` — improvement or regression in stealth bot detection
- `aggressive_blocked_pct_delta` — improvement or regression in obvious bot detection
- `score_delta` — overall protection score change

Deltas are displayed as ▲ (improvement) or ▼ (regression) on the KPI cards in the HTML report.

---

## Compare Mode

Compare mode runs the full pipeline against two targets and generates three reports:

1. **Individual report for Target A** (e.g. DataDome site)
2. **Individual report for Target B** (e.g. CrowdSec site)
3. **Unified comparison dashboard** (`comparison.html`) in `reports/compare_<timestamp>/`

The comparison dashboard shows:
- **Winner verdict** — automatically determined by score difference
- **Side-by-side KPI grid** — score, grade, WAF vendor, blocking mode, CDN, HSTS, stealth blocked%, aggressive blocked%, items extracted
- **▲/▼ winner indicators** per metric
- **Scraping bar charts** — blocked% and items extracted for A vs B
- **Bot flood charts** — blocked% and average latency by vector for A vs B
- **Recommendations** — side-by-side, A on the left (blue), B on the right (green)

```bash
python botstrike.py --compare \
    --url-a https://datadome-site.com  --label-a "DataDome" \
    --url-b https://crowdsec-site.com  --label-b "CrowdSec" \
    --mode full --confirm-authorized --yes \
    --operator "consultant@company.com"
```

All flags (`--mode`, `--profile`, `--rps`, `--duration`, `--proxy`) apply equally to both targets.

---

## Proxy Support

All modules (preflight, recon, scraping, bot flood) honor a single global proxy:

```bash
# HTTP proxy
python botstrike.py --url https://shop.example.com --proxy http://proxyhost:8080

# SOCKS5 / Tor
python botstrike.py --url https://shop.example.com --proxy socks5://127.0.0.1:9050
```

The proxy is set once at startup via `modules/utils.set_proxy()` and retrieved by every module via `get_proxy_dict()` which returns `{"http": url, "https": url}` for injection into `requests` and `requests.Session`.

---

## Config File

`config.yaml` provides defaults for all settings. CLI flags always override config file values.

```yaml
scraping:
  stealth:
    threads: 3
    delay_min: 1.5
    delay_max: 4.0
    max_pages: 100
  aggressive:
    threads: 10
    max_pages: 200

ddos:
  rps: 100
  duration: 60
  connections: 200        # slowloris concurrent connections
  ramp_up_seconds: 30
  pause_between_vectors: 10

preflight:
  timeout: 10

logging:
  level: "INFO"           # DEBUG | INFO | WARNING
```

Pass a custom config with `--config /path/to/my_config.yaml`.

**Precedence:** CLI flags > config file > profile preset > built-in defaults.

---

## Project Structure

```
botstrike/
├── botstrike.py              Main entry point
├── config.yaml               Default configuration
├── requirements.txt          Python dependencies
├── README.md
├── wordlists/
│   └── useragents.txt        200+ browser User-Agent strings
├── modules/
│   ├── __init__.py
│   ├── utils.py              Console, logging, UA pool, stealth headers, proxy, response classifier
│   ├── preflight.py          WAF/CDN fingerprinting + 8 probe requests
│   ├── recon.py              robots.txt + sitemap.xml + homepage link extraction
│   ├── scraper.py            Stealth + aggressive scraping, product extraction
│   ├── ddos.py               4-vector bot flood, _Stats class, live dashboard
│   └── reporter.py           Scoring, recommendations, JSON + HTML + comparison reports
├── templates/
│   ├── report.html.j2        Per-target HTML report (Jinja2)
│   └── comparison.html.j2    Side-by-side comparison report (Jinja2)
└── reports/                  Auto-created; contains all report output
    └── <hostname>_<date>_<time>/
        ├── botstrike_<sessionid>.json
        ├── botstrike_<sessionid>.html
        └── botstrike_<sessionid>.log
```

---

## Dependencies

| Package | Purpose |
|---|---|
| `requests` | All HTTP requests (preflight, recon, scraping, flood) |
| `rich` | Terminal UI — colored output, live dashboards, progress bars, tables |
| `beautifulsoup4` | HTML/XML parsing for recon and product extraction |
| `lxml` | Fast HTML parser backend for BeautifulSoup |
| `pyyaml` | YAML config file parsing |
| `aiohttp` | Async HTTP (used in high-concurrency flood paths) |
| `fake-useragent` | Fallback UA pool if `wordlists/useragents.txt` is absent |
| `jinja2` | HTML report templating |
| `urllib3` | Lower-level HTTP utilities |

All dependencies are auto-installed at first run if missing.

---

## Legal Notice

BotStrike is built for **authorized security testing only**.

- Use only against systems you **own** or have **explicit written authorization** to test.
- The `--confirm-authorized` flag is a legally binding declaration of authorization.
- Unauthorized use of this tool against third-party systems may violate computer crime laws in your jurisdiction (e.g. CFAA in the US, Computer Misuse Act in the UK, LCEN in France).
- The authors accept no liability for unauthorized or illegal use.

This tool is designed for professional engagements: security consultants comparing bot-protection vendors (DataDome, CrowdSec, Cloudflare, etc.) on behalf of clients who have commissioned the assessment.
