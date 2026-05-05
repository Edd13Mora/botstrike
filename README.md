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
- [Distributed Mode](#distributed-mode)
  - [How Distributed Mode Works](#how-distributed-mode-works)
  - [Prerequisites](#prerequisites)
  - [Step 1 — Generate a Dedicated SSH Key](#step-1--generate-a-dedicated-ssh-key)
  - [Step 2 — Authorize the Key on Every VPS](#step-2--authorize-the-key-on-every-vps)
  - [Step 3 — Create nodes.yaml](#step-3--create-nodesyaml)
  - [Step 4 — Bootstrap the Fleet](#step-4--bootstrap-the-fleet)
  - [Step 5 — Run a Distributed Test](#step-5--run-a-distributed-test)
  - [Live Fleet Dashboard](#live-fleet-dashboard)
  - [Distributed Output Structure](#distributed-output-structure)
  - [Merged Report Format](#merged-report-format)
  - [Distributed CLI Reference](#distributed-cli-reference)
  - [Security Model](#security-model)
  - [Troubleshooting](#troubleshooting)
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
├── nodes.yaml.example      Fleet config template for distributed mode
├── wordlists/
│   └── useragents.txt      200+ real browser UA strings (Chrome, Firefox, Safari, Edge, mobile)
├── modules/
│   ├── utils.py            Shared utilities: UA pool, stealth headers, response classifier, proxy
│   ├── preflight.py        WAF/CDN fingerprinting + 8 probe payloads
│   ├── recon.py            robots.txt + sitemap.xml parser + homepage link extractor
│   ├── scraper.py          Stealth and aggressive scraping + product data extraction
│   ├── ddos.py             4-vector bot flood engine with live Rich dashboard
│   ├── reporter.py         Scoring, recommendations, JSON + HTML report generation
│   └── distributor.py      SSH orchestration engine for distributed fleet execution
└── templates/
    ├── report.html.j2      Per-target HTML report (dark theme, Chart.js)
    └── comparison.html.j2  Side-by-side comparison report
```

**Data flow (single target):**

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
    ├─ [compare mode]      reporter.build_comparison_html(result_a, result_b)
    │
    └─ [distributed mode]  distributor.run_distributed(url, args, cfg)
                               │
                               ├─ [thread: node-sg-01]  SSH → upload → run → download
                               ├─ [thread: node-fr-01]  SSH → upload → run → download
                               └─ [thread: node-us-01]  SSH → upload → run → download
                                       ↓ all complete
                               distributor.merge_results() → merged_report.json
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

# ── Distributed mode (multi-VPS fleet) ──────────────────────────────────────

# First time: bootstrap all nodes (upload + install deps)
python botstrike.py --setup-nodes

# Distributed scraping across all nodes simultaneously
python botstrike.py --url https://shop.example.com --mode scrape --distributed

# Distributed full test (each node from its own IP)
python botstrike.py --url https://shop.example.com \
    --mode full --confirm-authorized --distributed

# Distributed full test, custom nodes file, heavy profile
python botstrike.py --url https://shop.example.com \
    --mode full --confirm-authorized --distributed \
    --nodes /path/to/my_nodes.yaml --profile heavy
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

### distributed mode

| Flag | Default | Description |
|---|---|---|
| `--distributed` | off | Run BotStrike simultaneously across all nodes in `--nodes`. Each node sends traffic from its own IP. Results are merged locally into a fleet report. |
| `--nodes FILE` | `nodes.yaml` | Path to the fleet config YAML. See [Step 3 — Create nodes.yaml](#step-3--create-nodesyaml) for format. |
| `--setup-nodes` | off | Bootstrap mode — connect to all nodes, upload BotStrike, install dependencies, run smoke test, then exit. No `--url` needed. Run this once before the first engagement. |

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

## Distributed Mode

Distributed mode lets you run BotStrike across a fleet of Linux VPS nodes simultaneously with a single command. Every node executes the full pipeline independently from its own public IP address. This is the correct way to test bot protection against realistic multi-source traffic — bypassing per-IP rate limiting, generating geographically diverse requests, and producing a combined picture of how the target behaves under pressure from many sources at once.

All orchestration happens over SSH. There is no agent to install on the VPS nodes, no daemon to run, no open ports to expose. BotStrike uploads itself, installs its own dependencies, runs, and downloads results — all automatically.

---

### How Distributed Mode Works

```
Your local machine                       Remote VPS fleet
──────────────────                       ──────────────────────────────────────
botstrike.py --distributed
    │
    ├── Read nodes.yaml                  
    ├── Launch one thread per node ──────┬─► node-sg-01 (Singapore)
    │                                    ├─► node-fr-01 (Paris)      [parallel]
    │                                    └─► node-us-01 (New York)   [parallel]
    │
    │   Per node (simultaneous):
    │     1. SSH connect (key auth)
    │     2. SFTP upload botstrike/ → ~/botstrike/
    │     3. pip install -r requirements.txt
    │     4. python3 botstrike.py --url <TARGET> --yes [flags...]
    │     5. Stream stdout back in real-time → live dashboard
    │     6. SFTP download JSON + HTML report
    │     7. Parse key metrics (score, blocked%, requests)
    │
    ├── Live fleet table refreshes every 500ms (all nodes visible)
    │
    └── When all threads finish:
          merge_results() → reports/distributed_<ts>/merged_report.json
          Print fleet summary to terminal
```

**Why this matters for engagements:**

A single-IP test is trivially blocked by rate limiting — the WAF blocks you, not the bot pattern. With 5 VPS nodes each sending 100 RPS from different IPs and countries, you have 500 combined RPS from 5 distinct sources. The WAF now needs to detect the *behavior pattern*, not just count requests per IP. That is where DataDome and CrowdSec are genuinely differentiated, and where the distributed results become meaningful evidence for your client.

---

### Prerequisites

**On your local machine:**
- Python 3.9+ with BotStrike installed
- `paramiko` Python library (`pip install paramiko`)
- SSH private key with access to each VPS

**On each VPS node:**
- Debian / Ubuntu / Kali Linux (any modern version)
- Python 3.9 or newer
- `pip3` / `python3-pip`
- Outbound internet access to the target domain
- SSH listening on the configured port, accessible from your local IP

```bash
# Minimum VPS setup (run on each node if needed)
apt update && apt install -y python3 python3-pip
```

No other software needs to be installed on the VPS nodes. BotStrike handles everything else automatically via `--setup-nodes`.

---

### Step 1 — Generate a Dedicated SSH Key

Generate one key pair specifically for BotStrike. Do **not** reuse your personal SSH key — this keeps your fleet credentials isolated and easy to rotate.

```bash
ssh-keygen -t ed25519 -C "botstrike-fleet" -f ~/.ssh/botstrike_key
```

This creates two files:
- `~/.ssh/botstrike_key` — your private key (stays on your machine, never shared)
- `~/.ssh/botstrike_key.pub` — the public key (will be installed on each VPS)

Use `ed25519` for modern elliptic-curve security. If your VPS provider requires RSA:

```bash
ssh-keygen -t rsa -b 4096 -C "botstrike-fleet" -f ~/.ssh/botstrike_key
```

---

### Step 2 — Authorize the Key on Every VPS

Push the public key to each VPS so BotStrike can connect without a password:

```bash
ssh-copy-id -i ~/.ssh/botstrike_key.pub root@1.2.3.4
ssh-copy-id -i ~/.ssh/botstrike_key.pub ubuntu@5.6.7.8
ssh-copy-id -i ~/.ssh/botstrike_key.pub kali@9.10.11.12
```

Verify that key-only login works before proceeding:

```bash
ssh -i ~/.ssh/botstrike_key root@1.2.3.4 "echo connected"
# Output: connected
```

If you cannot use `ssh-copy-id` (e.g. VPS was provisioned with a password only), add the key manually:

```bash
# On the VPS, as root or the target user:
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo "<paste contents of ~/.ssh/botstrike_key.pub here>" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```

---

### Step 3 — Create nodes.yaml

Copy the example file and fill in your VPS details:

```bash
cp nodes.yaml.example nodes.yaml
```

Edit `nodes.yaml`:

```yaml
nodes:

  - id: node-sg-01          # Label shown in reports and live dashboard
    host: 1.2.3.4           # VPS public IP or hostname
    user: root              # SSH user
    key: ~/.ssh/botstrike_key  # Path to private key on YOUR machine
    port: 22               # SSH port (optional — defaults to 22)

  - id: node-fr-01
    host: 5.6.7.8
    user: ubuntu
    key: ~/.ssh/botstrike_key

  - id: node-us-east-01
    host: 9.10.11.12
    user: kali
    key: ~/.ssh/botstrike_key
```

**Field reference:**

| Field | Required | Description |
|---|---|---|
| `id` | yes | Friendly identifier. Appears in the live dashboard, per-node reports, and merged JSON. Use descriptive names like `sg-01`, `fr-vpn`, `us-east`. |
| `host` | yes | VPS public IP address or fully qualified domain name. |
| `user` | yes | SSH username. Must have Python 3.9+ and pip available. |
| `key` | yes | Absolute or `~`-prefixed path to the **private** key file on your local machine. |
| `port` | no | SSH port. Defaults to `22` if omitted. |

`nodes.yaml` is permanently excluded from git via `.gitignore`. It will never be committed regardless of how many times you run `git add .`.

---

### Step 4 — Bootstrap the Fleet

Run the setup command once before your first engagement. This connects to every node in parallel, uploads BotStrike, installs all Python dependencies, and runs a smoke test:

```bash
python botstrike.py --setup-nodes
```

You will see a live table showing each node's progress through the setup stages:

```
╭───────────────────────────────────────────────────────────────────────────╮
│  BotStrike Distributed  ·  node setup  ·  3 nodes  ·  0 done  ·  12s    │
├────────────────┬──────────────────┬──────────────┬─────────┬─────────────┤
│ Node           │ Status           │ Phase        │ Elapsed │ Last        │
├────────────────┼──────────────────┼──────────────┼─────────┼─────────────┤
│ node-sg-01     │ ✓  DONE          │ —            │ 18s     │ Node ready  │
│ node-fr-01     │ ⚙  INSTALLING    │ —            │ 12s     │ Running pip │
│ node-us-east-01│ ↑  UPLOADING     │ —            │ 6s      │ Uploaded 14 │
╰────────────────┴──────────────────┴──────────────┴─────────┴─────────────╯
```

When complete:

```
  Ready: 3/3   Failed: 0

  Nodes are ready. Run:
    python botstrike.py --url <TARGET> --distributed --nodes nodes.yaml
```

If a node fails, the error is shown inline. Common causes and fixes are in [Troubleshooting](#troubleshooting).

**Using a custom nodes file:**

```bash
python botstrike.py --setup-nodes --nodes /path/to/my_nodes.yaml
```

**Re-running setup is safe.** Files are overwritten, pip skips already-installed packages, and the smoke test re-validates everything. Run it again any time you update BotStrike.

---

### Step 5 — Run a Distributed Test

#### Scraping only (no authorization required)

```bash
python botstrike.py \
    --url https://shop.example.com \
    --mode scrape \
    --distributed
```

#### Full test including bot flood

```bash
python botstrike.py \
    --url https://shop.example.com \
    --mode full \
    --confirm-authorized \
    --distributed
```

#### Non-interactive (scripted / CI)

```bash
python botstrike.py \
    --url https://shop.example.com \
    --mode full \
    --confirm-authorized \
    --distributed \
    --yes \
    --operator "j.doe@company.com"
```

#### Heavy profile — maximum pressure from all nodes

```bash
python botstrike.py \
    --url https://shop.example.com \
    --mode full \
    --confirm-authorized \
    --distributed \
    --profile heavy \
    --rps 300 \
    --duration 120
```

With 5 nodes at `--profile heavy`, you get 5 × 300 = **1,500 combined RPS** from 5 distinct IPs, each running for 120 seconds per vector.

#### Custom nodes file

```bash
python botstrike.py \
    --url https://shop.example.com \
    --mode scrape \
    --distributed \
    --nodes /etc/botstrike/engagement_nodes.yaml
```

---

### Live Fleet Dashboard

While a distributed run is in progress, BotStrike displays a live table that refreshes every 500ms. It shows all nodes simultaneously:

```
╭────────────────────────────────────────────────────────────────────────────────────────────────────╮
│  BotStrike Distributed  ·  https://shop.example.com  ·  3 nodes  ·  1 done  ·  0 failed  ·  142s  │
├──────────────────┬─────────────────┬──────────────────┬──────────┬──────────┬────────┬────────┬────╮
│ Node             │ Status          │ Phase            │ Requests │ Blocked% │ Score  │Elapsed │... │
├──────────────────┼─────────────────┼──────────────────┼──────────┼──────────┼────────┼────────┤    │
│ node-sg-01       │ ✓  DONE         │ Reporting        │ 1,842    │ 34.2%    │ C (67) │ 187s   │    │
│ node-fr-01       │ ●  RUNNING      │ HTTP Flood       │ 18,431   │ 71.0%    │ —      │ 142s   │    │
│ node-us-east-01  │ ●  RUNNING      │ Stealth Scrape   │ 203      │ 12.1%    │ —      │ 142s   │    │
╰──────────────────┴─────────────────┴──────────────────┴──────────┴──────────┴────────┴────────┴────╯
```

**Column descriptions:**

| Column | Description |
|---|---|
| Node | The `id` from `nodes.yaml` |
| Status | `CONNECTING` → `UPLOADING` → `INSTALLING` → `RUNNING` → `DONE` / `FAILED` |
| Phase | Current pipeline phase inferred from the node's stdout (`Pre-Flight`, `Recon`, `Stealth Scrape`, `Aggressive Scrape`, `HTTP Flood`, `Slowloris`, `POST Flood`, `Cache Buster`, `Reporting`) |
| Requests | Total HTTP requests sent so far by this node |
| Blocked% | Average of stealth blocked% and aggressive blocked% (populated after node finishes) |
| Score | Protection grade and numeric score (populated after report is downloaded) |
| Elapsed | Wall-clock seconds since this node's thread started |
| Last Activity | Most recent stdout line from the remote run, or error message on failure |

---

### Distributed Output Structure

All output is saved locally under `reports/distributed_<YYYYMMDD_HHMMSS>/`:

```
reports/
└── distributed_20260506_143021/
    ├── merged_report.json          ← Aggregated fleet results (main deliverable)
    │
    ├── node-sg-01/
    │   ├── botstrike_<id>.json     ← Full individual report from this node
    │   └── botstrike_<id>.html     ← Individual HTML dashboard from this node
    │
    ├── node-fr-01/
    │   ├── botstrike_<id>.json
    │   └── botstrike_<id>.html
    │
    └── node-us-east-01/
        ├── botstrike_<id>.json
        └── botstrike_<id>.html
```

- Individual JSON/HTML reports are full standard BotStrike reports, identical to what a single-node run would produce. They can be opened directly in a browser.
- `merged_report.json` aggregates all nodes into one document (see below).
- The `distributed_<ts>/` folder name is the engagement timestamp and is unique per run.

---

### Merged Report Format

`merged_report.json` has three top-level sections:

```json
{
  "distributed": {
    "node_count": 3,
    "nodes_ok": 3,
    "nodes_failed": 0,
    "target": "https://shop.example.com",
    "generated_at": "2026-05-06T14:52:11Z",
    "tool_version": "1.0"
  },

  "aggregated": {
    "total_requests_stealth": 4821,
    "total_requests_aggressive": 9102,
    "total_requests_all": 13923,
    "items_extracted_total": 247,
    "stealth_blocked_pct_avg": 28.4,
    "aggressive_blocked_pct_avg": 61.7,
    "ddos_vectors": {
      "http_flood": {
        "total_requests": 54300,
        "rps_combined": 287.4,
        "blocked_pct_avg": 71.2,
        "latency_avg_ms": 143.8
      },
      "slowloris":    { ... },
      "post_flood":   { ... },
      "cache_buster": { ... }
    },
    "score": 68,
    "grade": "C",
    "recommendations": [ { "priority", "title", "detail" }, ... ]
  },

  "per_node": [
    {
      "node_id": "node-sg-01",
      "host": "1.2.3.4",
      "status": "DONE",
      "score": 67,
      "grade": "C",
      "blocked_pct": 34.2,
      "requests": 1842,
      "html_report": "reports/distributed_.../node-sg-01/botstrike_abc123.html",
      "json_report": "reports/distributed_.../node-sg-01/botstrike_abc123.json",
      "log_tail": ["[SCRAPE:STEALTH] ...", "..."],
      "data": { <full botstrike JSON for this node> }
    },
    { ... },
    { ... }
  ]
}
```

**Aggregation logic:**

| Metric | How it is combined |
|---|---|
| `total_requests_*` | Sum across all nodes |
| `stealth_blocked_pct_avg` | Weighted average by request count per node |
| `aggressive_blocked_pct_avg` | Weighted average by request count per node |
| `ddos_vectors.total_requests` | Sum (nodes run the same vectors simultaneously) |
| `ddos_vectors.rps_combined` | Sum of each node's avg RPS (real combined throughput) |
| `ddos_vectors.blocked_pct_avg` | Average across nodes |
| `score` | Average of all nodes' numeric scores |
| `grade` | Derived from the averaged score |
| `recommendations` | Union of all nodes' recommendations, deduplicated by title |

---

### Distributed CLI Reference

| Flag | Requires | Description |
|---|---|---|
| `--distributed` | `--url`, `nodes.yaml` present | Enable fleet mode. Uploads, runs, and collects from all nodes simultaneously. |
| `--nodes FILE` | — | Override the default `nodes.yaml` path. Useful when managing multiple client engagement node files. |
| `--setup-nodes` | `nodes.yaml` present | Bootstrap all nodes. No `--url` needed. Idempotent — safe to re-run. |

All other flags pass through to each remote node unchanged:

| Passed through | Not passed through |
|---|---|
| `--mode`, `--confirm-authorized`, `--yes` | `--distributed` (would cause infinite loop) |
| `--profile`, `--rps`, `--duration`, `--connections` | `--proxy` (each node connects directly from its own IP — that is the point) |
| `--operator` (suffixed with `@<node_id>`) | `--compare`, `--url-a`, `--url-b` |
| `--config` | `--nodes`, `--setup-nodes` |

---

### Security Model

BotStrike's distributed mode is designed so that no sensitive data ever leaves your machine unintentionally, and no persistent footprint is left on the VPS nodes.

**Authentication:**
- SSH key-only authentication. Passwords are never used, stored, or prompted for.
- The private key never leaves your local machine. Only the public key is installed on VPS nodes.
- A dedicated key pair (`botstrike_key`) is recommended so it can be rotated independently of your personal keys.
- BotStrike uses `paramiko` with `look_for_keys=False` and `allow_agent=False`, meaning it uses only the explicitly specified key file.

**What is uploaded to each node:**
- The BotStrike Python source code (no secrets, no reports, no config)
- `nodes.yaml` is explicitly excluded from the SFTP upload — VPS IPs are never sent to other VPS nodes
- Previously generated reports are excluded from the upload
- `.git/` is excluded

**What stays on the VPS after a run:**
- `~/botstrike/` — the uploaded source code and generated reports
- The reports in `~/botstrike/reports/` are downloaded to your local machine and can then be deleted remotely

**`nodes.yaml` is gitignored.** The file containing your VPS IPs and key paths cannot be accidentally committed regardless of how you use git in this directory.

**Host key verification:** BotStrike uses `AutoAddPolicy` (equivalent to `StrictHostKeyChecking=no`) for first-time connections. This is intentional for pentest tooling where nodes are provisioned fresh per engagement. If you require strict verification, you can modify `_connect()` in `modules/distributor.py` to use `RejectPolicy` and provide a known_hosts file.

---

### Troubleshooting

**Node shows `FAILED: SSH key not found: ~/.ssh/botstrike_key`**

The key path in `nodes.yaml` does not resolve to an existing file on your local machine. Check the path:

```bash
ls -la ~/.ssh/botstrike_key
```

If it does not exist, run [Step 1](#step-1--generate-a-dedicated-ssh-key) again.

---

**Node shows `FAILED: Auth failed — check SSH key`**

The public key is not in the VPS's `authorized_keys` file. Run:

```bash
ssh-copy-id -i ~/.ssh/botstrike_key.pub <user>@<host>
# Then verify:
ssh -i ~/.ssh/botstrike_key <user>@<host> "echo ok"
```

---

**Node shows `FAILED: pip install failed`**

Python or pip is missing on the VPS:

```bash
ssh -i ~/.ssh/botstrike_key <user>@<host> "python3 --version && pip3 --version"
```

Install if missing:

```bash
ssh -i ~/.ssh/botstrike_key root@<host> "apt update && apt install -y python3 python3-pip"
```

Then re-run `--setup-nodes`.

---

**Node shows `FAILED: [Errno 111] Connection refused`**

SSH is not running on the expected port, or a firewall is blocking it:

```bash
# Test connectivity from your machine
nc -zv <host> <port>
# Check SSH on the VPS (if you have another way in)
systemctl status ssh
ufw allow 22
```

---

**Node shows `DONE` but `merged_report.json` shows it with no data**

The remote botstrike run exited before generating a report (e.g. target was unreachable from that node, or Python version was too old). Check the node's log:

```bash
# The last 30 log lines are embedded in merged_report.json
cat reports/distributed_*/merged_report.json | python3 -c "
import json,sys
d=json.load(sys.stdin)
for n in d['per_node']:
    print('\\n---', n['node_id'])
    print('\\n'.join(n['log_tail']))
"
```

---

**`paramiko` is not installed**

```bash
pip install paramiko
# or
pip install -r requirements.txt
```

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
