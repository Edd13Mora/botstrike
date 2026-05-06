# BotStrike v1.0

**Bot Protection Effectiveness Tester**

BotStrike is a command-line tool for security professionals. It attacks a website the same way real bots do — scraping, flooding, credential stuffing — and tells you how well the site's bot protection (DataDome, CrowdSec, Cloudflare, etc.) actually stops it. Results are scored A–F and saved as a full HTML dashboard + JSON report.

> **Authorized use only.** Only test websites you own or have written permission to test. The `--confirm-authorized` flag is your legal declaration of that authorization.

---

## Table of Contents

- [How It Works](#how-it-works)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Test Modules](#test-modules)
- [CLI Reference](#cli-reference)
- [Profile Presets](#profile-presets)
- [Protection Scoring](#protection-scoring)
- [Recommendations Engine](#recommendations-engine)
- [Reporting](#reporting)
- [Compare Mode](#compare-mode)
- [Distributed Mode — Run from Many VPS at Once](#distributed-mode--run-from-many-vps-at-once)
- [Proxy Support](#proxy-support)
- [Config File](#config-file)
- [Project Structure](#project-structure)
- [Dependencies](#dependencies)
- [Legal Notice](#legal-notice)

---

## How It Works

BotStrike runs 4 phases against your target, one after another:

```
Phase 0 · Pre-Flight      Checks what WAF / CDN is protecting the site
Phase 1 · Recon           Reads robots.txt and sitemap to find pages to attack
Phase 2 · Scraping        Sends stealth bots (human-like) then obvious bots
Phase 3 · Bot Flood       4 attack types: HTTP flood, Slowloris, POST flood, Cache buster
```

After all phases finish, BotStrike:
- Scores the protection 0–100 and gives it a grade (A = excellent, F = no protection)
- Lists specific things the site should fix, in priority order (CRITICAL → LOW)
- Saves an HTML dashboard and a JSON report to your `reports/` folder

Press `CTRL+C` at any time — BotStrike will save whatever it has collected so far.

---

## Installation

**You need:** Python 3.9 or newer.

```bash
git clone https://github.com/Edd13Mora/botstrike.git
cd botstrike
pip install -r requirements.txt
```

**On Kali Linux:**
```bash
sudo apt update && sudo apt install python3-pip -y
pip3 install -r requirements.txt
python3 botstrike.py --help
```

**On Windows:**
```powershell
pip install -r requirements.txt
python botstrike.py --help
```

---

## Quick Start

```bash
# Just scraping — no authorization needed
python botstrike.py --url https://shop.example.com --mode scrape

# Full test including bot flood — you must have written authorization
python botstrike.py --url https://shop.example.com --mode full --confirm-authorized

# Compare DataDome vs CrowdSec side by side
python botstrike.py --compare \
    --url-a https://site-with-datadome.com --label-a "DataDome" \
    --url-b https://site-with-crowdsec.com --label-b "CrowdSec" \
    --mode full --confirm-authorized

# Run from 3 VPS servers at once (see Distributed Mode section below)
python botstrike.py --url https://shop.example.com --mode full --confirm-authorized --distributed
```

---

## Test Modules

### Module 0 — Pre-Flight Fingerprinting

Runs before anything else. Figures out what is protecting the target.

1. Checks that the domain resolves (exits if it does not)
2. Sends a normal request to confirm the site is live
3. Reads response headers to detect the CDN (Cloudflare, Akamai, Fastly, etc.)
4. Reads `Server` / `X-Powered-By` headers to detect the tech stack
5. Checks for HTTPS and HSTS
6. Looks for rate-limit headers (`X-RateLimit-Limit`, `Retry-After`)
7. Checks for `robots.txt` and `sitemap.xml`
8. Sends 8 crafted "attack" requests to see if the WAF reacts

**The 8 WAF probe requests:**

| Probe | What it sends | What it tests |
|---|---|---|
| SQLi | `?id=1' OR '1'='1` | SQL injection detection |
| XSS User-Agent | `<script>alert(1)</script>` in UA | Header scanning depth |
| Path Traversal | `/../../../etc/passwd` | Directory traversal signatures |
| XFF Spoof | `X-Forwarded-For: 127.0.0.1` | Localhost bypass via proxy header |
| Empty UA | *(blank User-Agent)* | Most WAFs block empty UAs immediately |
| Bot UA | `python-requests/2.31.0` | Basic bot detection |
| Scanner UA | `Nikto/2.1.6` on `/wp-admin/` | Scanner detection |
| Header Injection | `X-Custom-IP-Authorization: 127.0.0.1` | Internal IP bypass |

**WAF detection covers 13 vendors:**
DataDome · CrowdSec · Cloudflare · PerimeterX · Akamai · AWS WAF · Imperva · F5 BIG-IP · ModSecurity · Sucuri · Radware · Reblaze · Barracuda

If any probe gets a 403, 429, or 503 → WAF is `ACTIVE (blocking)`.
If probes all get 200 → WAF is `PASSIVE (detection-only)` — a critical finding.

---

### Module 1 — Passive Recon

Discovers pages to use in the scraping and flood phases.

- Reads `robots.txt` — extracts all Allow/Disallow paths
- Reads `sitemap.xml` — extracts every `<loc>` URL (including nested sitemaps)
- Crawls the homepage — extracts all `<a href>` links
- Deduplicates everything and filters to the same domain

---

### Module 2A — Stealth Scraping

Simulates a patient, human-like bot. This is the hardest type to detect because it looks like real browsing.

**How it evades detection:**
- Picks from 200+ real browser User-Agent strings (Chrome, Firefox, Safari, Edge, mobile)
- Matches `Sec-CH-UA` headers to the chosen UA (a Chrome UA without the right `Sec-CH-UA` is a dead giveaway)
- Sends realistic headers: `Accept`, `Accept-Language`, `Referer` (from Google/Bing), `DNT`
- Randomizes header order (bot detectors fingerprint header order, not just values)
- Waits 1.5–4 seconds between requests (configurable)
- Uses a persistent session with cookies across requests

For every HTML page it visits, it also tries to extract product data:
- Name, price, description, images

---

### Module 2B — Aggressive Scraping

Simulates a naive, obvious bot — no delays, no session, minimal headers, raw speed. Any WAF should block these immediately. If it does not, that is a HIGH finding.

Also tries common API paths: `/api/products`, `/api/catalog`, `/api/prices`, `/search?q=*`, etc.

---

### Module 3 — Application-Layer Bot Flood

**Requires `--confirm-authorized`**

Runs 4 attack vectors in sequence. A live terminal dashboard updates every 500ms.

> These are single-source L7 floods — they test per-IP rate limiting and detection speed. They are not the same as a distributed DDoS from a botnet. For client reports, describe this as "Application-Layer Bot Flood Stress Test."

#### Vector 1 — HTTP Flood
High-volume GET flood. Ramps from 0 to target RPS over 30 seconds, then sustains. Spreads across all discovered URLs.

#### Vector 2 — Slowloris
Opens many TCP connections (default 200) and keeps each one alive by sending incomplete requests — never finishing them. Goal: exhaust the server's connection pool without much bandwidth.

#### Vector 3 — POST Flood
Sends random POST data to form endpoints: `/checkout`, `/cart`, `/login`, `/search`, etc. POST requests are more expensive for the server to process than GETs.

#### Vector 4 — Cache Buster
Adds a unique query string (`?cb=<uuid>&ts=<ms>`) to every request so CDN caches cannot serve cached responses. Every request hits the origin server.

**Metrics collected per vector:** total requests, avg/peak RPS, latency p50/p95/p99/peak, blocked%, full response code breakdown.

---

## CLI Reference

### Target

| Flag | Description |
|---|---|
| `--url URL` | The site to test. Include the scheme: `https://shop.example.com` |

### Test Control

| Flag | Default | Description |
|---|---|---|
| `--mode MODE` | `full` | `scrape` — recon + scraping only. `ddos` — recon + flood only. `full` — everything. |
| `--confirm-authorized` | off | Required to unlock the bot flood. Declares you have written authorization. |
| `--yes` | off | Skip all confirmation prompts. For CI/scripted runs. |

### DDoS Tuning

| Flag | Default | Description |
|---|---|---|
| `--rps N` | `100` | Target requests/second for the HTTP flood. |
| `--duration SECONDS` | `60` | How long each flood vector runs. |
| `--connections N` | `200` | Concurrent TCP connections for Slowloris. |

### Output & Metadata

| Flag | Default | Description |
|---|---|---|
| `--operator NAME` | — | Your name or email — embedded in the report for accountability. |
| `--config FILE` | `config.yaml` | Path to a custom config file. |

### Behaviour Presets

| Flag | Default | Description |
|---|---|---|
| `--profile PROFILE` | `medium` | `light`, `medium`, `heavy`, or `stealth`. See Profile Presets below. |
| `--proxy URL` | — | Route all traffic through a proxy. HTTP or SOCKS5. |

### Compare Mode

| Flag | Description |
|---|---|
| `--compare` | Enable side-by-side comparison of two targets. |
| `--url-a URL` | First target URL. |
| `--url-b URL` | Second target URL. |
| `--label-a NAME` | Label for Target A in the report (e.g. "DataDome"). |
| `--label-b NAME` | Label for Target B in the report (e.g. "CrowdSec"). |

### Distributed Mode

| Flag | Default | Description |
|---|---|---|
| `--distributed` | off | Run across all VPS nodes in `nodes.yaml` simultaneously. |
| `--nodes FILE` | `nodes.yaml` | Path to your fleet config file. |
| `--setup-nodes` | off | First-time setup: connects to all nodes, uploads BotStrike, installs dependencies. |

---

## Profile Presets

| Preset | Stealth threads | Delay between requests | Aggressive threads | RPS | Duration | Slowloris |
|---|---|---|---|---|---|---|
| `light` | 2 | 2.5–6.0 s | 4 | 30 | 30 s | 50 |
| `medium` *(default)* | 3 | 1.5–4.0 s | 10 | 100 | 60 s | 200 |
| `heavy` | 5 | 1.0–2.5 s | 20 | 300 | 120 s | 500 |
| `stealth` | 1 | 5.0–12.0 s | 1 | 10 | 30 s | 20 |

Any explicit CLI flag (`--rps`, `--duration`, `--connections`) overrides the preset.

---

## Protection Scoring

BotStrike starts at 100 and subtracts points for each problem it finds:

| Finding | Points lost | Severity |
|---|---|---|
| No WAF detected | −35 | CRITICAL |
| WAF is passive (detecting but not blocking) | −20 | HIGH |
| Stealth bots blocked less than 20% of the time | −20 | HIGH |
| Stealth bots blocked 20–49% of the time | −10 | MEDIUM |
| Obvious bots blocked less than 50% of the time | −15 | HIGH |
| Obvious bots blocked 50–79% of the time | −5 | LOW |
| Each flood vector blocked less than 30% | −5 | MEDIUM |
| No CDN detected | −5 | LOW |
| HSTS header missing | −5 | LOW |

**Grades:**

| Grade | Score |
|---|---|
| A | 90–100 |
| B | 80–89 |
| C | 65–79 |
| D | 50–64 |
| F | below 50 |

---

## Recommendations Engine

After scoring, BotStrike generates a prioritized list of things to fix. Each recommendation includes:
- Priority: CRITICAL / HIGH / MEDIUM / LOW
- Title
- Detailed description with product-specific guidance for DataDome and CrowdSec

Recommendations are sorted from most critical to least, and displayed as color-coded cards in the HTML report.

---

## Reporting

Reports are saved to `reports/<hostname>_<date>_<time>/` after every run.

### JSON Report (`botstrike_<id>.json`)
Machine-readable full output. Contains every metric from every phase, the score, all recommendations, and historical deltas.

### HTML Report (`botstrike_<id>.html`)
Standalone dark-themed dashboard — open it in any browser, no internet required. Sections:
- Protection score hero (grade circle, numeric score, deductions)
- Historical delta (▲/▼ vs your previous run on the same site)
- WAF fingerprint results and probe table
- Recommendations cards (color-coded by priority)
- Scraping results with charts and extracted product samples
- Bot flood results with latency percentiles and RPS charts

### Log File (`botstrike_<id>.log`)
Plain-text audit trail of every operation with timestamps.

### Historical Deltas
If you have run BotStrike against the same site before, the new report shows `▲ improved` or `▼ regressed` compared to the previous run — useful for tracking remediation progress over time.

---

## Compare Mode

Runs the full pipeline against two sites and generates three reports:
1. Individual report for Site A
2. Individual report for Site B
3. A side-by-side comparison dashboard

The comparison dashboard shows: winner verdict, KPI grid with ▲/▼ indicators, scraping charts, flood charts, and recommendations side by side.

```bash
python botstrike.py --compare \
    --url-a https://datadome-site.com  --label-a "DataDome" \
    --url-b https://crowdsec-site.com  --label-b "CrowdSec" \
    --mode full --confirm-authorized \
    --operator "consultant@company.com"
```

---

## Distributed Mode — Run from Many VPS at Once

> **What is this?** Instead of running BotStrike from your laptop (one IP), you run it from 3, 5, 10 VPS servers at the same time — each from a different IP, in a different country. This bypasses per-IP rate limits and generates realistic multi-source traffic. One command does everything.

---

### Step 0 — Understand How It Works (Plain English)

Here is exactly what happens when you run `--distributed`:

```
1. BotStrike reads your nodes.yaml file
   (this is where you list your VPS servers — IP, username, SSH key)

2. For each VPS, BotStrike:
   a. Connects to it over SSH (using your key — no password)
   b. Uploads itself (copies the BotStrike files to the VPS automatically)
   c. Installs its dependencies (runs pip install on the VPS)
   d. Runs the test (each VPS attacks the target from its own IP)
   e. Downloads the results back to your machine

3. All VPS servers run at the same time (parallel)

4. BotStrike merges all results into one combined report
```

**You do NOT need to manually copy files to the VPS.**
**You do NOT need to install anything on the VPS manually (except Python + pip).**
**One command does everything.**

---

### Step 1 — Get Your VPS Servers

You need at least 1 Linux VPS. Any provider works: DigitalOcean, Vultr, Hetzner, Linode, OVH, etc.

Each VPS must have:
- Debian, Ubuntu, or Kali Linux
- Python 3.9 or newer
- `pip3` installed
- SSH port open (usually port 22)

If Python or pip is missing, run this on the VPS:
```bash
apt update && apt install -y python3 python3-pip
```

---

### Step 2 — Generate One SSH Key (on YOUR machine)

You need an SSH key so BotStrike can log into your VPS servers without a password.

Run this **once on your local machine**:

```bash
ssh-keygen -t ed25519 -C "botstrike-fleet" -f ~/.ssh/botstrike_key
```

This creates two files:
- `~/.ssh/botstrike_key` — your **private key** (stays on your machine, never shared)
- `~/.ssh/botstrike_key.pub` — your **public key** (you put this on each VPS)

> **Same key for all VPS?** Yes. You generate one key pair. You install the public key on every VPS. Your private key stays on your machine and never moves.

---

### Step 3 — Put the Public Key on Every VPS

Run this **for each VPS** (replace IP and user with your actual VPS details):

```bash
ssh-copy-id -i ~/.ssh/botstrike_key.pub root@1.2.3.4
ssh-copy-id -i ~/.ssh/botstrike_key.pub ubuntu@5.6.7.8
ssh-copy-id -i ~/.ssh/botstrike_key.pub kali@9.10.11.12
```

Then verify the connection works (no password should be asked):

```bash
ssh -i ~/.ssh/botstrike_key root@1.2.3.4 "echo connected"
# Should print: connected
```

If `ssh-copy-id` is not available, do it manually on the VPS:
```bash
mkdir -p ~/.ssh && chmod 700 ~/.ssh
echo "PASTE YOUR PUBLIC KEY HERE" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
```
*(Your public key is the content of `~/.ssh/botstrike_key.pub` on your local machine)*

---

### Step 4 — Create Your nodes.yaml File

This file is where you tell BotStrike about your VPS servers.

Copy the example file:
```bash
cp nodes.yaml.example nodes.yaml
```

Open `nodes.yaml` and fill in your VPS details:

```yaml
nodes:

  - id: node-sg-01               # A name for this server (you choose it, appears in reports)
    host: 1.2.3.4                # The VPS IP address
    user: root                   # The SSH username
    key: ~/.ssh/botstrike_key    # Path to your private key (on YOUR machine)
    port: 22                     # SSH port (default is 22, you can omit this line)

  - id: node-fr-01
    host: 5.6.7.8
    user: ubuntu
    key: ~/.ssh/botstrike_key

  - id: node-us-east-01
    host: 9.10.11.12
    user: kali
    key: ~/.ssh/botstrike_key
```

**Each entry is one VPS server. Add as many as you want.**

> `nodes.yaml` is permanently excluded from git — it can never be accidentally committed, because it contains your server IPs.

---

### Step 5 — Bootstrap the Fleet (First Time Only)

Run this once before your first distributed test. BotStrike will connect to every VPS, upload itself, and install its dependencies:

```bash
python botstrike.py --setup-nodes
```

You will see a live status table showing each VPS going through the stages:

```
╭────────────────────────────────────────────────────────────────╮
│  BotStrike Distributed  ·  node setup  ·  3 nodes  ·  18s     │
├─────────────────┬─────────────────┬──────────┬─────────────────┤
│ Node            │ Status          │ Elapsed  │ Last            │
├─────────────────┼─────────────────┼──────────┼─────────────────┤
│ node-sg-01      │ ✓  DONE         │ 18s      │ Node ready      │
│ node-fr-01      │ ⚙  INSTALLING   │ 12s      │ Running pip...  │
│ node-us-east-01 │ ↑  UPLOADING    │ 6s       │ Uploaded 14...  │
╰─────────────────┴─────────────────┴──────────┴─────────────────╯

  Ready: 3/3   Failed: 0

  Nodes are ready. Run:
    python botstrike.py --url <TARGET> --distributed
```

**You only run `--setup-nodes` once.** After that, run it again only if you update BotStrike (it is safe to re-run at any time).

---

### Step 6 — Run a Distributed Test

```bash
# Scraping only (no authorization needed)
python botstrike.py --url https://shop.example.com --mode scrape --distributed

# Full test including bot flood (requires written authorization)
python botstrike.py --url https://shop.example.com --mode full --confirm-authorized --distributed

# Heavy pressure from all nodes (5 nodes × 300 RPS = 1,500 combined RPS)
python botstrike.py --url https://shop.example.com \
    --mode full --confirm-authorized --distributed \
    --profile heavy --rps 300 --duration 120
```

---

### Live Fleet Dashboard

While the test runs, you see all VPS servers in a live table:

```
╭──────────────────────────────────────────────────────────────────────────────────╮
│  BotStrike Distributed  ·  https://shop.example.com  ·  3 nodes  ·  142s        │
├──────────────────┬──────────────────┬──────────────────┬──────────┬──────────────┤
│ Node             │ Status           │ Phase            │ Requests │ Blocked%     │
├──────────────────┼──────────────────┼──────────────────┼──────────┼──────────────┤
│ node-sg-01       │ ✓  DONE          │ Reporting        │ 1,842    │ 34.2%        │
│ node-fr-01       │ ●  RUNNING       │ HTTP Flood       │ 18,431   │ 71.0%        │
│ node-us-east-01  │ ●  RUNNING       │ Stealth Scrape   │ 203      │ 12.1%        │
╰──────────────────┴──────────────────┴──────────────────┴──────────┴──────────────╯
```

**Status stages:** `CONNECTING` → `UPLOADING` → `INSTALLING` → `RUNNING` → `DONE` / `FAILED`

---

### Where Are the Results?

All results are saved locally on your machine under `reports/distributed_<timestamp>/`:

```
reports/
└── distributed_20260506_143021/
    │
    ├── merged_report.json        ← Combined results from ALL nodes (main report)
    │
    ├── node-sg-01/
    │   ├── botstrike_abc.json    ← Full report from this specific node
    │   └── botstrike_abc.html    ← HTML dashboard from this node (open in browser)
    │
    ├── node-fr-01/
    │   ├── botstrike_xyz.json
    │   └── botstrike_xyz.html
    │
    └── node-us-east-01/
        ├── botstrike_def.json
        └── botstrike_def.html
```

**Open any `.html` file in your browser** to see the full visual dashboard for that node.

**`merged_report.json`** combines everything: total requests summed, blocked% averaged across all nodes, combined RPS, unified recommendations.

---

### Troubleshooting

**"SSH key not found: ~/.ssh/botstrike_key"**
The key file does not exist at that path on your machine.
```bash
ls -la ~/.ssh/botstrike_key
# If missing, go back to Step 2 and generate the key
```

---

**"Auth failed — check SSH key"**
The public key is not installed on the VPS.
```bash
ssh-copy-id -i ~/.ssh/botstrike_key.pub <user>@<host>
ssh -i ~/.ssh/botstrike_key <user>@<host> "echo ok"
```

---

**"pip install failed"**
Python or pip is missing on the VPS.
```bash
# Run on the VPS:
apt update && apt install -y python3 python3-pip
# Then re-run:
python botstrike.py --setup-nodes
```

---

**"Connection refused"**
SSH is not running on that port, or the firewall is blocking it.
```bash
# Test from your machine:
nc -zv <host> 22
# Fix on the VPS:
systemctl start ssh
ufw allow 22
```

---

**Node says DONE but has no data in merged report**
The test ran but exited before finishing (target unreachable from that node, or wrong Python version). Read the node's log:
```bash
cat reports/distributed_*/merged_report.json | python3 -c "
import json,sys
d=json.load(sys.stdin)
for n in d['per_node']:
    print('---', n['node_id'])
    print('\n'.join(n['log_tail']))
"
```

---

**"paramiko is not installed"**
```bash
pip install -r requirements.txt
```

---

## Proxy Support

Route all traffic through a proxy with `--proxy`:

```bash
# HTTP proxy
python botstrike.py --url https://shop.example.com --proxy http://proxyhost:8080

# Tor (SOCKS5)
python botstrike.py --url https://shop.example.com --proxy socks5://127.0.0.1:9050
```

The proxy applies to every module: preflight, recon, scraping, and bot flood.

---

## Config File

`config.yaml` sets the defaults for everything. CLI flags always override it.

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
  connections: 200
  ramp_up_seconds: 30
  pause_between_vectors: 10

preflight:
  timeout: 10

logging:
  level: "INFO"    # DEBUG | INFO | WARNING
```

**Priority order:** CLI flags > config file > profile preset > built-in defaults.

---

## Project Structure

```
botstrike/
├── botstrike.py              Main entry point — run this
├── config.yaml               Default settings
├── requirements.txt          Python dependencies
├── nodes.yaml.example        Template for your VPS fleet config
├── README.md
├── wordlists/
│   └── useragents.txt        200+ real browser User-Agent strings
├── modules/
│   ├── preflight.py          WAF/CDN detection + 8 attack probes
│   ├── recon.py              robots.txt + sitemap + homepage crawler
│   ├── scraper.py            Stealth + aggressive scraping
│   ├── ddos.py               4-vector bot flood engine
│   ├── reporter.py           Scoring, recommendations, JSON + HTML reports
│   ├── distributor.py        SSH orchestration for distributed fleet mode
│   └── utils.py              Shared helpers: UA pool, headers, proxy, logging
└── templates/
    ├── report.html.j2        HTML report template
    └── comparison.html.j2    Side-by-side comparison template
```

---

## Dependencies

| Package | What it does |
|---|---|
| `requests` | All HTTP requests |
| `rich` | Terminal dashboards, tables, colored output |
| `beautifulsoup4` | HTML/XML parsing |
| `lxml` | Fast HTML parser |
| `pyyaml` | Reads YAML config and nodes files |
| `aiohttp` | Async HTTP for high-concurrency flood |
| `fake-useragent` | Fallback UA pool |
| `jinja2` | HTML report templates |
| `urllib3` | HTTP utilities |
| `paramiko` | SSH/SFTP for distributed mode |

---

## Legal Notice

BotStrike is for **authorized security testing only**.

- Only test systems you own or have **explicit written permission** to test.
- The `--confirm-authorized` flag is a legally binding declaration of that authorization.
- Unauthorized use may violate computer crime laws (CFAA in the US, Computer Misuse Act in the UK, etc.).
- The authors accept no liability for unauthorized or illegal use.
