# KRYPT CLI

```
██╗  ██╗██████╗ ██╗   ██╗██████╗ ████████╗
██║ ██╔╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝
█████╔╝ ██████╔╝ ╚████╔╝ ██████╔╝   ██║   
██╔═██╗ ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   
██║  ██╗██║  ██║   ██║   ██║        ██║   
╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   

             KRYPT CLI
   OSINT • RECON • DISCOVER • ASSESS
```

**Author:** Gaddam Manyu ([@manoharmanyu](https://github.com/manoharmanyu))  
**Version:** `0.1.0`  
**License:** MIT  

---

## Overview

**KRYPT CLI** is a **100% terminal-driven cybersecurity intelligence and authorized web-security assessment framework**.

Designed strictly for command-line efficiency:
* **NO** web dashboards
* **NO** graphical desktop windows
* **NO** external browser dependencies
* Everything is executed and visualized directly in your terminal via `krypt <command> [options]`.

KRYPT combines multi-source OSINT intelligence gathering, high-speed scoped web crawling, deep JavaScript static route extraction, defensive security header analysis, and controlled, fail-closed vulnerability assessment modules into a unified, modular architecture.

---

## Core Capabilities & Features

1. **Hard Target Scope Enforcement (Fail-Closed Safety):**
   * Pre-execution scope boundary validation prevents any active security probes from reaching unauthorized targets.
   * Scopes are registered explicitly via `krypt target add <target>`.
2. **Modular OSINT Intelligence Engine:**
   * Multi-source aggregation across DNS records (A, AAAA, MX, NS, TXT, CNAME, SOA), Certificate Transparency logs (`crt.sh`), passive subdomain enumeration, email indicator harvesting, and RDAP public records.
3. **Deep Web Reconnaissance & Fingerprinting:**
   * Automated identification of web servers (Nginx, Apache, IIS, Caddy), backend frameworks (Express, PHP, Laravel, Django, Flask, FastAPI), frontend libraries (React, Next.js, Vue), CMS (WordPress, Drupal), and CDN/WAF indicators (Cloudflare, CloudFront, Fastly).
4. **Controlled BFS Web Crawler (Photon & TorBot Inspired):**
   * Asynchronous, depth-bounded, rate-limited crawling discovering links, forms, parameters, scripts, and endpoints.
5. **Static JavaScript Inspection:**
   * Scans client-side JS bundles for internal API endpoints, route patterns, parameter definitions, and public configuration strings.
6. **Defensive Security Assessment Modules:**
   * **SQLi:** Defensive SQL injection detection using controlled syntax boundary probes and boolean differential analysis without destructive payload execution.
   * **XSS:** Reflected XSS analysis using harmless canary tokens and contextual output encoding verification.
   * **Auth:** Session cookie flags audit (`HttpOnly`, `Secure`, `SameSite`), token predictability, and rate-limiting indicators.
   * **Authz:** Broken access control and administrative route boundary tests (`/admin`, `/admin/dashboard`, `/admin/users`).
   * **IDOR:** Insecure Direct Object Reference testing across object identifier parameters using controlled test identities.
   * **Exposure:** Detection of leaked environment files (`.env`), Git repositories (`.git/HEAD`), backups, and debug endpoints (`/debug/vars`, `/actuator`).
   * **Headers:** Security headers grading (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy).
7. **Evidence-First Verification & Secret Redaction:**
   * Every security conclusion stores verifiable, redacted HTTP request/response proofs. Sensitive tokens, passwords, and authorization headers are automatically masked.
8. **Interactive Terminal Visualization:**
   * Renders tree graphs of target architecture, subdomains, endpoints, and finding severities directly inside the terminal (`krypt graph`).
9. **Multi-Format Reporting Engine:**
   * Generates reports in **Terminal (Rich table/cards)**, **JSON**, **HTML (dark-themed standalone)**, **Markdown**, **CSV**, and **PDF**.
10. **Built-in Intentionally Vulnerable Laboratory:**
    * Native Python/Docker laboratory environment with isolated test endpoints for testing and validating all assessment modules (`krypt lab start|stop|status|verify`).

---

## Architecture

```
                               ┌─────────────────────────────┐
                               │          KRYPT CLI          │
                               │      (Typer / Rich UI)      │
                               └──────────────┬──────────────┘
                                              │
              ┌───────────────────────────────┼───────────────────────────────┐
              │                               │                               │
              ▼                               ▼                               ▼
   ┌────────────────────┐          ┌────────────────────┐          ┌────────────────────┐
   │    OSINT Engine    │          │    Recon Engine    │          │  Security Modules  │
   │  DNS / Cert / Mail │          │ Crawler / JS / Tech│          │ SQLi, XSS, Auth,   │
   └──────────┬─────────┘          └──────────┬─────────┘          │ IDOR, Exposure     │
              │                               │                    └──────────┬─────────┘
              │                               │                               │
              └───────────────────────────────┼───────────────────────────────┘
                                              ▼
                               ┌─────────────────────────────┐
                               │   Fail-Closed Scope Engine  │
                               │   (Authorization Boundary)  │
                               └──────────────┬──────────────┘
                                              ▼
                               ┌─────────────────────────────┐
                               │        Evidence Store       │
                               │   & SQLite DB (~/.krypt/)   │
                               └──────────────┬──────────────┘
                                              ▼
                               ┌─────────────────────────────┐
                               │      Reporting Engine       │
                               │ (Terminal, JSON, HTML, PDF) │
                               └─────────────────────────────┘
```

---

## Installation

### Automatic Installation (macOS & Linux)

```bash
git clone https://github.com/manoharmanyu/krypt-cli.git
cd krypt-cli
chmod +x install.sh
./install.sh
```

### Manual Installation

```bash
# 1. Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Upgrade pip and install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 3. Install krypt-cli in editable mode
pip install -e .

# 4. Verify system diagnostics
krypt doctor
```

---

## Quick Start Guide

### 1. Run Diagnostics
```bash
krypt doctor
```

### 2. Start the Local Vulnerable Laboratory
```bash
krypt lab start
krypt lab verify
```

### 3. Register Authorized Target
```bash
krypt target add http://127.0.0.1:8888 --notes "Local Training Lab"
krypt target list
```

### 4. Gather OSINT & Domain Intelligence
```bash
krypt osint localhost
krypt dns localhost
```

### 5. Reconnaissance & Technology Fingerprinting
```bash
krypt recon http://127.0.0.1:8888
krypt tech http://127.0.0.1:8888
krypt headers http://127.0.0.1:8888
```

### 6. Crawl & Discover Endpoints
```bash
krypt crawl http://127.0.0.1:8888 --depth 3 --max-pages 50
krypt endpoints http://127.0.0.1:8888
krypt scripts http://127.0.0.1:8888
```

### 7. Run Security Assessment
```bash
# Run all security assessment modules
krypt scan http://127.0.0.1:8888 --all

# Or run specific modules
krypt scan http://127.0.0.1:8888 --module sqli
krypt scan http://127.0.0.1:8888 --module xss
krypt scan http://127.0.0.1:8888 --module authz
```

### 8. Inspect Findings & Verifiable Evidence
```bash
krypt findings
krypt findings show <FINDING_ID>
krypt evidence <FINDING_ID>
```

### 9. Terminal Visualization
```bash
krypt graph http://127.0.0.1:8888
```

### 10. Generate Assessment Reports
```bash
krypt report --format terminal
krypt report --format json --output report.json
krypt report --format html --output report.html
krypt report --format pdf --output report.pdf
```

### 11. Stop the Laboratory
```bash
krypt lab stop
```

---

## CLI Command Reference

| Command | Arguments / Options | Description |
| :--- | :--- | :--- |
| `krypt target add` | `<target> [--notes text]` | Register and authorize a target in scope. |
| `krypt target list` | | List all authorized targets in the database. |
| `krypt target remove` | `<target>` | Deauthorize and remove a target from scope. |
| `krypt target info` | `<target>` | Display detailed profile and history for target. |
| `krypt osint` | `<domain> [--json] [-o path]` | Aggregate all modular OSINT sources. |
| `krypt dns` | `<domain>` | Enumerate DNS records (A, AAAA, MX, NS, TXT, SOA). |
| `krypt subdomains` | `<domain>` | Discover subdomains & resolve IP addresses. |
| `krypt emails` | `<domain>` | Harvest public email indicators. |
| `krypt recon` | `<target>` | Full web recon (TLS, redirects, robots, sitemaps). |
| `krypt tech` | `<target>` | Fingerprint servers, frameworks, and CMS. |
| `krypt headers` | `<target>` | Audit security headers & cookie security flags. |
| `krypt seo` | `<target>` | Deep technical SEO audit & search rank diagnostics. |
| `krypt crawl` | `<target> [--depth] [--max-pages]` | Async BFS web crawler and link extractor. |
| `krypt endpoints` | `<target>` | View normalized discovered endpoint inventory. |
| `krypt scripts` | `<target>` | Inspect JavaScript files for API routes & params. |
| `krypt scan` | `<target> [--all] [--module name]` | Execute defensive security assessment modules. |
| `krypt findings` | `[show id] [--severity] [--target]` | Query recorded vulnerability findings. |
| `krypt evidence` | `<finding-id>` | Inspect redacted HTTP transaction proof. |
| `krypt graph` | `<target>` | Render terminal tree graph of attack surface. |
| `krypt report` | `[--format f] [--output o]` | Export reports (terminal, json, html, pdf, md, csv). |
| `krypt lab` | `<start|stop|status|verify> [--mode]` | Manage training laboratory (vulnerable or hardened). |
| `krypt plugins` | `<list|info name>` | List and inspect extensible plugin capabilities. |
| `krypt config` | `[get key] [set key val]` | View or update `~/.krypt/config.yaml`. |
| `krypt doctor` | | Run system health and environment diagnostics. |
| `krypt integrity` | `[--generate] [--json]` | Verify SHA-256 code integrity (crackproof & anti-tamper). |

---

## Target Authorization & Safety Model

KRYPT is strictly designed for:
* Systems you own
* Systems for which you have explicit written authorization
* Localhost test environments (`127.0.0.1`)
* Intentionally vulnerable training laboratories

### Fail-Closed Execution Pipeline
```
Target Registered?  ──►  Hostname Allowed?  ──►  Resolved IP Allowed?  ──►  EXECUTE
       │                        │                         │
       ▼ (NO)                   ▼ (NO)                    ▼ (NO)
   [BLOCKED]                [BLOCKED]                 [BLOCKED]
```

Unregistered external targets are blocked by default with `ScopeViolationException`.

---

## References & Attributions

KRYPT CLI draws architectural inspiration from prominent open-source security projects:
* **ARES** ([https://github.com/Mafifrizi/ARES](https://github.com/Mafifrizi/ARES)): Fail-closed scope model, modular findings.
* **theHarvester** ([https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester)): Multi-source OSINT aggregation.
* **Photon** ([https://github.com/s0md3v/Photon](https://github.com/s0md3v/Photon)): Fast BFS crawling, JS static inspection.
* **TorBot** ([https://github.com/DedSecInside/TorBot](https://github.com/DedSecInside/TorBot)): CLI-first architecture, optional SOCKS5 routing.

See `REFERENCES.md` for full attribution details.

---

## Legal & Responsible Use

KRYPT CLI is an educational and authorized security assessment framework. It is intended solely for security professionals, researchers, developers, and educators assessing systems they have explicit permission to test. Unauthorized scanning or testing of third-party systems is illegal. The author assumes no liability for misuse of this tool.
