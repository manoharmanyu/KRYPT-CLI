# KRYPT CLI User Guide

```
OSINT • RECON • DISCOVER • ASSESS
by Gaddam Manyu (@manoharmanyu)
```

---

## Command Reference & Walkthrough

### 1. Target Management
```bash
# Register target
krypt target add http://127.0.0.1:8888 --notes "Authorized lab environment"

# List targets
krypt target list

# Target profile and telemetry
krypt target info http://127.0.0.1:8888

# Remove target from scope
krypt target remove http://127.0.0.1:8888
```

---

### 2. OSINT Intelligence
```bash
# Run complete OSINT pipeline
krypt osint example.com

# DNS records enumeration
krypt dns example.com

# Subdomain discovery and IP resolution
krypt subdomains example.com

# Email indicator harvesting
krypt emails example.com
```

---

### 3. Web Reconnaissance & Fingerprinting
```bash
# General web recon (HTTP, TLS, headers, robots, sitemaps)
krypt recon http://127.0.0.1:8888

# Tech stack fingerprinting
krypt tech http://127.0.0.1:8888

# Security headers & cookies audit
krypt headers http://127.0.0.1:8888

# Deep technical SEO audit (metadata, OpenGraph, Twitter, headings, schema, robots, sitemap)
krypt seo http://127.0.0.1:8888
```

---

### 4. Crawling & JavaScript Analysis
```bash
# Controlled BFS crawl
krypt crawl http://127.0.0.1:8888 --depth 3 --max-pages 50 --rate 10.0

# View discovered endpoint inventory
krypt endpoints http://127.0.0.1:8888

# Static JS inspection for API routes and parameters
krypt scripts http://127.0.0.1:8888
```

---

### 5. Security Scanning & Assessments
```bash
# Run all security modules
krypt scan http://127.0.0.1:8888 --all

# Run individual modules
krypt scan http://127.0.0.1:8888 --module sqli
krypt scan http://127.0.0.1:8888 --module xss
krypt scan http://127.0.0.1:8888 --module auth
krypt scan http://127.0.0.1:8888 --module authz
krypt scan http://127.0.0.1:8888 --module idor
krypt scan http://127.0.0.1:8888 --module exposure
krypt scan http://127.0.0.1:8888 --module headers
```

---

### 6. Inspecting Findings & Evidence
```bash
# List all recorded findings
krypt findings

# Filter findings by severity
krypt findings --severity critical

# Inspect finding details
krypt findings show <FINDING_ID>

# View verifiable HTTP transaction evidence
krypt evidence <FINDING_ID>
```

---

### 7. Terminal Visualization
```bash
krypt graph http://127.0.0.1:8888
```

---

### 8. Generating Reports
```bash
# Terminal summary
krypt report --format terminal

# Structured JSON export
krypt report --format json --output results/report.json

# Modern dark-themed HTML report
krypt report --format html --output results/report.html

# Pure-Python PDF report
krypt report --format pdf --output results/report.pdf

# Markdown export
krypt report --format md --output results/report.md

# CSV findings export
krypt report --format csv --output results/report.csv
```

---

### 9. Laboratory Management
```bash
# Start local training lab (vulnerable mode for training)
krypt lab start --port 8888 --mode vulnerable

# Start production-hardened lab (zero-vulnerability / hackproof mode)
krypt lab start --port 8888 --mode hardened

# Check lab status
krypt lab status

# Run automated lab verification test suite
krypt lab verify

# Stop lab server
krypt lab stop
```

---

### 10. System Diagnostics, Anti-Tamper & Plugins
```bash
# Run system doctor (checks Python, DB, Docker, network, and cryptographic integrity)
krypt doctor

# Verify SHA-256 cryptographic framework code integrity (crackproof & anti-tamper check)
krypt integrity

# Regenerate cryptographic baseline manifest
krypt integrity --generate

# List available plugins
krypt plugins list

# Inspect module details
krypt plugins info sqli

# View / set runtime configuration
krypt config
krypt config set socks5.enabled true
```
