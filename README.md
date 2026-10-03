# 🔐 KRYPT CLI

### OSINT • RECON • DISCOVER • ASSESS

> **KRYPT CLI** is a terminal-only cybersecurity intelligence and authorized web-security assessment framework built for security researchers, penetration testers, students, and authorized testing environments.
[![Tests](https://img.shields.io/badge/Tests-37%20Passing-brightgreen.svg)](#testing)
[![Security](https://img.shields.io/badge/Security-Authorized%20Testing-red.svg)](#-responsible-use)
---

# KRYPT CLI

```text
██╗  ██╗██████╗ ██╗   ██╗██████╗ ████████╗
██║ ██╔╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝
█████╔╝ ██████╔╝ ╚████╔╝ ██████╔╝   ██║
██╔═██╗ ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║
██║  ██╗██║  ██║   ██║   ██║        ██║
╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝
```

# 🔐 KRYPT CLI

### OSINT • RECON • DISCOVER • ASSESS

**Terminal-First Cybersecurity Intelligence & Authorized Web Security Assessment Framework**

[![Version](https://img.shields.io/badge/version-0.1.0-00D9FF?style=for-the-badge)](#)
[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge\&logo=python\&logoColor=white)](#)
[![Interface](https://img.shields.io/badge/Interface-Terminal-111111?style=for-the-badge\&logo=gnubash\&logoColor=white)](#)
[![Security](https://img.shields.io/badge/Security-Fail--Closed-22C55E?style=for-the-badge)](#security-model)
[![Tests](https://img.shields.io/badge/Tests-37%20Passing-22C55E?style=for-the-badge)](#testing)
[![License](https://img.shields.io/badge/License-MIT-2563EB?style=for-the-badge)](LICENSE)

---

## ⚡ Executive Summary

**KRYPT CLI** is a terminal-only cybersecurity framework created by **Gaddam Manyu (@manoharmanyu)** for authorized security research, reconnaissance, OSINT collection, controlled vulnerability assessment, evidence management, and professional reporting.

KRYPT combines:

* OSINT intelligence
* Domain reconnaissance
* DNS intelligence
* Subdomain discovery
* Web crawling
* JavaScript analysis
* Endpoint discovery
* Technology fingerprinting
* Security-header analysis
* Controlled vulnerability detection
* Evidence collection
* Technical SEO auditing
* Application hardening validation
* Cryptographic code-integrity verification
* Multi-format reporting

Everything is controlled through a single CLI:

```bash
krypt <command> [options]
```

**No dashboard.
No website.
No desktop GUI.
No browser interface.**

KRYPT is intentionally designed around a terminal-first workflow.

---

# 🎯 Why KRYPT?

Modern security workflows often require operators to switch between multiple disconnected tools for:

```text
OSINT
   ↓
DNS
   ↓
Recon
   ↓
Crawler
   ↓
Endpoints
   ↓
Technology Detection
   ↓
Security Analysis
   ↓
Evidence
   ↓
Findings
   ↓
Reports
```

KRYPT brings these workflows together under one controlled command-line architecture.

---

# 🧠 Core Design Principles

```text
┌──────────────────────┐
│   FAIL-CLOSED        │
│   SCOPE ENFORCEMENT  │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│   RECON & OSINT      │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│   DISCOVERY          │
│   CRAWL / ENDPOINTS  │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ CONTROLLED SECURITY  │
│     ASSESSMENT       │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ EVIDENCE & FINDINGS  │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│     REPORTING        │
└──────────────────────┘
```

### Core principles

**Scope First**

Every active request must be validated against the registered target scope.

**Fail Closed**

If scope validation fails, the request is blocked.

**Evidence First**

Security findings must be backed by observable evidence.

**Terminal First**

All functionality is accessible through the CLI.

**Authorized Testing**

Active testing is restricted to systems the operator is authorized to assess.

---

# 🛡️ Security Model

KRYPT implements a hard authorization boundary.

Before active testing:

```bash
krypt target add <target>
```

Execution pipeline:

```text
TARGET
   │
   ▼
REGISTERED?
   │
   ▼
HOSTNAME ALLOWED?
   │
   ▼
RESOLVED IP ALLOWED?
   │
   ▼
DESTINATION ALLOWED?
   │
   ▼
EXECUTE
```

If any validation fails:

```text
╭────────────────────────────────╮
│        REQUEST BLOCKED          │
│                                │
│ Target is outside registered   │
│ authorization scope.           │
╰────────────────────────────────╯
```

KRYPT never silently continues outside scope.

---

# 🔎 OSINT Intelligence Engine

```bash
krypt osint example.com
```

The OSINT engine uses modular source adapters.

```text
Source
   ↓
Collector
   ↓
Normalizer
   ↓
Deduplicator
   ↓
Evidence Store
   ↓
Intelligence Report
```

Supported intelligence categories:

| Category    | Information              |
| ----------- | ------------------------ |
| Domain      | Domain information       |
| Subdomain   | Discovered hosts         |
| Host        | Hostname intelligence    |
| IP          | Resolved addresses       |
| Email       | Public email indicators  |
| URL         | Discovered URLs          |
| DNS         | DNS records              |
| Certificate | Certificate intelligence |
| Technology  | Technology fingerprints  |
| Metadata    | Public metadata          |

---

# 🌐 DNS Intelligence

```bash
krypt dns example.com
```

Supported records:

```text
A
AAAA
MX
NS
TXT
CNAME
SOA
```

---

# 🌎 Subdomain Discovery

```bash
krypt subdomains example.com
```

Example:

```text
example.com
├── www.example.com
├── api.example.com
├── dev.example.com
└── mail.example.com
```

Results contain:

```text
Hostname
Source
First Seen
Last Seen
Resolved IP
Status
```

---

# 📧 Email Intelligence

```bash
krypt emails example.com
```

KRYPT collects publicly available email indicators through supported sources.

Credentials are never verified or harvested.

---

# 🔬 Web Reconnaissance

```bash
krypt recon https://authorized.example
```

Reconnaissance includes:

```text
HTTP Status
HTTPS
Redirects
TLS Information
HTTP Headers
Server Information
robots.txt
sitemap.xml
Page Metadata
Technology Detection
```

---

# 🧠 Technology Fingerprinting

```bash
krypt tech https://authorized.example
```

KRYPT can identify technologies such as:

```text
Nginx
Apache
IIS
Node.js
Express
PHP
Laravel
Django
Flask
React
Next.js
WordPress
Drupal
CDN / WAF indicators
```

Example:

```text
╭──────────────── Technology Detection ────────────────╮
│ Technology     Confidence     Evidence               │
├──────────────────────────────────────────────────────┤
│ Nginx          HIGH            Server Header          │
│ React          MEDIUM          Script Fingerprint     │
│ Next.js        HIGH            Framework Marker       │
│ Cloudflare     HIGH            Response Headers       │
╰──────────────────────────────────────────────────────╯
```

---

# 🕷️ Controlled Web Crawler

```bash
krypt crawl https://authorized.example
```

Options:

```bash
--depth
--max-pages
--rate
--threads
--timeout
--same-origin
--json
```

The crawler discovers:

```text
Links
Forms
Parameters
Scripts
APIs
Endpoints
Redirects
robots.txt
sitemap.xml
```

Crawler pipeline:

```text
URL
 │
 ▼
Scope Check
 │
 ▼
HTTP Client
 │
 ▼
Parser
 │
 ├── Links
 ├── Forms
 ├── Scripts
 ├── Parameters
 └── Endpoints
 │
 ▼
Deduplication
 │
 ▼
Evidence Store
```

---

# 📜 JavaScript Analysis

```bash
krypt scripts https://authorized.example
```

Analyzes JavaScript for:

```text
Endpoint References
API Paths
URL Patterns
Parameter Names
Public Configuration
Non-secret Environment Indicators
```

Sensitive information is redacted.

---

# 🔗 Endpoint Discovery

```bash
krypt endpoints https://authorized.example
```

Example:

```text
GET     /api/users
POST    /api/login
GET     /api/products?id=
GET     /api/profile
POST    /api/orders
```

Endpoint records contain:

```text
Method
URL
Parameters
Content Type
Discovery Source
Confidence
```

---

# 🛡️ Security Header Engine

```bash
krypt headers https://authorized.example
```

Analyzes:

```text
Content-Security-Policy
Strict-Transport-Security
X-Frame-Options
X-Content-Type-Options
Referrer-Policy
Permissions-Policy
```

Cookie controls:

```text
Secure
HttpOnly
SameSite
```

---

# 🔥 Controlled Vulnerability Assessment

Run the complete assessment:

```bash
krypt scan <target> --all
```

Available modules:

```text
sqli
xss
auth
authz
idor
exposure
headers
```

Individual module:

```bash
krypt scan <target> --module sqli
krypt scan <target> --module xss
krypt scan <target> --module auth
krypt scan <target> --module authz
krypt scan <target> --module idor
krypt scan <target> --module exposure
```

---

# 💉 SQL Injection Detection

KRYPT performs controlled SQL injection detection.

```text
Candidate Parameter
        │
        ▼
Controlled Validation
        │
        ▼
Response Comparison
        │
        ▼
Error / Behavior Analysis
        │
        ▼
Confidence
        │
        ▼
Evidence
        │
        ▼
Finding
```

KRYPT does not implement:

```text
Database dumping
Destructive SQL
Arbitrary record modification
Credential extraction
```

---

# 🧪 XSS Detection

```bash
krypt scan <target> --module xss
```

Detects:

```text
Reflected XSS
Potential Stored XSS
Reflection Points
Context
Encoding Behavior
```

Validation uses harmless markers.

---

# 🔐 Authentication Analysis

KRYPT can analyze authorized applications for:

```text
Session weaknesses
Cookie security
Authentication-state inconsistencies
Reset-flow weaknesses
Missing rate limiting
```

Laboratory identities can be used for controlled testing.

---

# 🚪 Authorization / IDOR

Example laboratory workflow:

```text
USER_TEST
   │
   ├── Own Resource
   │      └── EXPECTED: ALLOWED
   │
   └── Other Test User
          └── EXPECTED: DENIED
```

Unexpected access can generate:

```text
[HIGH] BROKEN ACCESS CONTROL / IDOR
```

Administrative endpoints are evaluated as authorization boundaries.

---

# 📊 Findings Engine

List findings:

```bash
krypt findings
```

Show finding:

```bash
krypt findings show <id>
```

Filter:

```bash
krypt findings --severity critical
```

Target filter:

```bash
krypt findings --target <target>
```

Finding model:

```text
ID
Target
Module
Vulnerability
Severity
Confidence
Endpoint
Parameter
Evidence
Impact
Remediation
References
Timestamp
```

Severity:

```text
CRITICAL
HIGH
MEDIUM
LOW
INFO
```

---

# 🧾 Evidence Library

KRYPT follows an evidence-first architecture.

Evidence may contain:

```text
Request Metadata
Response Metadata
Relevant Headers
Status Code
Timing Observations
Discovery Source
Crawler Source
```

Sensitive values are redacted:

```text
Passwords
API Keys
Bearer Tokens
Cookies
Session IDs
Authorization Headers
```

---

# 🚀 Technical SEO Engine

KRYPT also provides a technical SEO audit engine.

```bash
krypt seo https://authorized.example
```

The engine checks:

```text
Title Tag
Meta Description
Canonical URL
Viewport
Robots Meta
OpenGraph
Twitter Cards
H1
H2
Schema.org / JSON-LD
Image Alt Text
robots.txt
sitemap.xml
```

Example:

```text
╭──────────────────── SEO Technical Audit ────────────────────╮
│ Target:          http://127.0.0.1:8888                    │
│ SEO Score:       100%                                      │
│ Grade:           A+                                        │
│ Canonical:       http://127.0.0.1:8888/                  │
│ Sitemap:         DETECTED                                  │
│ Structured Data: YES                                       │
╰────────────────────────────────────────────────────────────╯
```

---

# 🧱 Hardened Laboratory

KRYPT provides isolated vulnerable and hardened environments.

Start hardened mode:

```bash
krypt lab start --mode hardened
```

The laboratory supports validation of:

```text
SQL Injection
XSS
IDOR
Broken Access Control
Authentication
Insecure Cookies
Security Headers
Information Exposure
```

Hardened protections include:

```text
Parameterized SQL Queries
Context-Aware Escaping
Content Security Policy
Role-Based Access Control
Password Hashing
Constant-Time Verification
Rate Limiting
Secure Cookies
Security Headers
Sensitive Path Protection
```

---

# 🔐 Cryptographic Integrity Engine

KRYPT includes a source-code integrity subsystem.

Verify:

```bash
krypt integrity
```

Generate baseline:

```bash
krypt integrity --generate
```

Integrity pipeline:

```text
Python Source Files
        │
        ▼
SHA-256 Digests
        │
        ▼
File Signatures
        │
        ▼
Master Verification Hash
        │
        ▼
Tamper Detection
```

Detects:

```text
Modified Files
Missing Modules
Unexpected Files
Injected Scripts
```

---

# 🩺 KRYPT Doctor

Run complete diagnostics:

```bash
krypt doctor
```

Checks:

```text
Python
Dependencies
SQLite
Docker
Configuration
Network
Permissions
Laboratory
Code Integrity
```

---

# 🎯 Target Management

Add:

```bash
krypt target add https://authorized.example
```

List:

```bash
krypt target list
```

Information:

```bash
krypt target info https://authorized.example
```

Remove:

```bash
krypt target remove https://authorized.example
```

---

# 🧅 Optional SOCKS5 Support

Enable:

```bash
krypt config set socks5.enabled true
```

Default:

```text
127.0.0.1:9050
```

KRYPT does not claim anonymity merely because SOCKS5/Tor is enabled.

---

# 📄 Reporting Engine

Generate terminal report:

```bash
krypt report --format terminal
```

JSON:

```bash
krypt report --format json
```

HTML:

```bash
krypt report --format html
```

PDF:

```bash
krypt report --format pdf
```

Reports include:

```text
Executive Summary
Scope
Methodology
Findings
Severity
Confidence
Evidence
Impact
Remediation
Technical Details
Timestamp
```

---

# 🌳 Terminal Intelligence Graph

```bash
krypt graph example.com
```

Example:

```text
example.com
├── www.example.com
│   ├── /login
│   ├── /api
│   └── /assets
│
├── api.example.com
│   ├── /v1
│   └── /v2
│
└── dev.example.com
    └── /test
```

KRYPT remains completely terminal-based.

---

# 🔌 Plugin Architecture

```bash
krypt plugins list
```

Inspect:

```bash
krypt plugins info <module>
```

Plugin categories:

```text
OSINT
├── DNS
├── Subdomains
├── Emails
└── Certificates

WEB
├── Crawler
├── Endpoints
├── Headers
└── Technology

SECURITY
├── SQLi
├── XSS
├── Auth
├── AuthZ
└── IDOR
```

---

# ⚙️ Configuration

Configuration:

```text
~/.krypt/config.yaml
```

Example:

```yaml
request:
  timeout: 10
  rate_limit: 5
  user_agent: "KRYPT-CLI/0.1"

crawler:
  max_depth: 3
  max_pages: 500
  threads: 5

socks5:
  enabled: false
  host: 127.0.0.1
  port: 9050

safety:
  require_registered_target: true
  lab_mode: false
```

---

# 🚀 Quickstart

## Requirements

```text
Python 3.11+
SQLite
Docker
Git
```

## Installation

```bash
git clone https://github.com/manoharmanyu/krypt-cli.git
cd krypt-cli

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -e .
```

Run:

```bash
krypt doctor
```

---

# ⚡ First Run

```bash
krypt --version
```

```bash
krypt --help
```

Start laboratory:

```bash
krypt lab start
```

Verify:

```bash
krypt lab verify
```

Register local target:

```bash
krypt target add http://127.0.0.1:8888
```

Recon:

```bash
krypt recon http://127.0.0.1:8888
```

Crawl:

```bash
krypt crawl http://127.0.0.1:8888
```

Scan:

```bash
krypt scan http://127.0.0.1:8888 --all
```

Findings:

```bash
krypt findings
```

Report:

```bash
krypt report --format html
```

Stop laboratory:

```bash
krypt lab stop
```

---

# 🧪 Testing

Run:

```bash
pytest -v
```

Current verification:

```text
37 tests
37 passed
100% pass rate
```

Test coverage includes:

```text
CLI
Crawler
DNS
Evidence Redaction
Hardened Application
Integrity
Security Modules
Reporting
Scope
SEO
Technology Detection
```

Example:

```text
============================= 37 passed =============================
```

---

# 🏗️ System Architecture

```text
                         ┌─────────────────┐
                         │    KRYPT CLI    │
                         └────────┬────────┘
                                  │
             ┌────────────────────┼────────────────────┐
             │                    │                    │
             ▼                    ▼                    ▼
        ┌─────────┐         ┌─────────┐         ┌──────────┐
        │  OSINT  │         │  RECON  │         │ SECURITY │
        └────┬────┘         └────┬────┘         └────┬─────┘
             │                   │                   │
             ▼                   ▼                   ▼
        DNS / Email         Crawler / Tech       SQLi / XSS
        Subdomains          Endpoints / Headers  Auth / IDOR
             │                   │                   │
             └───────────────────┼───────────────────┘
                                 ▼
                        ┌─────────────────┐
                        │  SCOPE ENGINE   │
                        └────────┬────────┘
                                 │
                                 ▼
                        ┌─────────────────┐
                        │ EVIDENCE STORE  │
                        └────────┬────────┘
                                 │
                                 ▼
                        ┌─────────────────┐
                        │  FINDINGS DB    │
                        └────────┬────────┘
                                 │
                                 ▼
                        ┌─────────────────┐
                        │ REPORT ENGINE   │
                        └───────┬─────────┘
                                │
                    ┌───────────┼───────────┐
                    ▼           ▼           ▼
                   JSON        HTML         PDF
```

---

# 📁 Project Structure

```text
krypt-cli/
│
├── krypt/
│   ├── __init__.py
│   ├── __main__.py
│   │
│   ├── cli/
│   ├── core/
│   ├── safety/
│   ├── osint/
│   ├── recon/
│   ├── crawler/
│   ├── modules/
│   ├── database/
│   ├── evidence/
│   ├── reporting/
│   ├── plugins/
│   └── utils/
│
├── lab/
├── tests/
├── docs/
├── scripts/
├── reports/
│
├── AUTHORS.md
├── REFERENCES.md
├── LICENSE
├── README.md
├── pyproject.toml
├── requirements.txt
└── Makefile
```

---
KRYPT CLI is not affiliated with these projects.

Detailed attribution is available in:

```text
REFERENCES.md
```

---

# 🧩 Technology Stack

```text
Python 3.11+
Typer
Rich
httpx
dnspython
BeautifulSoup4
SQLAlchemy
Pydantic
PyYAML
SQLite
Docker
```

---

# 🛡️ Responsible Use & Legal Notice

KRYPT CLI is intended for:

* Authorized penetration testing
* Security research
* Defensive security validation
* Local security laboratories
* Systems owned or explicitly authorized for testing

Do not run active security testing against systems without authorization.

The user is responsible for complying with applicable laws, regulations, policies, and authorization requirements.

---

# 👨‍💻 Author

## Gaddam Manyu

**Creator & Developer**

GitHub:

**[@manoharmanyu](https://github.com/manoharmanyu)**

Project:

**KRYPT CLI**

Tagline:

> **OSINT • RECON • DISCOVER • ASSESS**

---

# 📜 License

KRYPT CLI is distributed under the license included in:

```text
LICENSE
```

---

# ⭐ KRYPT CLI

```text
██╗  ██╗██████╗ ██╗   ██╗██████╗ ████████╗
██║ ██╔╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝
█████╔╝ ██████╔╝ ╚████╔╝ ██████╔╝   ██║
██╔═██╗ ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║
██║  ██╗██║  ██║   ██║   ██║        ██║
╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝

          OSINT • RECON • DISCOVER • ASSESS

             Created by Gaddam Manyu
                  @manoharmanyu
```

**Terminal-native. Evidence-driven. Scope-controlled.**

```bash
krypt --help
```
