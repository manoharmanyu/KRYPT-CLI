# KRYPT CLI Architecture Specification

## Overview

KRYPT CLI is an asynchronous, modular cybersecurity framework built on a fail-closed safety model.

```
┌─────────────────────────────────────────────────────────────┐
│                         CLI Layer                           │
│     Typer commands, Rich tables, panels, tree graphs        │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────┴──────────────────────────────┐
│                    Fail-Closed Scope Engine                 │
│ Target Registration Check ──► Hostname Check ──► IP Boundary│
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────┴──────────────────────────────┐
│                     Engines & Subsystems                    │
│ ┌────────────────┐ ┌────────────────┐ ┌───────────────────┐ │
│ │  OSINT Engine  │ │  Recon Engine  │ │  Crawler & Script │ │
│ │  (6 Adapters)  │ │(Tech & Headers)│ │(BFS Async & Regex)│ │
│ └────────────────┘ └────────────────┘ └───────────────────┘ │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │            Security Assessment Modules                  │ │
│ │    SQLi • XSS • Auth • Authz • IDOR • Exposure • Headers│ │
│ └─────────────────────────────────────────────────────────┘ │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────┴──────────────────────────────┐
│                   Storage & Evidence Layer                  │
│       SQLite Database (~/.krypt/krypt.db) & Evidence Store  │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────┴──────────────────────────────┐
│                      Reporting Engine                       │
│    Terminal • JSON • Standalone HTML • Markdown • CSV • PDF │
└─────────────────────────────────────────────────────────────┘
```

---

## 1. Safety & Scope Model (`krypt.safety.scope`)
- **Fail-Closed Principle:** No network scan packets are transmitted unless the target has been explicitly registered in the local authorization database (`~/.krypt/krypt.db`).
- **Resolution & Boundary Verification:** Hostnames are resolved to IP addresses and verified to prevent target drift or unintentional third-party testing.

---

## 2. OSINT Engine (`krypt.osint.engine`)
- **Data Flow:** `BaseSource.collect()` ──► `BaseSource.normalize()` ──► `Deduplicator` ──► `db.add_intelligence()` ──► `IntelReport`.
- **Sources Included:**
  * `DNSSource`: A, AAAA, MX, NS, TXT, CNAME, SOA queries via `dnspython`.
  * `CrtshSource`: Certificate Transparency subdomain log queries.
  * `SubdomainSource`: Active DNS name checks & IP resolution.
  * `EmailSource`: Public email indicators via DNS TXT records, security.txt, and web text.
  * `CertificateSource`: Live TLS/SSL socket handshakes, SANs, and issuer parsing.
  * `PublicRecordsSource`: RDAP registration info and robots.txt disclosures.

---

## 3. Crawler & Static JS Inspection (`krypt.crawler`)
- **Queue-Based BFS Crawl:** Asynchronous concurrent task workers consuming from an `asyncio.Queue` bounded by `--depth` and `--max-pages`.
- **Static JS Analyzer:** Extracts API routes, endpoint paths, parameter names, and public configuration strings without running a headless browser.

---

## 4. Security Modules (`krypt.modules`)
- Every module adheres to `BaseModule`:
  * `name`: Module identifier.
  * `description`: Assessment scope.
  * `check_scope()`: Authorization check.
  * `run()`: Controlled probe execution.
  * `findings()`: Standardized `FindingModel` collection.
- Payloads are strictly defensive, controlled, and non-destructive.

---

## 5. Evidence Store & Redaction (`krypt.evidence`)
- Every finding captures request/response metadata, timestamps, and observations.
- All credentials (passwords, bearer tokens, API keys, cookies, basic auth) are automatically masked via regex patterns in `krypt.evidence.redactor`.
