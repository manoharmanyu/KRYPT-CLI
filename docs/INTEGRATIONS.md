# Upstream Tool Integrations Architecture & Repository Inventory

## 1. Executive Summary

KRYPT CLI integrates four specialized external open-source cybersecurity intelligence and assessment projects through a modular, isolated, fail-closed adapter architecture:

1. **theHarvester** (`laramies/theHarvester`) — OSINT reconnaissance aggregator for domains, subdomains, emails, and hosts.
2. **Photon** (`s0md3v/Photon`) — Fast, multi-threaded crawler for URL discovery, parameter extraction, scripts, and secret patterns.
3. **TorBot** (`DedSecInside/TorBot`) — Darknet (.onion) OSINT crawler and link-relationship analyzer with SOCKS5 routing.
4. **ARES** (`Mafifrizi/ARES`) — Automated Red Team Engagement System for safe prerequisite diagnostics, module capability inspection, and scope validation.

---

## 2. Repository Inventory & Provenance

All upstream repositories are maintained in the dedicated directory `integrations/vendor/` and tracked to specific, inspected commit SHAs:

| Tool | Upstream Repository | Branch | Exact Commit SHA | License | Python Runtime |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **theHarvester** | [laramies/theHarvester](https://github.com/laramies/theHarvester.git) | `master` | `6790b147f52309e4eee22ed941db1d285ab2ec23` | GPL-2.0-only | Python 3.14.7 |
| **Photon** | [s0md3v/Photon](https://github.com/s0md3v/Photon.git) | `master` | `c8d2566841d69a268b244609921143d84b72b0c6` | GPL-3.0 | Python 3.11.16 |
| **TorBot** | [DedSecInside/TorBot](https://github.com/DedSecInside/TorBot.git) | `dev` | `1cc500ff2bae6c2cce3a3accd3e55a9c69f51034` | GPL-3.0 | Python 3.12.15 |
| **ARES** | [Mafifrizi/ARES](https://github.com/Mafifrizi/ARES.git) | `main` | `3e1a9dd5137cc778b19a0aae6cd4218853f4f603` | MIT | Python 3.11.16 |

---

## 3. Runtime & Dependency Isolation

Because upstream tools possess mutually incompatible Python runtime requirements (e.g. `theHarvester` requires Python `>=3.14`, while `ARES` requires Python `>=3.10,<3.13`), dependencies are strictly isolated into project-local virtual environments inside `integrations/venvs/`:

```
integrations/
├── vendor/
│   ├── theHarvester/       (Tracked to commit 6790b14)
│   ├── Photon/             (Tracked to commit c8d2566)
│   ├── TorBot/             (Tracked to commit 1cc500f)
│   └── ARES/               (Tracked to commit 3e1a9dd)
└── venvs/
    ├── theHarvester/       (Python 3.14.7 virtualenv)
    ├── photon/             (Python 3.11.16 virtualenv)
    ├── torbot/             (Python 3.12.15 virtualenv)
    └── ares/               (Python 3.11.16 virtualenv)
```

No upstream dependencies leak into or pollute the host system Python, Homebrew Python, or KRYPT's primary runtime (`.venv`).

---

## 4. Adapter Architecture & Execution Model

The integration is managed through `krypt/integrations/`:

```
krypt/integrations/
├── models.py           # Standardized data contracts: ToolInfo, ToolFinding, ToolEvidence, AdapterResult
├── executor.py         # SubprocessExecutor: Argument arrays, timeouts, directory isolation, secret redactor
├── registry.py         # ToolRegistry: Central discovery, adapter resolution, doctor health checks
└── adapters/
    ├── __init__.py
    ├── base.py         # BaseAdapter: Abstract base class enforcing scope validation and execution contracts
    ├── harvester.py    # HarvesterAdapter: Passive OSINT + active brute-force gating
    ├── photon.py       # PhotonAdapter: Active crawl scope verification + endpoint normalization
    ├── torbot.py       # TorBotAdapter: Tor proxy reachability + dry-run verification
    └── ares.py         # ARESAdapter: Safe prerequisite doctor + module catalog inspection
```

### Key Security Guardrails:
1. **Argument Arrays Only**: All subprocesses are launched via argument arrays (`asyncio.create_subprocess_exec`). Shell string concatenation and `shell=True` are strictly prohibited.
2. **Directory Isolation & Traversal Prevention**: Each tool invocation runs inside an isolated directory (`~/.krypt/runs/<tool>_<run_id>/`). Canonical path verification ensures no directory traversal is possible.
3. **Timeout & Process Reclamation**: All executions are enforced with explicit timeouts (30s-120s) with graceful SIGTERM followed by SIGKILL process cleanup.
4. **Secret Redaction**: All captured output streams (stdout, stderr, log files) are passed through KRYPT's regex-based secret redactor before storage or display.

---

## 5. Fail-Closed Scope Enforcement

Before any active reconnaissance or security assessment is executed by an adapter, KRYPT enforces its fail-closed authorization boundary:

- **Passive OSINT Mode** (`theHarvester` default): Queries public third-party sources (e.g. crt.sh, DuckDuckGo, HackerTarget) without directly probing the target.
- **Active Scanning / Crawling Mode** (`theHarvester --active`, `Photon`, `TorBot`, `ARES`): Strictly requires the target to be registered in KRYPT's authorization database:
  ```bash
  krypt target add <target>
  ```
  Unregistered targets immediately halt execution with exit code `2` and an explicit scope violation warning.

---

## 6. CLI Command Reference

### Tool Discovery & Environment Diagnostics
```bash
# List all integrated tools, licenses, SHAs, and readiness
krypt tools list

# Run health diagnostics and smoke tests across all tool virtual environments
krypt tools doctor
```

### theHarvester
```bash
# Passive OSINT discovery (default)
krypt tools harvester example.com --sources crtsh,duckduckgo,hackertarget --limit 50

# Active DNS brute-force (strictly requires target registered in scope)
krypt tools harvester example.com --active
```

### Photon Web Crawler
```bash
# Crawl authorized web application for endpoints, parameters, and scripts
krypt tools photon http://localhost:8888 --level 2 --threads 4
```

### TorBot Darknet Intelligence
```bash
# Dry-run validation (verifies target scope and Tor proxy readiness)
krypt tools torbot http://example5wqqfdgah56trldsd.onion --dry-run

# Active .onion crawl (requires running Tor SOCKS5 daemon at 127.0.0.1:9050 or 9150)
krypt tools torbot http://example5wqqfdgah56trldsd.onion --depth 1
```

### ARES Safe Audit & Capabilities
```bash
# Run safe environment and dependency prerequisite diagnostics
krypt tools ares local_audit --action doctor

# Catalog and inspect registered security assessment modules
krypt tools ares local_audit --action modules
```

---

## 7. Rollback & Maintenance Procedures

To safely roll back or reset integrations:

1. **Rollback Git Branch**:
   ```bash
   git checkout main
   ```
2. **Remove Isolated Virtual Environments**:
   ```bash
   rm -rf integrations/venvs/
   ```
3. **Verify Host Project**:
   ```bash
   .venv/bin/pytest tests/
   ```
