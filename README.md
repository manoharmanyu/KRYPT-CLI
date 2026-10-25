# KRYPT CLI

<div align="center">

```text
██╗  ██╗██████╗ ██╗   ██╗██████╗ ████████╗
██║ ██╔╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝
█████╔╝ ██████╔╝ ╚████╔╝ ██████╔╝   ██║
██╔═██╗ ██╔══██╗  ╚╔╝    ██╔═══╝    ██║
██║  ██╗██║  ██║   ██║   ██║        ██║
╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝
```

### OSINT · Reconnaissance · Web Discovery · Authorized Security Assessment

**A terminal-first, modular cybersecurity toolkit with evidence-driven reporting and scope-aware execution.**

[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-informational)](#installation)
[![License](https://img.shields.io/badge/license-MIT-green)](#legal--responsible-use)
[![Security](https://img.shields.io/badge/defaults-scope--aware%20%7C%20fail--closed-success)](#target-authorization--safe-operation)

**Author:** [Gaddam Manyu](https://github.com/manoharmanyu) · **Repository:** [manoharmanyu/KRYPT-CLI](https://github.com/manoharmanyu/KRYPT-CLI)

</div>

---

## Overview

**KRYPT CLI** is a terminal-driven framework for OSINT, web reconnaissance, crawling, endpoint discovery, defensive web-security checks, evidence collection, and reporting.

KRYPT brings its native capabilities together with isolated adapters for four open-source projects:

- **theHarvester** — Public-source intelligence gathering.
- **Photon** — Web crawling and data extraction.
- **TorBot** — Optional onion-service OSINT workflows.
- **ARES** — Authorized red-team readiness and orchestration workflows, subject to its own controls.

The integration layer preserves upstream projects as separate components while exposing consistent KRYPT commands, diagnostics, scope checks, structured run results, and output handling.

> **Authorization required:** Use KRYPT only on systems you own, local training environments, or systems for which you have explicit permission. Scope registration is an application control, not a substitute for legal authorization.

## Highlights

- **Scope-aware execution:** Active actions should fail closed when the target is not registered and permitted by policy.
- **Modular integrations:** Upstream tools remain separate and can be diagnosed independently.
- **Runtime isolation:** Per-tool Python environments reduce dependency conflicts.
- **Controlled subprocess execution:** Argument arrays, timeouts, and process cleanup.
- **Normalized results:** Run IDs, status, timing, findings, evidence references, errors, and output paths.
- **Evidence-first reporting:** Structured results and redacted logs help make assessments reproducible.
- **CLI diagnostics:** Inspect the health of the core CLI and upstream integrations.
- **Multiple report formats:** Terminal, JSON, HTML, Markdown, CSV, and PDF where supported.
- **Local training support:** Use the built-in lab when available to validate functionality without targeting external systems.

## Architecture

```text
                         KRYPT CLI
                             |
                   Command / Policy Layer
                             |
              +--------------+--------------+
              |              |              |
           Native          Adapters       Diagnostics
           modules            |
                    +--------+--------+---------+
                    |        |        |         |
                theHarvester Photon  TorBot     ARES
                    |        |        |         |
                    +--------+--------+---------+
                             |
                      Scope / Run Controls
                             |
                  Normalized Run & Evidence
                             |
                    Results / Reporting
```

The adapters normalize invocation and results; they do not assume that the four upstream applications have identical dependencies, licensing, or runtime requirements.

## Repository layout

The integration implementation is organized around the existing project architecture. Confirm the exact paths in your checkout.

```text
krypt-cli/
├── krypt/
│   └── integrations/
│       ├── executor.py
│       ├── adapters/
│       └── models.py
├── integrations/
│   ├── vendor/
│   └── venvs/
├── tests/
├── docs/
│   └── INTEGRATIONS.md
├── REFERENCES.md
├── requirements.txt
├── install.sh
└── README.md
```

Do not commit generated virtual environments, API credentials, scan output, caches, or other machine-specific data unless explicitly required and documented.

## Installation

### 1. Clone KRYPT CLI

```bash
git clone https://github.com/manoharmanyu/KRYPT-CLI.git
cd KRYPT-CLI
```

### 2. Install

For macOS or Linux:

```bash
chmod +x install.sh
./install.sh
```

Alternatively, use a project-local virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .
```

### 3. Verify the installation

```bash
krypt --help
krypt doctor
krypt tools list
krypt tools doctor
```

Depending on your installation and shell configuration, the `krypto` alias may also be available:

```bash
krypto --help
krypto tools list
```

If a command is not found, activate the intended environment and verify that installation completed successfully.

For integration-specific setup and compatibility, see [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md).

## Upstream integrations

| Tool | Purpose | Upstream license* | Runtime strategy |
|---|---|---|---|
| [theHarvester](https://github.com/laramies/theHarvester) | Public-source OSINT and domain intelligence | GPL-2.0-only | Isolated Python environment |
| [Photon](https://github.com/s0md3v/Photon) | Web crawling and data extraction | GPL-3.0 | Isolated Python environment |
| [TorBot](https://github.com/DedSecInside/TorBot) | Onion-service OSINT and link mapping | Verify exact upstream snapshot | Isolated Python environment; optional Tor service |
| [ARES](https://github.com/Mafifrizi/ARES) | Authorized red-team readiness and orchestration | MIT | Isolated Python environment |

\*Check the license file at each pinned upstream revision before redistributing source or binaries.

### Reported upstream revisions

The integration report records these revisions. Verify the actual checked-out commit IDs with `git rev-parse HEAD` before relying on them.

| Component | Branch | Reported commit |
|---|---|---|
| theHarvester | `master` | `6790b147f52309e4eee22ed941db1d285ab2ec23` |
| Photon | `master` | `c8d2566841d69a268b244609921143d84b72b0c6` |
| TorBot | `dev` | `1cc500ff2bae6c2cce3a3accd3e55a9c69f51034` |
| ARES | `main` | `3e1a9dd5137cc778b19a0aae6cd4218853f4f603` |

Read the upstream license files and [REFERENCES.md](REFERENCES.md) before redistributing integrated software. Keep required notices and attribution.

## CLI quick start

Start with diagnostics:

```bash
krypt doctor
krypt tools list
krypt tools doctor
```

Use each command's `--help` option to confirm the options supported by your installed version.

### 1. Passive OSINT with theHarvester

```bash
krypt tools harvester example.com --sources crtsh,duckduckgo,hackertarget --limit 50
```

Use a domain you own or are authorized to assess. Providers may receive the query even when the selected source does not contact the target directly. Some data sources require API credentials.

### 2. Crawling with Photon

Register an authorized test target:

```bash
krypt target add http://127.0.0.1:8888 --notes "Local training lab"
krypt target list
```

Run a bounded crawl:

```bash
krypt tools photon http://127.0.0.1:8888 --level 2 --threads 4
```

Use conservative depth, concurrency, and page limits. Review crawl results before taking any additional actions.

### 3. TorBot

Check the available options first:

```bash
krypt tools torbot --help
```

Example dry run:

```bash
krypt tools torbot http://example.onion --dry-run
```

Live onion-service use is opt-in and requires the intended Tor/SOCKS5 configuration, authorization, and scope. Do not assume Tor is installed or running merely because TorBot is present.

### 4. ARES readiness checks

```bash
krypt tools ares --help
krypt tools ares local_audit --action doctor
krypt tools ares local_audit --action modules
```

Begin with readiness checks, configuration review, module inventory, and scope validation. Do not launch active red-team modules without an authorized engagement and explicit operator action.

### 5. Native KRYPT features

```bash
krypt target list
krypt doctor
krypt lab status
krypt findings
krypt report --format json --output report.json
```

Use only commands and options supported by the installed version. The built-in lab is the preferred place to exercise security-check workflows.

## Target authorization & safe operation

KRYPT is intended for:

- Systems you own.
- Systems for which you have explicit written authorization.
- Localhost test targets.
- Intentionally vulnerable training environments.

### Fail-closed execution model

```text
Target provided
      |
Target registered?
   | yes     | no
   v         v
Policy and   Block
scope checks
      |
Resolved destination in scope?
   | yes     | no
   v         v
Execute      Block
      |
Bounded run + evidence capture + redacted reporting
```

Important safeguards:

- Register targets deliberately with `krypt target add`.
- Keep crawler depth, concurrency, request rates, and execution time bounded.
- Validate redirect destinations and resolved IP addresses, not only the original URL.
- Treat discovered URLs, scripts, file paths, and secrets as untrusted input.
- Do not execute discovered JavaScript, downloaded files, or extracted tokens.
- Do not bypass authentication, access controls, rate limits, or scope restrictions.
- Keep active red-team functionality separate from routine diagnostics.
- Review output before sharing it, as reports may contain sensitive target information.

A registered target is a local policy signal, not proof of authorization.

## Runtime architecture

Upstream projects have different Python requirements and dependency graphs. KRYPT uses isolated environments under `integrations/venvs/` so their dependencies do not have to coexist in the main KRYPT environment.

Diagnose missing interpreters or dependencies with:

```bash
krypt tools doctor
```

Do not assume one tool's environment can satisfy all the other integrations. Follow the setup instructions for the pinned upstream revision. Keep local environments, caches, generated data, and credentials out of Git.

## Results and reporting

The normalized integration result is intended to preserve, where available:

- Tool name and run ID.
- Start and completion timestamps.
- Target and declared scope.
- Status and partial-completion information.
- Structured findings and evidence references.
- Errors and output artifact paths.

Example report commands:

```bash
krypt report --format terminal
krypt report --format json --output report.json
krypt report --format html --output report.html
krypt report --format md --output report.md
```

Confirm supported formats with `krypt report --help`.

Store assessment output securely, redact sensitive data, and avoid committing results to a public repository.

## Development & testing

Create a development environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -e .
```

Run the test suite:

```bash
python -m pytest
```

Run diagnostics and integrity checks:

```bash
krypt doctor
krypt tools doctor
krypt integrity
```

The integration report previously supplied for this repository reported 48 passing tests and a SHA-256 baseline for source integrity. These are historical reported results, not a guarantee for every checkout or environment. Re-run tests after changes and record actual results before publishing a release.

## Troubleshooting

### `krypt` or `krypto` is not found

- Activate the intended virtual environment.
- Confirm that `pip install -e .` completed.
- Inspect the installed console-script entry points.

### An integration is unhealthy

- Run `krypt tools doctor`.
- Confirm the expected interpreter and executable path.
- Review [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md).

### An API source fails

- Confirm the API key is configured through the supported secret mechanism.
- Check provider limits and network availability.
- Never paste credentials into public issues or reports.

### A target is blocked

- Check `krypt target list`.
- Verify the scheme, hostname, port, and permitted destination addresses.
- Do not disable scope enforcement to bypass a block.

### Tests or installation fail

- Record the exact command, interpreter, package versions, and error.
- Keep every upstream runtime isolated.
- Do not delete environments or reset the Git tree before preserving local changes and useful logs.

## Upstream references & attribution

KRYPT CLI includes or integrates with:

- [theHarvester](https://github.com/laramies/theHarvester)
- [Photon](https://github.com/s0md3v/Photon)
- [TorBot](https://github.com/DedSecInside/TorBot)
- [ARES](https://github.com/Mafifrizi/ARES)

See [REFERENCES.md](REFERENCES.md) and [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md) for fuller attribution, pinned versions, setup instructions, compatibility, and integration controls.

Retain all notices required by upstream licenses.

## Legal & responsible use

KRYPT CLI is intended for education, defensive engineering, and authorized security assessment. You are responsible for obtaining permission before testing any system and for complying with applicable laws, contracts, provider terms, and upstream licenses.

Do not use the tool to access systems, data, accounts, or services without authorization. Do not upload sensitive findings or credentials to public repositories. Review scope, impact, and output before executing active assessment workflows.

---

<div align="center">

**KRYPT CLI — Scope-aware security work, structured evidence, and reproducible workflows.**

[Repository](https://github.com/manoharmanyu/KRYPT-CLI) · [Issues](https://github.com/manoharmanyu/KRYPT-CLI/issues)

</div>
