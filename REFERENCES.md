# Architecture References & Open-Source Attributions

KRYPT CLI synthesizes foundational architectural patterns and workflow designs inspired by prominent open-source cybersecurity frameworks. Rather than copying source code, KRYPT CLI cleanly and modernly reimplements these concepts in a unified, typed, async architecture, and integrates upstream tools via isolated virtual environments and standardized adapters.

---

### 1. theHarvester
* **Repository:** [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester)
* **Upstream Branch:** `master`
* **Pinned Commit SHA:** `6790b147f52309e4eee22ed941db1d285ab2ec23`
* **Upstream License:** GPL-2.0-only
* **Integration Module:** `krypt.integrations.adapters.harvester.HarvesterAdapter`
* **Isolated Runtime:** `integrations/venvs/theHarvester` (Python 3.14.7)
* **Architectural Inspirations & Capabilities:**
  * Multi-source OSINT intelligence aggregation (DNS, subdomains, emails, IP mappings, certificates).
  * Passive reconnaissance mode allowing broad discovery without touching target infrastructure.
  * Strict fail-closed gating for active DNS brute-forcing (`-a`).

---

### 2. Photon
* **Repository:** [https://github.com/s0md3v/Photon](https://github.com/s0md3v/Photon)
* **Upstream Branch:** `master`
* **Pinned Commit SHA:** `c8d2566841d69a268b244609921143d84b72b0c6`
* **Upstream License:** GPL-3.0
* **Integration Module:** `krypt.integrations.adapters.photon.PhotonAdapter`
* **Isolated Runtime:** `integrations/venvs/photon` (Python 3.11.16)
* **Architectural Inspirations & Capabilities:**
  * High-speed BFS web crawling with configurable depth and threads.
  * Comprehensive endpoint, query parameter, and JavaScript asset discovery.
  * Secret key regex pattern matching and external resource mapping.
  * Strict fail-closed scope check preventing crawling of unauthorized hosts.

---

### 3. TorBot
* **Repository:** [https://github.com/DedSecInside/TorBot](https://github.com/DedSecInside/TorBot)
* **Upstream Branch:** `dev`
* **Pinned Commit SHA:** `1cc500ff2bae6c2cce3a3accd3e55a9c69f51034`
* **Upstream License:** GPL-3.0
* **Integration Module:** `krypt.integrations.adapters.torbot.TorBotAdapter`
* **Isolated Runtime:** `integrations/venvs/torbot` (Python 3.12.15)
* **Architectural Inspirations & Capabilities:**
  * Terminal-first darknet (.onion) OSINT crawling and link relationship mapping.
  * Tor SOCKS5 daemon routing (default `127.0.0.1:9050` or `9150`).
  * Fail-closed reachability diagnostics and `--dry-run` simulation mode.

---

### 4. ARES
* **Repository:** [https://github.com/Mafifrizi/ARES](https://github.com/Mafifrizi/ARES)
* **Upstream Branch:** `main`
* **Pinned Commit SHA:** `3e1a9dd5137cc778b19a0aae6cd4218853f4f603`
* **Upstream License:** MIT
* **Integration Module:** `krypt.integrations.adapters.ares.ARESAdapter`
* **Isolated Runtime:** `integrations/venvs/ares` (Python 3.11.16)
* **Architectural Inspirations & Capabilities:**
  * Fail-closed target scope enforcement model.
  * Standardized module lifecycle and capability cataloging.
  * Environmental prerequisite diagnostics (`ares doctor`).
  * Structured finding schema and auditable evidence logging.

---

### Disclaimer & Attribution
KRYPT CLI is an independent, original software framework created by **Gaddam Manyu (@manoharmanyu)**. It is not directly affiliated with, sponsored by, or endorsed by the authors of the referenced projects. All upstream code remains in `integrations/vendor/` under their respective open-source licenses.
