# Architecture References & Open-Source Attributions

KRYPT CLI synthesizes foundational architectural patterns and workflow designs inspired by prominent open-source cybersecurity frameworks. Rather than copying source code, KRYPT CLI cleanly and modernly reimplements these concepts in a unified, typed, async Python 3.11+ architecture.

---

### 1. ARES
* **Repository:** [https://github.com/Mafifrizi/ARES](https://github.com/Mafifrizi/ARES)
* **Architectural Inspirations:**
  * **Fail-Closed Target Scope Enforcement:** Implemented in `krypt.safety.scope` to guarantee that no active assessment packets reach unauthorized destinations.
  * **Modular Security Modules:** Standardized module lifecycle (`name()`, `description()`, `check_scope()`, `run()`, `findings()`) across `krypt/modules/`.
  * **Structured Findings & Evidence Trail:** Decoupled finding schemas containing verifiable, redacted HTTP request/response proofs.
  * **Professional Terminal Output:** Clean, informative terminal logging and execution statuses.

---

### 2. theHarvester
* **Repository:** [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester)
* **Architectural Inspirations:**
  * **Multi-Source OSINT Aggregation:** Pluggable source adapters (`BaseSource`) feeding into an ingestion pipeline.
  * **Domain & Email Intelligence:** Modular extractors for DNS records (A, AAAA, MX, NS, TXT, SOA), Certificate Transparency (crt.sh), and public email indicators.
  * **Result Normalization & Deduplication:** Standardized entity schemas (`IntelReport`) to deduplicate cross-source findings before storage.

---

### 3. Photon
* **Repository:** [https://github.com/s0md3v/Photon](https://github.com/s0md3v/Photon)
* **Architectural Inspirations:**
  * **Controlled BFS Web Crawling:** Fast asynchronous crawler (`krypt.crawler.crawler`) parsing links, forms, parameters, scripts, and endpoints.
  * **Static JavaScript Inspection:** Analyzing JavaScript code for API routes, parameter names, URL patterns, and public environment variables without browser overhead.
  * **Target Surface Discovery:** Automated extraction of `robots.txt`, `sitemap.xml`, and form input parameters.

---

### 4. TorBot
* **Repository:** [https://github.com/DedSecInside/TorBot](https://github.com/DedSecInside/TorBot)
* **Architectural Inspirations:**
  * **100% Terminal-First Design:** Complete operation from CLI commands without requiring web dashboards or desktop GUIs.
  * **Optional SOCKS5 / Tor Routing:** Configurable SOCKS5 proxying (`socks5.enabled`) with clear terminal status indicators.
  * **Terminal Visualization & Link Relationships:** Terminal graph and tree rendering (`krypt graph`) for target hierarchy and discovered attack surfaces.
  * **Graceful Network Fault Tolerance:** Resilient async request handling with strict rate-limiting.

---

### Disclaimer & Attribution
KRYPT CLI is an independent, original software framework created by **Gaddam Manyu (@manoharmanyu)**. It is not directly affiliated with, sponsored by, or endorsed by the authors of the referenced projects. All intellectual property and trademarks of referenced projects belong to their respective owners.
