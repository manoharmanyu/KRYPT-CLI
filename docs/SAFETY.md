# KRYPT CLI Safety & Authorization Model

KRYPT CLI is engineered strictly for authorized security assessments, defensive engineering, and educational training.

---

## 1. Fail-Closed Target Scope Enforcement

* **Hard Boundary:** Active assessment modules will refuse to execute against any target unless that target is explicitly registered in the authorized target scope database.
* **Pre-Flight Pipeline:**
  ```
  Target Registered?  ──►  Hostname Allowed?  ──►  Resolved IP Allowed?  ──►  EXECUTE
         │                        │                         │
         ▼ (NO)                   ▼ (NO)                    ▼ (NO)
     [BLOCKED]                [BLOCKED]                 [BLOCKED]
  ```
* **Bypass Restrictions:** Unregistered external targets cannot receive vulnerability scanning packets under any circumstances.

---

## 2. Defensive & Non-Destructive Principles

KRYPT strictly forbids and does NOT implement:
* Credential theft or harvesting
* Arbitrary account takeover
* Persistence mechanisms or backdoor installations
* Malware, trojans, or ransomware deployment
* Destructive database manipulations (`DROP`, `DELETE`, `UPDATE`)
* Unauthorized privilege escalation
* Unauthorized bulk data extraction
* Evasion of security controls or firewall disruption

---

## 3. Evidence-First Design & Automatic Secret Masking

All captured evidence is filtered through `krypt.evidence.redactor` prior to logging and disk storage. The following sensitive parameters are systematically redacted:
* Authorization headers (`Bearer`, `Basic`)
* API keys and tokens
* Passwords and hashes
* Session cookies and session identifiers
* Private cryptographic keys

---

## 4. Responsible Use & Compliance

Security professionals, researchers, and penetration testers using KRYPT CLI must ensure they possess unambiguous, documented written authorization from target asset owners before performing any active testing.
