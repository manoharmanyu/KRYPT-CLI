"""
Information & Sensitive File Exposure Assessment Module for KRYPT CLI.
Detects exposed environment files, git repositories, backups, and debug metrics safely.
"""

from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from krypt.core.http import http_client
from krypt.database.models import FindingModel
from krypt.modules.base import BaseModule

EXPOSURE_TARGETS = [
    {
        "path": "/.env",
        "indicator": "DB_PASSWORD|SECRET_KEY|DATABASE_URL|API_KEY|APP_KEY",
        "severity": "CRITICAL",
        "vuln": "Exposed Environment Configuration File (.env)",
    },
    {
        "path": "/.git/HEAD",
        "indicator": "ref: refs/",
        "severity": "HIGH",
        "vuln": "Exposed Git Version Control Repository (.git/HEAD)",
    },
    {
        "path": "/.DS_Store",
        "indicator": "Bud1",
        "severity": "LOW",
        "vuln": "Exposed macOS Metadata Artifact (.DS_Store)",
    },
    {
        "path": "/debug/vars",
        "indicator": "cmdline|memstats|goroutines",
        "severity": "MEDIUM",
        "vuln": "Exposed Go Debug Variables Endpoint (/debug/vars)",
    },
    {
        "path": "/actuator/health",
        "indicator": "status|UP|DOWN",
        "severity": "LOW",
        "vuln": "Exposed Spring Actuator Endpoint (/actuator/health)",
    },
    {
        "path": "/backup.sql",
        "indicator": "CREATE TABLE|INSERT INTO|MySQL dump",
        "severity": "CRITICAL",
        "vuln": "Exposed Database SQL Backup (backup.sql)",
    },
    {
        "path": "/server-status",
        "indicator": "Apache Server Status|Current Time|Server uptime",
        "severity": "MEDIUM",
        "vuln": "Exposed Apache Server Status (/server-status)",
    },
]


class ExposureModule(BaseModule):
    @property
    def name(self) -> str:
        return "exposure"

    @property
    def description(self) -> str:
        return "Information & Sensitive File Exposure Assessment (.env, .git, backups, debug endpoints)"

    async def run(self, target: str, scan_id: Optional[str] = None, **kwargs) -> List[FindingModel]:
        """Test for common sensitive file and configuration leaks."""
        self.check_scope(target)
        self._findings.clear()

        # Check a randomized non-existent file first to calibrate baseline 404 response
        baseline_404_url = urljoin(target, "/krypt_nonexistent_probe_404981.txt")
        baseline_resp = await http_client.get(baseline_404_url)
        baseline_body = baseline_resp.text if baseline_resp else ""
        baseline_status = baseline_resp.status_code if baseline_resp else 404

        for exp in EXPOSURE_TARGETS:
            path = exp["path"]
            full_url = urljoin(target, path)
            resp = await http_client.get(full_url)

            if not resp:
                continue

            if resp.status_code == 200:
                # Disregard if server returns 200 for all random non-existent paths (catch-all SPA)
                if baseline_status == 200 and resp.text == baseline_body:
                    continue

                import re
                indicator = exp["indicator"]
                if re.search(indicator, resp.text, re.IGNORECASE):
                    ev_text = (
                        f"Sensitive resource at path '{path}' was directly accessible (HTTP 200).\n"
                        f"Matched expected data signature: `{indicator}`."
                    )

                    self.add_finding(
                        target_url=target,
                        vulnerability=exp["vuln"],
                        severity=exp["severity"],
                        confidence="HIGH",
                        endpoint=path,
                        parameter="N/A",
                        evidence_text=ev_text,
                        impact=(
                            "Potential leak of secret API keys, database credentials, internal system topology, "
                            "or proprietary application source code."
                        ),
                        remediation=(
                            f"Restrict web server access to '{path}' via web server configuration or remove "
                            "unnecessary sensitive backup files and debug routes from production deployment."
                        ),
                        references=[
                            "https://owasp.org/Top10/A05_2021-Security_Misconfiguration/",
                            "https://cwe.mitre.org/data/definitions/200.html"
                        ],
                        scan_id=scan_id,
                        raw_evidence={
                            "request": {"url": full_url, "method": "GET"},
                            "response": {"status_code": 200, "body_snippet": resp.text[:400]},
                            "observation": f"Matched signature '{indicator}'"
                        }
                    )

        return self._findings
