"""
Security Headers Vulnerability Assessment Module for KRYPT CLI.
Evaluates missing CSP, HSTS, X-Frame-Options, and X-Content-Type-Options, generating structured findings.
"""

from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from krypt.core.http import http_client
from krypt.database.models import FindingModel
from krypt.modules.base import BaseModule
from krypt.recon.headers import HeaderAnalyzer


class HeadersModule(BaseModule):
    @property
    def name(self) -> str:
        return "headers"

    @property
    def description(self) -> str:
        return "HTTP Security Headers & Transport Security Assessment (CSP, HSTS, XFO, XCTO)"

    async def run(self, target: str, scan_id: Optional[str] = None, **kwargs) -> List[FindingModel]:
        """Audit target headers for missing hardening directives."""
        self.check_scope(target)
        self._findings.clear()

        resp = await http_client.get(target)
        if not resp:
            return self._findings

        report = HeaderAnalyzer.analyze(target, response=resp)

        for item in report.header_results:
            if item.status == "FAIL":
                severity = "LOW"
                if item.header_name == "Content-Security-Policy":
                    severity = "MEDIUM"
                elif item.header_name == "Strict-Transport-Security" and target.startswith("https://"):
                    severity = "MEDIUM"
                elif item.header_name == "X-Frame-Options":
                    severity = "MEDIUM"

                self.add_finding(
                    target_url=target,
                    vulnerability=f"Missing Security Header: {item.header_name}",
                    severity=severity,
                    confidence="HIGH",
                    endpoint="/",
                    parameter=item.header_name,
                    evidence_text=f"Header '{item.header_name}' was not present in the HTTP response headers.",
                    impact=item.description,
                    remediation=item.recommendation,
                    references=[
                        "https://owasp.org/www-project-secure-headers/",
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers"
                    ],
                    scan_id=scan_id
                )

        return self._findings
