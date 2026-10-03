"""
Email Intelligence Source for KRYPT CLI.
Harvests publicly available email indicators from DNS records, security.txt, and public indicators.
Never attempts password discovery or credential verification.
"""

import re
from typing import Any, Dict, List, Set
from urllib.parse import urlparse

from krypt.core.http import http_client
from krypt.osint.models import EmailIndicator, IntelReport
from krypt.osint.sources.base import BaseSource

EMAIL_REGEX = re.compile(
    r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+",
    re.IGNORECASE
)


class EmailSource(BaseSource):
    @property
    def name(self) -> str:
        return "Email Harvester"

    @property
    def category(self) -> str:
        return "Email"

    async def collect(self, domain: str) -> Dict[str, Any]:
        """Collect email indicators from public endpoints and web text."""
        emails_found: Set[str] = set()

        # Check security.txt
        urls_to_check = [
            f"https://{domain}/.well-known/security.txt",
            f"https://{domain}/security.txt",
            f"http://{domain}/.well-known/security.txt",
            f"http://{domain}/security.txt",
            f"http://{domain}/",
        ]

        for url in urls_to_check:
            try:
                resp = await http_client.get(url, timeout=4.0)
                if resp and resp.status_code == 200:
                    matches = EMAIL_REGEX.findall(resp.text)
                    for m in matches:
                        # Clean and filter image / font / dummy false positives
                        m_clean = m.strip().lower()
                        if not any(m_clean.endswith(ext) for ext in [".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".js"]):
                            if domain in m_clean or not domain.endswith(".local"):
                                emails_found.add(m_clean)
            except Exception:
                pass

        return {"domain": domain, "emails": list(emails_found)}

    def normalize(self, raw_data: Dict[str, Any], report: IntelReport) -> None:
        emails = raw_data.get("emails", [])
        
        # Also parse emails from DNS TXT / SOA records already in report
        for record in report.dns_records:
            if record.record_type in ("TXT", "SOA"):
                matches = EMAIL_REGEX.findall(record.value)
                for m in matches:
                    emails.append(m.lower())
                # Handle SOA hostmaster format (e.g. hostmaster.domain.com -> hostmaster@domain.com)
                if record.record_type == "SOA":
                    parts = record.value.split()
                    if len(parts) >= 2 and "." in parts[1]:
                        hostmaster = parts[1].replace(".", "@", 1)
                        if EMAIL_REGEX.match(hostmaster):
                            emails.append(hostmaster.lower())

        existing_emails = {e.email for e in report.emails}
        for email in set(emails):
            if email not in existing_emails:
                report.emails.append(EmailIndicator(
                    email=email,
                    source="public_recon",
                    confidence="HIGH" if report.target_domain in email else "MEDIUM"
                ))
                existing_emails.add(email)
