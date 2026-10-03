"""
Certificate Transparency Intelligence Source (crt.sh) for KRYPT CLI.
Discovers subdomains and certificates from public Certificate Transparency logs.
"""

from typing import Any, Dict, List, Set
from krypt.core.http import http_client
from krypt.core.logger import logger
from krypt.osint.models import IntelReport, SubdomainInfo
from krypt.osint.sources.base import BaseSource


class CrtshSource(BaseSource):
    @property
    def name(self) -> str:
        return "crt.sh"

    @property
    def category(self) -> str:
        return "Subdomain"

    async def collect(self, domain: str) -> Dict[str, Any]:
        """Query crt.sh API for subdomains."""
        if domain in ("localhost", "127.0.0.1"):
            return {"domain": domain, "subdomains": []}

        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            resp = await http_client.get(url, timeout=10.0)
            if resp and resp.status_code == 200:
                try:
                    entries = resp.json()
                    subdomains: Set[str] = set()
                    if isinstance(entries, list):
                        for entry in entries:
                            name_val = entry.get("name_value", "")
                            for name in name_val.split("\n"):
                                name = name.strip().lower()
                                if name and not name.startswith("*.") and domain in name:
                                    subdomains.add(name)
                    return {"domain": domain, "subdomains": list(subdomains)}
                except Exception as e:
                    logger.debug(f"crt.sh JSON parsing error: {e}")
        except Exception as e:
            logger.debug(f"crt.sh query error: {e}")

        return {"domain": domain, "subdomains": []}

    def normalize(self, raw_data: Dict[str, Any], report: IntelReport) -> None:
        subdomains = raw_data.get("subdomains", [])
        existing_hostnames = {s.hostname for s in report.subdomains}

        for sub in subdomains:
            if sub not in existing_hostnames:
                report.subdomains.append(SubdomainInfo(
                    hostname=sub,
                    source="crt.sh",
                    status="discovered"
                ))
                existing_hostnames.add(sub)
