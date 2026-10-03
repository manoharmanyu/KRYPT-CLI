"""
Public Records and Metadata Intelligence Source for KRYPT CLI.
Fetches RDAP registry data, robots.txt, and public metadata.
"""

from typing import Any, Dict
from urllib.parse import urlparse

from krypt.core.http import http_client
from krypt.osint.models import IntelReport
from krypt.osint.sources.base import BaseSource
from krypt.core.logger import logger


class PublicRecordsSource(BaseSource):
    @property
    def name(self) -> str:
        return "Public Records & RDAP"

    @property
    def category(self) -> str:
        return "Public metadata"

    async def collect(self, domain: str) -> Dict[str, Any]:
        """Query RDAP endpoints and public records."""
        metadata: Dict[str, Any] = {}

        if domain not in ("localhost", "127.0.0.1"):
            rdap_url = f"https://rdap.org/domain/{domain}"
            try:
                resp = await http_client.get(rdap_url, timeout=5.0)
                if resp and resp.status_code == 200:
                    data = resp.json()
                    metadata["registrar"] = data.get("entities", [{}])[0].get("vcardArray", [[], []])[1] if "entities" in data else None
                    metadata["status"] = data.get("status", [])
                    metadata["handle"] = data.get("handle")
            except Exception as e:
                logger.debug(f"RDAP query error for {domain}: {e}")

        # Check robots.txt for public path indicators
        try:
            robots_resp = await http_client.get(f"http://{domain}/robots.txt", timeout=3.0)
            if robots_resp and robots_resp.status_code == 200:
                disallowed = []
                for line in robots_resp.text.splitlines():
                    if line.lower().startswith("disallow:"):
                        disallowed.append(line.split(":", 1)[1].strip())
                metadata["robots_disallowed"] = disallowed[:10]
        except Exception:
            pass

        return {"domain": domain, "metadata": metadata}

    def normalize(self, raw_data: Dict[str, Any], report: IntelReport) -> None:
        meta = raw_data.get("metadata", {})
        report.metadata.update(meta)
