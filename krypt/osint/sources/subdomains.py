"""
Subdomain Discovery and Resolution Engine for KRYPT CLI.
Discovers subdomains through passive wordlists and resolves their IP addresses.
"""

import asyncio
import socket
from typing import Any, Dict, List, Set

from krypt.osint.models import IntelReport, SubdomainInfo
from krypt.osint.sources.base import BaseSource

COMMON_SUBDOMAINS = [
    "www", "mail", "api", "dev", "staging", "app", "admin", "test",
    "portal", "auth", "vpn", "cdn", "static", "beta", "shop", "blog",
    "docs", "status", "secure", "m", "gateway", "backend", "direct"
]


class SubdomainSource(BaseSource):
    @property
    def name(self) -> str:
        return "Subdomain Enumerator"

    @property
    def category(self) -> str:
        return "Subdomain"

    async def collect(self, domain: str) -> Dict[str, Any]:
        """Check resolution of common subdomains."""
        resolved: List[Dict[str, Any]] = []
        loop = asyncio.get_event_loop()

        def _resolve_sub(sub: str) -> Optional[Dict[str, Any]]:
            hostname = f"{sub}.{domain}" if domain not in ("localhost", "127.0.0.1") else f"{sub}.local"
            try:
                addr_info = socket.getaddrinfo(hostname, None)
                ips = list({r[4][0] for r in addr_info})
                if ips:
                    return {
                        "hostname": hostname,
                        "resolved_ip": ips[0],
                        "status": "active"
                    }
            except Exception:
                pass
            return None

        tasks = [loop.run_in_executor(None, _resolve_sub, sub) for sub in COMMON_SUBDOMAINS]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results:
            if isinstance(res, dict) and res:
                resolved.append(res)

        return {"domain": domain, "resolved_subdomains": resolved}

    def normalize(self, raw_data: Dict[str, Any], report: IntelReport) -> None:
        resolved = raw_data.get("resolved_subdomains", [])
        existing_hostnames = {s.hostname: s for s in report.subdomains}

        for item in resolved:
            hostname = item["hostname"]
            ip = item.get("resolved_ip")
            if hostname in existing_hostnames:
                existing_hostnames[hostname].resolved_ip = ip
                existing_hostnames[hostname].status = "active"
            else:
                report.subdomains.append(SubdomainInfo(
                    hostname=hostname,
                    source="dns_active",
                    resolved_ip=ip,
                    status="active"
                ))
