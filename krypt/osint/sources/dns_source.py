"""
DNS Intelligence Source for KRYPT CLI.
Queries A, AAAA, MX, NS, TXT, CNAME, SOA records using dnspython and socket fallback.
"""

import asyncio
import socket
from typing import Any, Dict, List
import dns.resolver

from krypt.osint.models import DNSRecord, IntelReport
from krypt.osint.sources.base import BaseSource
from krypt.core.logger import logger

RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


class DNSSource(BaseSource):
    @property
    def name(self) -> str:
        return "DNS Resolver"

    @property
    def category(self) -> str:
        return "DNS"

    async def collect(self, domain: str) -> Dict[str, Any]:
        """Collect DNS records asynchronously."""
        results: Dict[str, List[Dict[str, Any]]] = {rtype: [] for rtype in RECORD_TYPES}
        
        loop = asyncio.get_event_loop()
        
        def _resolve_type(rtype: str) -> List[Dict[str, Any]]:
            records = []
            try:
                resolver = dns.resolver.Resolver()
                resolver.timeout = 3.0
                resolver.lifetime = 3.0
                answers = resolver.resolve(domain, rtype)
                for rdata in answers:
                    val = rdata.to_text().strip('"')
                    records.append({"type": rtype, "name": domain, "value": val, "ttl": answers.ttl})
            except Exception:
                pass
            return records

        for rtype in RECORD_TYPES:
            recs = await loop.run_in_executor(None, _resolve_type, rtype)
            results[rtype].extend(recs)

        # Fallback to socket getaddrinfo for localhost/local domain if A record was empty
        if not results["A"] and domain in ("localhost", "127.0.0.1"):
            try:
                addr_info = socket.getaddrinfo(domain, None)
                for item in addr_info:
                    ip = item[4][0]
                    results["A"].append({"type": "A", "name": domain, "value": ip, "ttl": 300})
            except Exception:
                pass

        return {"domain": domain, "records": results}

    def normalize(self, raw_data: Dict[str, Any], report: IntelReport) -> None:
        records_dict = raw_data.get("records", {})
        for rtype, items in records_dict.items():
            for item in items:
                dns_rec = DNSRecord(
                    record_type=item["type"],
                    name=item["name"],
                    value=item["value"],
                    ttl=item.get("ttl")
                )
                if dns_rec not in report.dns_records:
                    report.dns_records.append(dns_rec)
