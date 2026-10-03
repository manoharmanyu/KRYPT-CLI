"""
OSINT Engine for KRYPT CLI.
Orchestrates multi-source collection, normalization, deduplication, and database persistence.
"""

import asyncio
from typing import List, Optional

from krypt.database.db import db
from krypt.osint.models import IntelReport
from krypt.osint.sources.base import BaseSource
from krypt.osint.sources.certificate import CertificateSource
from krypt.osint.sources.crtsh import CrtshSource
from krypt.osint.sources.dns_source import DNSSource
from krypt.osint.sources.emails import EmailSource
from krypt.osint.sources.public_records import PublicRecordsSource
from krypt.osint.sources.subdomains import SubdomainSource
from krypt.safety.scope import ScopeEngine


class OSINTEngine:
    """Multi-source OSINT intelligence aggregator."""

    def __init__(self, sources: Optional[List[BaseSource]] = None):
        self.sources: List[BaseSource] = sources or [
            DNSSource(),
            CrtshSource(),
            SubdomainSource(),
            CertificateSource(),
            EmailSource(),
            PublicRecordsSource(),
        ]

    async def run(self, domain: str) -> IntelReport:
        """Execute OSINT collection pipeline for a domain."""
        # Check scope (allow passive reconnaissance for public domain queries)
        ScopeEngine.check_scope(domain, is_active_assessment=False, allow_passive=True)

        report = IntelReport(target_domain=domain)

        # 1. Concurrent collection across all sources
        tasks = [source.collect(domain) for source in self.sources]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # 2. Normalization & Deduplication
        for source, res in zip(self.sources, results):
            if isinstance(res, dict):
                source.normalize(res, report)

        # 3. Save into Intelligence database
        for rec in report.dns_records:
            db.add_intelligence(
                target_host=domain,
                category="DNS",
                key=f"{rec.record_type}:{rec.name}",
                value=rec.value,
                source="dns"
            )

        for sub in report.subdomains:
            db.add_intelligence(
                target_host=domain,
                category="Subdomain",
                key=sub.hostname,
                value=sub.resolved_ip or "unresolved",
                source=sub.source
            )

        for em in report.emails:
            db.add_intelligence(
                target_host=domain,
                category="Email",
                key=em.email,
                value=em.confidence,
                source=em.source
            )

        if report.certificate:
            db.add_intelligence(
                target_host=domain,
                category="Certificate",
                key="TLS_Subject",
                value=report.certificate.subject,
                source="tls_probe"
            )

        # 4. Summary counts
        report.summary_counts = {
            "dns_records": len(report.dns_records),
            "subdomains": len(report.subdomains),
            "emails": len(report.emails),
            "has_certificate": 1 if report.certificate else 0,
        }

        return report
