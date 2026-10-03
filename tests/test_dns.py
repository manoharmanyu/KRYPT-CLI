"""
Unit tests for DNS and OSINT models and normalizer.
"""

import pytest
from krypt.osint.models import DNSRecord, EmailIndicator, IntelReport, SubdomainInfo
from krypt.osint.sources.dns_source import DNSSource
from krypt.osint.sources.emails import EmailSource


@pytest.mark.asyncio
async def test_dns_collector_loopback():
    source = DNSSource()
    data = await source.collect("localhost")
    assert "records" in data
    assert "A" in data["records"]
    assert len(data["records"]["A"]) > 0


def test_email_normalizer():
    source = EmailSource()
    report = IntelReport(target_domain="example.com")
    report.dns_records.append(DNSRecord(record_type="TXT", name="example.com", value="v=spf1 include:_spf.google.com contact=security@example.com ~all"))
    
    source.normalize({"emails": ["admin@example.com", "info@example.com"]}, report)
    
    email_addresses = {e.email for e in report.emails}
    assert "admin@example.com" in email_addresses
    assert "info@example.com" in email_addresses
    assert "security@example.com" in email_addresses
