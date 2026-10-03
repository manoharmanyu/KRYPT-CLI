"""
OSINT data models for KRYPT CLI.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class DNSRecord(BaseModel):
    record_type: str
    name: str
    value: str
    ttl: Optional[int] = None


class SubdomainInfo(BaseModel):
    hostname: str
    source: str = "crtsh"
    first_seen: Optional[datetime] = Field(default_factory=datetime.utcnow)
    last_seen: Optional[datetime] = Field(default_factory=datetime.utcnow)
    resolved_ip: Optional[str] = None
    status: str = "active"


class EmailIndicator(BaseModel):
    email: str
    source: str
    context: Optional[str] = None
    confidence: str = "MEDIUM"


class CertificateInfo(BaseModel):
    subject: str
    issuer: str
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    sans: List[str] = Field(default_factory=list)
    serial_number: Optional[str] = None
    fingerprint_sha256: Optional[str] = None


class IntelReport(BaseModel):
    target_domain: str
    dns_records: List[DNSRecord] = Field(default_factory=list)
    subdomains: List[SubdomainInfo] = Field(default_factory=list)
    emails: List[EmailIndicator] = Field(default_factory=list)
    certificate: Optional[CertificateInfo] = None
    technologies: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    summary_counts: Dict[str, int] = Field(default_factory=dict)
