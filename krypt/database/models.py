"""
SQLAlchemy models for KRYPT CLI SQLite database.
Stores targets, scans, findings, evidence, endpoints, technologies, intelligence, and crawler results.
"""

from datetime import datetime
import json
from typing import Any, Dict, List, Optional
from sqlalchemy import (
    Column, Integer, String, Text, Boolean, DateTime, ForeignKey, Float
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class TargetModel(Base):
    __tablename__ = "targets"

    id = Column(Integer, primary_key=True, autoincrement=True)
    url = Column(String(512), unique=True, nullable=False, index=True)
    host = Column(String(256), nullable=False, index=True)
    port = Column(Integer, nullable=True)
    scheme = Column(String(16), default="http")
    scope_status = Column(String(32), default="AUTHORIZED")
    notes = Column(Text, default="")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    scans = relationship("ScanModel", back_populates="target", cascade="all, delete-orphan")
    endpoints = relationship("EndpointModel", back_populates="target", cascade="all, delete-orphan")
    technologies = relationship("TechnologyModel", back_populates="target", cascade="all, delete-orphan")
    crawler_results = relationship("CrawlerResultModel", back_populates="target", cascade="all, delete-orphan")


class ScanModel(Base):
    __tablename__ = "scans"

    id = Column(String(64), primary_key=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=True)
    target_url = Column(String(512), nullable=False)
    module = Column(String(64), nullable=False)
    status = Column(String(32), default="completed")  # running, completed, failed
    findings_count = Column(Integer, default=0)
    options_json = Column(Text, default="{}")
    start_time = Column(DateTime, default=datetime.utcnow)
    end_time = Column(DateTime, nullable=True)

    target = relationship("TargetModel", back_populates="scans")
    findings = relationship("FindingModel", back_populates="scan", cascade="all, delete-orphan")


class FindingModel(Base):
    __tablename__ = "findings"

    id = Column(String(64), primary_key=True)
    target_id = Column(Integer, nullable=True, index=True)
    target_url = Column(String(512), nullable=False, index=True)
    scan_id = Column(String(64), ForeignKey("scans.id"), nullable=True)
    module = Column(String(64), nullable=False)
    vulnerability = Column(String(256), nullable=False)
    severity = Column(String(16), nullable=False, index=True)  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    confidence = Column(String(16), default="HIGH")          # HIGH, MEDIUM, LOW
    endpoint = Column(String(512), default="/")
    parameter = Column(String(128), default="")
    evidence = Column(Text, default="")
    impact = Column(Text, default="")
    remediation = Column(Text, default="")
    references_json = Column(Text, default="[]")
    timestamp = Column(DateTime, default=datetime.utcnow)

    scan = relationship("ScanModel", back_populates="findings")
    evidence_records = relationship("EvidenceModel", back_populates="finding", cascade="all, delete-orphan")

    def get_references(self) -> List[str]:
        try:
            return json.loads(self.references_json or "[]")
        except Exception:
            return []


class EvidenceModel(Base):
    __tablename__ = "evidence"

    id = Column(String(64), primary_key=True)
    finding_id = Column(String(64), ForeignKey("findings.id"), nullable=False, index=True)
    evidence_type = Column(String(64), default="HTTP_TRANSACTION")
    raw_data = Column(Text, default="")
    redacted_data = Column(Text, default="")
    request_meta_json = Column(Text, default="{}")
    response_meta_json = Column(Text, default="{}")
    timestamp = Column(DateTime, default=datetime.utcnow)

    finding = relationship("FindingModel", back_populates="evidence_records")


class EndpointModel(Base):
    __tablename__ = "endpoints"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=True, index=True)
    target_url = Column(String(512), nullable=False)
    method = Column(String(16), default="GET")
    url = Column(String(1024), nullable=False)
    path = Column(String(512), default="/")
    parameters = Column(Text, default="")
    content_type = Column(String(128), default="")
    discovered_from = Column(String(512), default="")
    confidence = Column(String(16), default="HIGH")
    first_seen = Column(DateTime, default=datetime.utcnow)

    target = relationship("TargetModel", back_populates="endpoints")


class TechnologyModel(Base):
    __tablename__ = "technologies"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=True, index=True)
    target_url = Column(String(512), nullable=False)
    name = Column(String(128), nullable=False)
    version = Column(String(64), default="")
    category = Column(String(64), default="Web Server")
    confidence = Column(String(16), default="HIGH")
    evidence = Column(Text, default="")
    first_seen = Column(DateTime, default=datetime.utcnow)

    target = relationship("TargetModel", back_populates="technologies")


class IntelligenceModel(Base):
    __tablename__ = "intelligence"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target_host = Column(String(256), nullable=False, index=True)
    category = Column(String(64), nullable=False, index=True)  # Domain, Subdomain, Host, IP, Email, URL, Technology, DNS, Certificate, Public metadata
    key = Column(String(256), nullable=False)
    value = Column(Text, nullable=False)
    source = Column(String(64), default="osint")
    raw_json = Column(Text, default="{}")
    timestamp = Column(DateTime, default=datetime.utcnow)


class CrawlerResultModel(Base):
    __tablename__ = "crawler_results"

    id = Column(Integer, primary_key=True, autoincrement=True)
    target_id = Column(Integer, ForeignKey("targets.id"), nullable=True, index=True)
    target_url = Column(String(512), nullable=False)
    url = Column(String(1024), nullable=False)
    status_code = Column(Integer, default=200)
    content_type = Column(String(128), default="")
    links_count = Column(Integer, default=0)
    depth = Column(Integer, default=0)
    timestamp = Column(DateTime, default=datetime.utcnow)

    target = relationship("TargetModel", back_populates="crawler_results")
