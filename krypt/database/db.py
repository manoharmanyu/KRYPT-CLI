"""
Database connection and repository operations for KRYPT CLI.
"""

from datetime import datetime
import json
import uuid
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
from sqlalchemy import create_engine, select, desc
from sqlalchemy.orm import sessionmaker, Session

from krypt.utils.filesystem import KRYPT_DB_FILE, ensure_krypt_dirs
from krypt.database.models import (
    Base, TargetModel, ScanModel, FindingModel, EvidenceModel,
    EndpointModel, TechnologyModel, IntelligenceModel, CrawlerResultModel
)
from krypt.evidence.redactor import redact_dict, redact_text


class DatabaseManager:
    """Manages SQLite database operations for KRYPT."""

    def __init__(self, db_path: Optional[str] = None):
        ensure_krypt_dirs()
        self.db_path = db_path or str(KRYPT_DB_FILE)
        self.engine = create_engine(
            f"sqlite:///{self.db_path}",
            connect_args={"check_same_thread": False},
            echo=False
        )
        Base.metadata.create_all(self.engine)
        self.SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)

    def get_session(self) -> Session:
        return self.SessionLocal()

    # ----------------------------------------------------
    # Target Operations
    # ----------------------------------------------------
    def add_target(self, target_input: str, notes: str = "") -> TargetModel:
        """Register a new target with safety scope checks."""
        # Normalize input
        if not target_input.startswith(("http://", "https://")):
            normalized_url = f"http://{target_input}"
        else:
            normalized_url = target_input

        parsed = urlparse(normalized_url)
        host = parsed.hostname or target_input
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        scheme = parsed.scheme or "http"
        
        # Clean canonical URL
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            clean_url = f"{scheme}://{host}"
        else:
            clean_url = f"{scheme}://{host}:{port}"

        with self.get_session() as session:
            existing = session.query(TargetModel).filter(
                (TargetModel.url == clean_url) | (TargetModel.host == host) & (TargetModel.port == port)
            ).first()
            if existing:
                existing.is_active = True
                existing.notes = notes or existing.notes
                session.commit()
                session.refresh(existing)
                return existing

            new_target = TargetModel(
                url=clean_url,
                host=host,
                port=port,
                scheme=scheme,
                scope_status="AUTHORIZED",
                notes=notes,
                is_active=True,
                created_at=datetime.utcnow()
            )
            session.add(new_target)
            session.commit()
            session.refresh(new_target)
            return new_target

    def list_targets(self) -> List[TargetModel]:
        """List all registered targets."""
        with self.get_session() as session:
            return session.query(TargetModel).order_by(desc(TargetModel.created_at)).all()

    def remove_target(self, target_input: str) -> bool:
        """Remove a target from registered scope."""
        parsed = urlparse(target_input if "://" in target_input else f"http://{target_input}")
        host = parsed.hostname or target_input

        with self.get_session() as session:
            targets = session.query(TargetModel).filter(
                (TargetModel.url == target_input) | 
                (TargetModel.host == host) | 
                (TargetModel.host == target_input)
            ).all()
            if not targets:
                return False
            for t in targets:
                session.delete(t)
            session.commit()
            return True

    def get_target(self, target_input: str) -> Optional[TargetModel]:
        """Find a target by URL or host."""
        parsed = urlparse(target_input if "://" in target_input else f"http://{target_input}")
        host = parsed.hostname or target_input

        with self.get_session() as session:
            return session.query(TargetModel).filter(
                (TargetModel.url == target_input) | 
                (TargetModel.host == host) | 
                (TargetModel.host == target_input)
            ).first()

    def is_target_registered(self, host_or_url: str) -> bool:
        """Check whether a target or host is registered in scope."""
        parsed = urlparse(host_or_url if "://" in host_or_url else f"http://{host_or_url}")
        host = parsed.hostname or host_or_url

        with self.get_session() as session:
            # Check exact URL or exact Host or subdomain match
            match = session.query(TargetModel).filter(
                (TargetModel.url == host_or_url) |
                (TargetModel.host == host) |
                (TargetModel.host == host_or_url)
            ).first()
            if match:
                return True
            
            # Check if parent domain is registered
            all_targets = session.query(TargetModel).all()
            for t in all_targets:
                if host == t.host or host.endswith("." + t.host):
                    return True
            return False

    # ----------------------------------------------------
    # Scan & Finding Operations
    # ----------------------------------------------------
    def create_scan(self, target_url: str, module: str, options: Optional[Dict[str, Any]] = None) -> ScanModel:
        """Record start of a scan run."""
        scan_id = str(uuid.uuid4())[:8]
        target = self.get_target(target_url)
        with self.get_session() as session:
            scan = ScanModel(
                id=scan_id,
                target_id=target.id if target else None,
                target_url=target_url,
                module=module,
                status="running",
                options_json=json.dumps(options or {}),
                start_time=datetime.utcnow()
            )
            session.add(scan)
            session.commit()
            session.refresh(scan)
            return scan

    def complete_scan(self, scan_id: str, findings_count: int, status: str = "completed") -> None:
        """Mark scan as finished."""
        with self.get_session() as session:
            scan = session.query(ScanModel).filter(ScanModel.id == scan_id).first()
            if scan:
                scan.status = status
                scan.findings_count = findings_count
                scan.end_time = datetime.utcnow()
                session.commit()

    def add_finding(
        self,
        target_url: str,
        module: str,
        vulnerability: str,
        severity: str,
        confidence: str = "HIGH",
        endpoint: str = "/",
        parameter: str = "",
        evidence_text: str = "",
        impact: str = "",
        remediation: str = "",
        references: Optional[List[str]] = None,
        scan_id: Optional[str] = None,
        raw_evidence: Optional[Dict[str, Any]] = None
    ) -> FindingModel:
        """Store a finding and associated redacted evidence."""
        finding_id = f"KRYPT-{datetime.utcnow().strftime('%Y%m')}-{uuid.uuid4().hex[:6].upper()}"
        target = self.get_target(target_url)
        clean_evidence = redact_text(evidence_text)

        with self.get_session() as session:
            finding = FindingModel(
                id=finding_id,
                target_id=target.id if target else None,
                target_url=target_url,
                scan_id=scan_id,
                module=module,
                vulnerability=vulnerability,
                severity=severity.upper(),
                confidence=confidence.upper(),
                endpoint=endpoint,
                parameter=parameter,
                evidence=clean_evidence,
                impact=impact,
                remediation=remediation,
                references_json=json.dumps(references or []),
                timestamp=datetime.utcnow()
            )
            session.add(finding)
            session.commit()

            # Add structured evidence record
            if raw_evidence or clean_evidence:
                redacted_ev = redact_dict(raw_evidence) if raw_evidence else {}
                evidence_rec = EvidenceModel(
                    id=str(uuid.uuid4())[:8],
                    finding_id=finding_id,
                    evidence_type="VULN_VERIFICATION",
                    raw_data=json.dumps(redacted_ev),
                    redacted_data=clean_evidence,
                    request_meta_json=json.dumps(redacted_ev.get("request", {})),
                    response_meta_json=json.dumps(redacted_ev.get("response", {})),
                    timestamp=datetime.utcnow()
                )
                session.add(evidence_rec)
                session.commit()

            session.refresh(finding)
            return finding

    def get_findings(
        self,
        severity: Optional[str] = None,
        target: Optional[str] = None,
        module: Optional[str] = None
    ) -> List[FindingModel]:
        """Query findings with optional filters."""
        with self.get_session() as session:
            q = session.query(FindingModel)
            if severity:
                q = q.filter(FindingModel.severity == severity.upper())
            if target:
                q = q.filter(FindingModel.target_url.contains(target))
            if module:
                q = q.filter(FindingModel.module == module.lower())
            return q.order_by(desc(FindingModel.timestamp)).all()

    def get_finding_by_id(self, finding_id: str) -> Optional[FindingModel]:
        """Fetch a specific finding by its ID."""
        with self.get_session() as session:
            return session.query(FindingModel).filter(FindingModel.id == finding_id).first()

    def get_evidence_for_finding(self, finding_id: str) -> List[EvidenceModel]:
        """Fetch all evidence records linked to a finding."""
        with self.get_session() as session:
            return session.query(EvidenceModel).filter(EvidenceModel.finding_id == finding_id).all()

    # ----------------------------------------------------
    # Endpoints & Technologies & Intelligence
    # ----------------------------------------------------
    def add_endpoint(
        self,
        target_url: str,
        method: str,
        url: str,
        path: str = "/",
        parameters: str = "",
        content_type: str = "",
        discovered_from: str = "",
        confidence: str = "HIGH"
    ) -> None:
        """Store discovered endpoint."""
        target = self.get_target(target_url)
        with self.get_session() as session:
            existing = session.query(EndpointModel).filter(
                (EndpointModel.target_url == target_url) &
                (EndpointModel.method == method) &
                (EndpointModel.url == url)
            ).first()
            if not existing:
                ep = EndpointModel(
                    target_id=target.id if target else None,
                    target_url=target_url,
                    method=method.upper(),
                    url=url,
                    path=path,
                    parameters=parameters,
                    content_type=content_type,
                    discovered_from=discovered_from,
                    confidence=confidence,
                    first_seen=datetime.utcnow()
                )
                session.add(ep)
                session.commit()

    def get_endpoints(self, target_url: Optional[str] = None) -> List[EndpointModel]:
        """List discovered endpoints."""
        with self.get_session() as session:
            q = session.query(EndpointModel)
            if target_url:
                q = q.filter(EndpointModel.target_url.contains(target_url))
            return q.all()

    def add_technology(
        self,
        target_url: str,
        name: str,
        version: str = "",
        category: str = "Web Server",
        confidence: str = "HIGH",
        evidence: str = ""
    ) -> None:
        """Store fingerprint technology."""
        target = self.get_target(target_url)
        with self.get_session() as session:
            existing = session.query(TechnologyModel).filter(
                (TechnologyModel.target_url == target_url) &
                (TechnologyModel.name == name)
            ).first()
            if not existing:
                tech = TechnologyModel(
                    target_id=target.id if target else None,
                    target_url=target_url,
                    name=name,
                    version=version,
                    category=category,
                    confidence=confidence,
                    evidence=evidence,
                    first_seen=datetime.utcnow()
                )
                session.add(tech)
                session.commit()

    def get_technologies(self, target_url: Optional[str] = None) -> List[TechnologyModel]:
        """List identified technologies."""
        with self.get_session() as session:
            q = session.query(TechnologyModel)
            if target_url:
                q = q.filter(TechnologyModel.target_url.contains(target_url))
            return q.all()

    def add_intelligence(
        self,
        target_host: str,
        category: str,
        key: str,
        value: str,
        source: str = "osint",
        raw_json: Optional[Dict[str, Any]] = None
    ) -> None:
        """Store OSINT intelligence record."""
        with self.get_session() as session:
            existing = session.query(IntelligenceModel).filter(
                (IntelligenceModel.target_host == target_host) &
                (IntelligenceModel.category == category) &
                (IntelligenceModel.key == key) &
                (IntelligenceModel.value == value)
            ).first()
            if not existing:
                intel = IntelligenceModel(
                    target_host=target_host,
                    category=category,
                    key=key,
                    value=value,
                    source=source,
                    raw_json=json.dumps(raw_json or {}),
                    timestamp=datetime.utcnow()
                )
                session.add(intel)
                session.commit()

    def get_intelligence(self, target_host: Optional[str] = None, category: Optional[str] = None) -> List[IntelligenceModel]:
        """Query OSINT intelligence items."""
        with self.get_session() as session:
            q = session.query(IntelligenceModel)
            if target_host:
                q = q.filter(IntelligenceModel.target_host == target_host)
            if category:
                q = q.filter(IntelligenceModel.category == category)
            return q.all()


# Global singleton instance
db = DatabaseManager()
