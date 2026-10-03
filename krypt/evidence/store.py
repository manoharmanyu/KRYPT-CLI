"""
Evidence Store for KRYPT CLI.
Captures and manages verifiable proof for security findings.
"""

from datetime import datetime
import json
from typing import Any, Dict, List, Optional
import uuid

from krypt.database.db import db
from krypt.database.models import EvidenceModel, FindingModel
from krypt.evidence.redactor import redact_dict, redact_headers, redact_text


class EvidenceStore:
    """Manages creation, redaction, and retrieval of finding evidence."""

    @staticmethod
    def capture_http_evidence(
        finding_id: str,
        request_url: str,
        request_method: str,
        request_headers: Optional[Dict[str, str]] = None,
        request_body: Optional[str] = None,
        response_status: Optional[int] = None,
        response_headers: Optional[Dict[str, str]] = None,
        response_body: Optional[str] = None,
        observation: str = ""
    ) -> EvidenceModel:
        """Create and store structured HTTP request/response evidence."""
        req_meta = {
            "url": request_url,
            "method": request_method,
            "headers": redact_headers(request_headers or {}),
            "body": redact_text(request_body or "") if request_body else "",
        }
        res_meta = {
            "status_code": response_status,
            "headers": redact_headers(response_headers or {}),
            "body_snippet": redact_text(response_body[:2000]) if response_body else "",
        }
        
        redacted_summary = redact_text(observation)
        raw_combined = {
            "observation": observation,
            "request": req_meta,
            "response": res_meta,
        }

        with db.get_session() as session:
            ev = EvidenceModel(
                id=str(uuid.uuid4())[:8],
                finding_id=finding_id,
                evidence_type="HTTP_INTERACTION",
                raw_data=json.dumps(redact_dict(raw_combined)),
                redacted_data=redacted_summary,
                request_meta_json=json.dumps(req_meta),
                response_meta_json=json.dumps(res_meta),
                timestamp=datetime.utcnow()
            )
            session.add(ev)
            session.commit()
            session.refresh(ev)
            return ev

    @staticmethod
    def get_evidence(finding_id: str) -> List[EvidenceModel]:
        """Fetch all evidence items for a given finding ID."""
        return db.get_evidence_for_finding(finding_id)
