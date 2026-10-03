"""
Base Security Assessment Module for KRYPT CLI.
Defines standard lifecycle: name, description, scope validation, execution, and findings.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional
import httpx

from krypt.database.db import db
from krypt.database.models import FindingModel
from krypt.safety.scope import ScopeEngine


class BaseModule(ABC):
    """Abstract base class for all security assessment modules."""

    def __init__(self):
        self._findings: List[FindingModel] = []

    @property
    @abstractmethod
    def name(self) -> str:
        """Module identifier name (e.g. 'sqli', 'xss', 'auth')."""
        pass

    @property
    @abstractmethod
    def description(self) -> str:
        """Human-readable description of what this module assesses."""
        pass

    def check_scope(self, target: str) -> bool:
        """Enforce fail-closed authorization check before running tests."""
        return ScopeEngine.check_scope(target, is_active_assessment=True)

    @abstractmethod
    async def run(self, target: str, scan_id: Optional[str] = None, **kwargs) -> List[FindingModel]:
        """
        Execute controlled defensive assessment against target.
        Returns generated findings.
        """
        pass

    def findings(self) -> List[FindingModel]:
        """Return all findings generated in the last run."""
        return self._findings

    def add_finding(
        self,
        target_url: str,
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
        """Helper to create, save, and track a finding."""
        finding = db.add_finding(
            target_url=target_url,
            module=self.name,
            vulnerability=vulnerability,
            severity=severity,
            confidence=confidence,
            endpoint=endpoint,
            parameter=parameter,
            evidence_text=evidence_text,
            impact=impact,
            remediation=remediation,
            references=references or [],
            scan_id=scan_id,
            raw_evidence=raw_evidence
        )
        self._findings.append(finding)
        return finding
