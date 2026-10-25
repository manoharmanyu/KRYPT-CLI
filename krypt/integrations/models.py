"""
Models and Data Contracts for Upstream Tool Integrations in KRYPT CLI.
Defines the normalized result schema, tool capabilities, and runtime status models.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ToolInfo(BaseModel):
    """Metadata, capabilities, and runtime status for an integrated upstream tool."""
    name: str
    display_name: str
    upstream_repo: str
    upstream_branch: str
    commit_sha: str
    license: str
    runtime_python: str
    venv_path: str
    executable: str
    installed: bool = False
    description: str = ""
    capabilities: List[str] = Field(default_factory=list)
    external_services: List[str] = Field(default_factory=list)
    safety_notes: str = ""
    version: str = "Unknown"


class ToolFinding(BaseModel):
    """Normalized finding extracted from an integrated tool's output."""
    category: str
    item: str
    details: str
    source_tool: str
    severity: str = "info"  # info, low, medium, high, critical
    extra: Dict[str, Any] = Field(default_factory=dict)


class ToolEvidence(BaseModel):
    """Verifiable transaction or output evidence preserved from an upstream run."""
    evidence_id: str
    tool: str
    evidence_type: str  # http_transaction, raw_file, stdout, log_excerpt
    content: Any
    file_path: Optional[str] = None
    created_at: str = Field(default_factory=lambda: datetime.utcnow().isoformat() + "Z")


class AdapterResult(BaseModel):
    """
    Common normalized result contract for all upstream adapter executions.
    Preserves original evidence, output file references, error records, and structured findings.
    """
    tool: str
    run_id: str
    started_at: str
    completed_at: str
    target: str
    scope: Dict[str, Any] = Field(default_factory=dict)
    status: str = "SUCCESS"  # SUCCESS, PARTIAL, FAILED, BLOCKED, TIMEOUT
    findings: List[Dict[str, Any]] = Field(default_factory=list)
    evidence: List[Dict[str, Any]] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)
    output_files: List[str] = Field(default_factory=list)
    raw_result: Optional[Dict[str, Any]] = None

    def add_error(self, message: str) -> None:
        """Add an error message and adjust status."""
        self.errors.append(message)
        if self.status == "SUCCESS":
            self.status = "PARTIAL"

    def fail(self, message: str) -> None:
        """Mark the result as failed."""
        self.errors.append(message)
        self.status = "FAILED"

    def block(self, message: str) -> None:
        """Mark the result as blocked due to safety/scope enforcement."""
        self.errors.append(message)
        self.status = "BLOCKED"
