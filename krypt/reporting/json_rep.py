"""
JSON Report Generator for KRYPT CLI.
"""

from datetime import datetime
import json
from typing import Any, Dict, List, Optional

from krypt.database.models import FindingModel, TargetModel


def generate_json_report(
    target_url: str,
    findings: List[FindingModel],
    metadata: Optional[Dict[str, Any]] = None
) -> str:
    """Serialize findings and scan results into structured JSON."""
    report_dict = {
        "framework": "KRYPT CLI",
        "version": "0.1.0",
        "author": "Gaddam Manyu (@manoharmanyu)",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "target": target_url,
        "metadata": metadata or {},
        "summary": {
            "total_findings": len(findings),
            "critical": sum(1 for f in findings if f.severity == "CRITICAL"),
            "high": sum(1 for f in findings if f.severity == "HIGH"),
            "medium": sum(1 for f in findings if f.severity == "MEDIUM"),
            "low": sum(1 for f in findings if f.severity == "LOW"),
            "info": sum(1 for f in findings if f.severity == "INFO"),
        },
        "findings": [
            {
                "id": f.id,
                "target": f.target_url,
                "module": f.module,
                "vulnerability": f.vulnerability,
                "severity": f.severity,
                "confidence": f.confidence,
                "endpoint": f.endpoint,
                "parameter": f.parameter,
                "evidence": f.evidence,
                "impact": f.impact,
                "remediation": f.remediation,
                "references": f.get_references(),
                "timestamp": f.timestamp.isoformat() + "Z" if f.timestamp else None,
            }
            for f in findings
        ]
    }
    return json.dumps(report_dict, indent=2)
