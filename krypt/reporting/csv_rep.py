"""
CSV Export Generator for KRYPT CLI.
"""

import csv
import io
from typing import Any, Dict, List, Optional
from krypt.database.models import FindingModel


def generate_csv_report(
    target_url: str,
    findings: List[FindingModel],
    metadata: Optional[Dict[str, Any]] = None
) -> str:
    """Generate CSV string of findings."""
    output = io.StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow([
        "ID", "Target", "Module", "Vulnerability", "Severity",
        "Confidence", "Endpoint", "Parameter", "Evidence", "Impact", "Remediation", "Timestamp"
    ])

    for f in findings:
        writer.writerow([
            f.id,
            f.target_url,
            f.module,
            f.vulnerability,
            f.severity,
            f.confidence,
            f.endpoint,
            f.parameter,
            f.evidence,
            f.impact,
            f.remediation,
            f.timestamp.isoformat() if f.timestamp else ""
        ])

    return output.getvalue()
