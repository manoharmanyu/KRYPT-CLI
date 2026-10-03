"""
Markdown Report Generator for KRYPT CLI.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from krypt.database.models import FindingModel


def generate_markdown_report(
    target_url: str,
    findings: List[FindingModel],
    metadata: Optional[Dict[str, Any]] = None
) -> str:
    """Render findings into GitHub Flavored Markdown."""
    counts = {
        "CRITICAL": sum(1 for f in findings if f.severity == "CRITICAL"),
        "HIGH": sum(1 for f in findings if f.severity == "HIGH"),
        "MEDIUM": sum(1 for f in findings if f.severity == "MEDIUM"),
        "LOW": sum(1 for f in findings if f.severity == "LOW"),
    }

    lines = [
        f"# KRYPT CLI Security Assessment Report",
        f"",
        f"**Target:** `{target_url}`  ",
        f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
        f"**Author:** Gaddam Manyu (@manoharmanyu)  ",
        f"**Framework Version:** 0.1.0  ",
        f"",
        f"---",
        f"",
        f"## Executive Summary",
        f"",
        f"| Severity | Count |",
        f"| :--- | :---: |",
        f"| **CRITICAL** | {counts['CRITICAL']} |",
        f"| **HIGH** | {counts['HIGH']} |",
        f"| **MEDIUM** | {counts['MEDIUM']} |",
        f"| **LOW** | {counts['LOW']} |",
        f"| **TOTAL** | {len(findings)} |",
        f"",
        f"---",
        f"",
        f"## Findings Catalog",
        f"",
    ]

    if not findings:
        lines.append("*No security vulnerabilities identified in authorized scope.*")
    else:
        for f in findings:
            lines.extend([
                f"### [{f.severity}] {f.vulnerability} (`{f.id}`)",
                f"",
                f"- **Endpoint:** `{f.endpoint}`",
                f"- **Parameter:** `{f.parameter or 'N/A'}`",
                f"- **Module:** `{f.module}`",
                f"- **Confidence:** `{f.confidence}`",
                f"",
                f"#### Evidence",
                f"```text",
                f"{f.evidence or 'No evidence recorded.'}",
                f"```",
                f"",
                f"#### Impact",
                f"{f.impact or 'N/A'}",
                f"",
                f"#### Remediation",
                f"{f.remediation or 'N/A'}",
                f"",
                f"---",
                f"",
            ])

    return "\n".join(lines)
