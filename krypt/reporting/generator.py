"""
Unified Report Generator for KRYPT CLI.
Coordinates multiple export formats (terminal, JSON, HTML, PDF, Markdown, CSV).
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console

from krypt.database.db import db
from krypt.database.models import FindingModel
from krypt.reporting.csv_rep import generate_csv_report
from krypt.reporting.html_rep import generate_html_report
from krypt.reporting.json_rep import generate_json_report
from krypt.reporting.md_rep import generate_markdown_report
from krypt.reporting.pdf_rep import generate_pdf_report
from krypt.reporting.terminal import TerminalReporter
from krypt.utils.filesystem import get_reports_path


class ReportGenerator:
    """Coordinates reporting generation across formats."""

    @classmethod
    def generate(
        cls,
        target_url: Optional[str] = None,
        severity: Optional[str] = None,
        format_type: str = "terminal",
        output_path: Optional[str] = None,
        console: Optional[Console] = None
    ) -> Optional[str]:
        """Generate and save or display security report."""
        findings = db.get_findings(severity=severity, target=target_url)
        target_display = target_url or "All Registered Targets"
        
        timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        target_slug = (target_url or "krypt_assessment").replace("://", "_").replace("/", "_").replace(":", "_")

        fmt = format_type.lower()

        if fmt == "terminal":
            reporter = TerminalReporter(console=console)
            reporter.render_findings_table(findings, title=f"KRYPT Report: {target_display}")
            return None

        elif fmt == "json":
            content = generate_json_report(target_display, findings)
            dest = Path(output_path) if output_path else get_reports_path(f"report_{target_slug}_{timestamp_str}.json")
            with open(dest, "w", encoding="utf-8") as f:
                f.write(content)
            return str(dest)

        elif fmt == "html":
            content = generate_html_report(target_display, findings)
            dest = Path(output_path) if output_path else get_reports_path(f"report_{target_slug}_{timestamp_str}.html")
            with open(dest, "w", encoding="utf-8") as f:
                f.write(content)
            return str(dest)

        elif fmt == "md" or fmt == "markdown":
            content = generate_markdown_report(target_display, findings)
            dest = Path(output_path) if output_path else get_reports_path(f"report_{target_slug}_{timestamp_str}.md")
            with open(dest, "w", encoding="utf-8") as f:
                f.write(content)
            return str(dest)

        elif fmt == "csv":
            content = generate_csv_report(target_display, findings)
            dest = Path(output_path) if output_path else get_reports_path(f"report_{target_slug}_{timestamp_str}.csv")
            with open(dest, "w", encoding="utf-8") as f:
                f.write(content)
            return str(dest)

        elif fmt == "pdf":
            pdf_bytes = generate_pdf_report(target_display, findings)
            dest = Path(output_path) if output_path else get_reports_path(f"report_{target_slug}_{timestamp_str}.pdf")
            with open(dest, "wb") as f:
                f.write(pdf_bytes)
            return str(dest)

        else:
            raise ValueError(f"Unsupported report format: {format_type}. Supported: terminal, json, html, pdf, md, csv")
