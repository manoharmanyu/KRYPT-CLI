"""
Unit tests for Report Generators (JSON, HTML, Markdown, CSV, PDF).
"""

from datetime import datetime
from krypt.database.models import FindingModel
from krypt.reporting.csv_rep import generate_csv_report
from krypt.reporting.html_rep import generate_html_report
from krypt.reporting.json_rep import generate_json_report
from krypt.reporting.md_rep import generate_markdown_report
from krypt.reporting.pdf_rep import generate_pdf_report


def mock_findings():
    return [
        FindingModel(
            id="KRYPT-2026-TEST01",
            target_url="http://127.0.0.1:8888",
            module="sqli",
            vulnerability="SQL Injection (SQLite)",
            severity="CRITICAL",
            confidence="HIGH",
            endpoint="/search",
            parameter="q",
            evidence="Controlled syntax probe elicited database error signature.",
            impact="Database compromise.",
            remediation="Use parameterized queries.",
            references_json='["https://owasp.org"]',
            timestamp=datetime.utcnow()
        )
    ]


def test_json_report_generation():
    findings = mock_findings()
    res = generate_json_report("http://127.0.0.1:8888", findings)
    assert "KRYPT CLI" in res
    assert "KRYPT-2026-TEST01" in res
    assert "CRITICAL" in res


def test_html_report_generation():
    findings = mock_findings()
    res = generate_html_report("http://127.0.0.1:8888", findings)
    assert "<!DOCTYPE html>" in res
    assert "KRYPT CLI Assessment Report" in res
    assert "SQL Injection (SQLite)" in res


def test_markdown_report_generation():
    findings = mock_findings()
    res = generate_markdown_report("http://127.0.0.1:8888", findings)
    assert "# KRYPT CLI Security Assessment Report" in res
    assert "SQL Injection (SQLite)" in res


def test_csv_report_generation():
    findings = mock_findings()
    res = generate_csv_report("http://127.0.0.1:8888", findings)
    assert "ID,Target,Module,Vulnerability,Severity" in res
    assert "KRYPT-2026-TEST01" in res


def test_pdf_report_generation():
    findings = mock_findings()
    pdf_bytes = generate_pdf_report("http://127.0.0.1:8888", findings)
    assert pdf_bytes.startswith(b"%PDF-1.4")
    assert len(pdf_bytes) > 200
