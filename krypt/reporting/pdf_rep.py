"""
Pure-Python PDF Report Generator for KRYPT CLI.
Generates compliant, standalone PDF documents without external C/GUI dependencies.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from krypt.database.models import FindingModel


class SimplePdfWriter:
    """Minimal compliant PDF 1.4 generator."""

    def __init__(self):
        self.objects: List[bytes] = []

    def _add_object(self, data: bytes) -> int:
        self.objects.append(data)
        return len(self.objects)

    def generate(self, title: str, text_lines: List[str]) -> bytes:
        # 1. Font Object
        font_id = 1
        
        # Build text stream
        stream_lines = ["BT", "/F1 11 Tf", "50 780 Td", "14 TL"]
        # Add title
        stream_lines.append(f"/F1 16 Tf ({self._escape(title)}) Tj T*")
        stream_lines.append("/F1 10 Tf 14 TL T*")

        y = 750
        for line in text_lines:
            # Word wrap or truncate lines to avoid running off page
            clean = self._escape(line[:100])
            stream_lines.append(f"({clean}) Tj T*")

        stream_lines.append("ET")
        stream_content = "\n".join(stream_lines).encode("latin1", errors="replace")

        # PDF structure
        obj1 = b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"
        obj2 = f"<< /Length {len(stream_content)} >>\nstream\n".encode("ascii") + stream_content + b"\nendstream"
        obj3 = b"<< /Type /Page /Parent 4 0 R /MediaBox [0 0 595 842] /Contents 2 0 R /Resources << /Font << /F1 1 0 R >> >> >>"
        obj4 = b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>"
        obj5 = b"<< /Type /Catalog /Pages 4 0 R >>"

        objs = [obj1, obj2, obj3, obj4, obj5]

        out = bytearray(b"%PDF-1.4\n")
        xref_offsets = [0]

        for i, obj_data in enumerate(objs, 1):
            xref_offsets.append(len(out))
            out.extend(f"{i} 0 obj\n".encode("ascii"))
            out.extend(obj_data)
            out.extend(b"\nendobj\n")

        xref_start = len(out)
        out.extend(f"xref\n0 {len(objs) + 1}\n0000000000 65535 f \n".encode("ascii"))
        for offset in xref_offsets[1:]:
            out.extend(f"{offset:010d} 00000 n \n".encode("ascii"))

        out.extend(f"trailer\n<< /Size {len(objs) + 1} /Root 5 0 R >>\nstartxref\n{xref_start}\n%%EOF\n".encode("ascii"))
        return bytes(out)

    def _escape(self, text: str) -> str:
        return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def generate_pdf_report(
    target_url: str,
    findings: List[FindingModel],
    metadata: Optional[Dict[str, Any]] = None
) -> bytes:
    """Generate PDF bytes for the security assessment report."""
    writer = SimplePdfWriter()
    lines = [
        f"KRYPT CLI Security Assessment Report",
        f"Target: {target_url}",
        f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"Author: Gaddam Manyu (@manoharmanyu)",
        f"Total Findings: {len(findings)}",
        "--------------------------------------------------------------------------------",
        "",
        "FINDINGS SUMMARY:",
    ]

    for f in findings:
        lines.append(f"[{f.severity}] {f.vulnerability} (ID: {f.id})")
        lines.append(f"  Endpoint: {f.endpoint} | Param: {f.parameter or 'N/A'}")
        if f.evidence:
            first_line = f.evidence.splitlines()[0] if f.evidence else ""
            lines.append(f"  Evidence: {first_line[:80]}")
        lines.append("")

    if not findings:
        lines.append("No security vulnerabilities detected within scope.")

    return writer.generate(f"KRYPT Report - {target_url}", lines)
