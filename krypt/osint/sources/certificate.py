"""
TLS Certificate Intelligence Source for KRYPT CLI.
Inspects live TLS certificates, Subject Alternative Names (SANs), issuers, and validity dates.
"""

import asyncio
import hashlib
import socket
import ssl
from typing import Any, Dict, List, Optional

from krypt.osint.models import CertificateInfo, IntelReport
from krypt.osint.sources.base import BaseSource
from krypt.core.logger import logger


class CertificateSource(BaseSource):
    @property
    def name(self) -> str:
        return "TLS Certificate Inspector"

    @property
    def category(self) -> str:
        return "Certificate"

    async def collect(self, domain: str) -> Dict[str, Any]:
        """Fetch and inspect TLS certificate via SSL handshake."""
        loop = asyncio.get_event_loop()

        def _fetch_cert() -> Optional[Dict[str, Any]]:
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

                with socket.create_connection((domain, 443), timeout=3.0) as sock:
                    with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                        der_cert = ssock.getpeercert(binary_form=True)
                        parsed_cert = ssock.getpeercert()

                        if not der_cert:
                            return None

                        sha256_fp = hashlib.sha256(der_cert).hexdigest()

                        # Extract SANs
                        sans = []
                        if parsed_cert and "subjectAltName" in parsed_cert:
                            for typ, val in parsed_cert["subjectAltName"]:
                                if typ.lower() in ("dns", "ip"):
                                    sans.append(val)

                        # Extract Subject and Issuer strings
                        subject_str = ""
                        if parsed_cert and "subject" in parsed_cert:
                            subject_parts = [f"{k}={v}" for r in parsed_cert["subject"] for k, v in r]
                            subject_str = ", ".join(subject_parts)

                        issuer_str = ""
                        if parsed_cert and "issuer" in parsed_cert:
                            issuer_parts = [f"{k}={v}" for r in parsed_cert["issuer"] for k, v in r]
                            issuer_str = ", ".join(issuer_parts)

                        return {
                            "subject": subject_str or domain,
                            "issuer": issuer_str or "Unknown Issuer",
                            "valid_from": parsed_cert.get("notBefore") if parsed_cert else None,
                            "valid_to": parsed_cert.get("notAfter") if parsed_cert else None,
                            "sans": sans,
                            "serial_number": str(parsed_cert.get("serialNumber")) if parsed_cert else None,
                            "fingerprint_sha256": sha256_fp,
                        }
            except Exception as e:
                logger.debug(f"TLS cert fetch error for {domain}: {e}")
                return None

        cert_data = await loop.run_in_executor(None, _fetch_cert)
        return {"domain": domain, "certificate": cert_data}

    def normalize(self, raw_data: Dict[str, Any], report: IntelReport) -> None:
        cert = raw_data.get("certificate")
        if cert:
            report.certificate = CertificateInfo(
                subject=cert.get("subject", ""),
                issuer=cert.get("issuer", ""),
                valid_from=cert.get("valid_from"),
                valid_to=cert.get("valid_to"),
                sans=cert.get("sans", []),
                serial_number=cert.get("serial_number"),
                fingerprint_sha256=cert.get("fingerprint_sha256")
            )
            # Add SANs to subdomains if they belong to target
            for san in cert.get("sans", []):
                san_clean = san.strip().lower()
                if san_clean.startswith("*."):
                    san_clean = san_clean[2:]
                if report.target_domain in san_clean and not any(s.hostname == san_clean for s in report.subdomains):
                    report.subdomains.append(
                        SubdomainInfo(
                            hostname=san_clean,
                            source="certificate_san",
                            status="discovered"
                        )
                    )
