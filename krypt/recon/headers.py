"""
Security Header and Cookie Analysis Engine for KRYPT CLI.
Evaluates HTTP response headers and cookie security flags against modern hardening standards.
"""

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
import httpx

from krypt.database.db import db
from krypt.evidence.redactor import redact_headers


@dataclass
class HeaderCheckResult:
    header_name: str
    status: str  # PASS, WARN, FAIL, INFO
    value: Optional[str]
    description: str
    recommendation: str


@dataclass
class CookieCheckResult:
    cookie_name: str
    has_secure: bool
    has_httponly: bool
    samesite: Optional[str]
    issues: List[str]


@dataclass
class SecurityHeadersReport:
    target_url: str
    score_percentage: int
    grade: str
    header_results: List[HeaderCheckResult]
    cookie_results: List[CookieCheckResult]
    server_disclosure: Optional[str] = None


class HeaderAnalyzer:
    """Security header analyzer and grader."""

    SECURITY_HEADERS = {
        "content-security-policy": {
            "name": "Content-Security-Policy",
            "desc": "Prevents XSS, data injection, and clickjacking attacks",
            "rec": "Define a robust CSP policy avoiding 'unsafe-inline' and 'unsafe-eval'",
        },
        "strict-transport-security": {
            "name": "Strict-Transport-Security",
            "desc": "Enforces secure HTTPS communication and prevents downgrade attacks",
            "rec": "Set 'max-age=31536000; includeSubDomains; preload'",
        },
        "x-frame-options": {
            "name": "X-Frame-Options",
            "desc": "Mitigates Clickjacking by controlling iframe embedding",
            "rec": "Set to 'DENY' or 'SAMEORIGIN'",
        },
        "x-content-type-options": {
            "name": "X-Content-Type-Options",
            "desc": "Prevents MIME-sniffing vulnerabilities",
            "rec": "Set to 'nosniff'",
        },
        "referrer-policy": {
            "name": "Referrer-Policy",
            "desc": "Controls referrer information sent in HTTP requests",
            "rec": "Set to 'strict-origin-when-cross-origin' or 'no-referrer'",
        },
        "permissions-policy": {
            "name": "Permissions-Policy",
            "desc": "Restricts browser feature and API access (camera, mic, geo)",
            "rec": "Explicitly disable unused browser permissions",
        },
    }

    @classmethod
    def analyze(
        cls,
        target_url: str,
        response: Optional[httpx.Response] = None,
        headers: Optional[Dict[str, str]] = None,
        cookies: Optional[List[str]] = None
    ) -> SecurityHeadersReport:
        """Run complete security header and cookie audit."""
        resp_headers = {k.lower(): v for k, v in (headers or (response.headers if response else {})).items()}
        
        header_results: List[HeaderCheckResult] = []
        passed_count = 0

        for h_key, meta in cls.SECURITY_HEADERS.items():
            if h_key in resp_headers:
                val = resp_headers[h_key]
                header_results.append(
                    HeaderCheckResult(
                        header_name=meta["name"],
                        status="PASS",
                        value=val,
                        description=meta["desc"],
                        recommendation=""
                    )
                )
                passed_count += 1
            else:
                header_results.append(
                    HeaderCheckResult(
                        header_name=meta["name"],
                        status="FAIL",
                        value=None,
                        description=meta["desc"],
                        recommendation=meta["rec"]
                    )
                )

        # Server information disclosure check
        server_val = resp_headers.get("server") or resp_headers.get("x-powered-by")
        server_disclosure = server_val if server_val else None

        # Cookie analysis
        cookie_results: List[CookieCheckResult] = []
        raw_cookie_headers: List[str] = []
        if response and "set-cookie" in response.headers:
            # Handle multiple set-cookie headers
            raw_cookie_headers = [c for c in response.headers.get_list("set-cookie")]
        elif "set-cookie" in resp_headers:
            raw_cookie_headers = [resp_headers["set-cookie"]]

        for raw_c in raw_cookie_headers:
            parts = [p.strip() for p in raw_c.split(";")]
            if not parts:
                continue
            name_val = parts[0].split("=", 1)
            c_name = name_val[0]
            
            parts_lower = [p.lower() for p in parts[1:]]
            has_secure = "secure" in parts_lower
            has_httponly = "httponly" in parts_lower
            
            samesite_val = None
            for p in parts[1:]:
                if p.lower().startswith("samesite="):
                    samesite_val = p.split("=", 1)[1].strip()

            issues = []
            if not has_secure:
                issues.append("Missing 'Secure' flag")
            if not has_httponly:
                issues.append("Missing 'HttpOnly' flag")
            if not samesite_val:
                issues.append("Missing 'SameSite' attribute")
            elif samesite_val.lower() == "none" and not has_secure:
                issues.append("SameSite=None without Secure flag")

            cookie_results.append(
                CookieCheckResult(
                    cookie_name=c_name,
                    has_secure=has_secure,
                    has_httponly=has_httponly,
                    samesite=samesite_val,
                    issues=issues
                )
            )

        total_headers = len(cls.SECURITY_HEADERS)
        score_pct = int((passed_count / total_headers) * 100)
        
        if score_pct >= 85:
            grade = "A"
        elif score_pct >= 65:
            grade = "B"
        elif score_pct >= 45:
            grade = "C"
        elif score_pct >= 25:
            grade = "D"
        else:
            grade = "F"

        return SecurityHeadersReport(
            target_url=target_url,
            score_percentage=score_pct,
            grade=grade,
            header_results=header_results,
            cookie_results=cookie_results,
            server_disclosure=server_disclosure
        )
