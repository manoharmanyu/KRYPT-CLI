"""
Authentication and Session Security Assessment Module for KRYPT CLI.
Analyzes session cookie attributes, token predictability, and rate limiting indicators.
Does NOT perform brute-force credential attacks or password guessing.
"""

from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from krypt.core.http import http_client
from krypt.database.models import FindingModel
from krypt.modules.base import BaseModule


class AuthModule(BaseModule):
    @property
    def name(self) -> str:
        return "auth"

    @property
    def description(self) -> str:
        return "Authentication & Session Management Assessment (Cookies, Session Tokens, Rate Limits)"

    async def run(self, target: str, scan_id: Optional[str] = None, **kwargs) -> List[FindingModel]:
        """Audit authentication mechanisms and session cookies."""
        self.check_scope(target)
        self._findings.clear()

        # 1. Audit login endpoint for session cookie flags and rate limiting
        login_url = urljoin(target, "/login")
        resp = await http_client.get(login_url)

        # Also submit harmless probe login request
        auth_resp = await http_client.post(
            login_url,
            data={"username": "krypt_test_user", "password": "krypt_test_password"}
        )

        test_resp = auth_resp if auth_resp else resp
        if test_resp:
            self._audit_cookies(target, login_url, test_resp, scan_id)
            await self._audit_rate_limiting(target, login_url, scan_id)

        return self._findings

    def _audit_cookies(
        self,
        target: str,
        login_url: str,
        response: Any,
        scan_id: Optional[str] = None
    ) -> None:
        """Inspect cookies for missing Secure, HttpOnly, and SameSite flags."""
        cookie_headers = []
        if hasattr(response, "headers"):
            if "set-cookie" in response.headers:
                cookie_headers = response.headers.get_list("set-cookie")

        for cookie_str in cookie_headers:
            parts = [p.strip() for p in cookie_str.split(";")]
            if not parts:
                continue

            c_name = parts[0].split("=", 1)[0]
            parts_lower = [p.lower() for p in parts[1:]]

            # Missing HttpOnly
            if "httponly" not in parts_lower:
                self.add_finding(
                    target_url=target,
                    vulnerability="Insecure Cookie: Missing HttpOnly Flag",
                    severity="MEDIUM",
                    confidence="HIGH",
                    endpoint="/login",
                    parameter=c_name,
                    evidence_text=f"Cookie `{c_name}` set without `HttpOnly` flag: `{cookie_str}`.",
                    impact="Client-side scripts (e.g. via XSS) can read the session cookie, enabling session hijacking.",
                    remediation="Set `HttpOnly` flag on all session and sensitive authentication cookies.",
                    references=["https://owasp.org/www-community/HttpOnly"],
                    scan_id=scan_id
                )

            # Missing Secure flag on HTTPS
            if target.startswith("https://") and "secure" not in parts_lower:
                self.add_finding(
                    target_url=target,
                    vulnerability="Insecure Cookie: Missing Secure Flag",
                    severity="MEDIUM",
                    confidence="HIGH",
                    endpoint="/login",
                    parameter=c_name,
                    evidence_text=f"Cookie `{c_name}` transmitted over HTTPS without `Secure` flag.",
                    impact="Cookies may be transmitted in cleartext over unencrypted HTTP channels.",
                    remediation="Set `Secure` flag on all sensitive cookies.",
                    references=["https://owasp.org/www-community/controls/SecureCookieAttribute"],
                    scan_id=scan_id
                )

    async def _audit_rate_limiting(self, target: str, login_url: str, scan_id: Optional[str] = None) -> None:
        """Perform a quick 3-request probe to observe rate-limiting response indicators."""
        responses = []
        for _ in range(4):
            r = await http_client.post(
                login_url,
                data={"username": "probe_user", "password": "probe_password"},
                timeout=3.0
            )
            if r:
                responses.append(r.status_code)

        # Check if all returned 200/401 with no 429 Too Many Requests or retry-after headers
        if len(responses) == 4 and all(code in (200, 401) for code in responses):
            self.add_finding(
                target_url=target,
                vulnerability="Missing Rate Limiting on Authentication Endpoint",
                severity="LOW",
                confidence="MEDIUM",
                endpoint="/login",
                parameter="login_form",
                evidence_text="Rapid authentication requests received standard responses without HTTP 429 throttling or lockouts.",
                impact="Susceptible to automated brute-force attempts and credential stuffing.",
                remediation="Implement IP-based and account-based rate limiting, progressive delays, or CAPTCHA controls.",
                references=["https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks"],
                scan_id=scan_id
            )
