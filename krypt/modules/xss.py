"""
Defensive Cross-Site Scripting (XSS) Assessment Module for KRYPT CLI.
Detects reflected parameters and analyzes context-aware output encoding using harmless canary probes.
Does NOT execute destructive browser scripts or malicious actions.
"""

import html
import random
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

from krypt.core.http import http_client
from krypt.database.db import db
from krypt.database.models import FindingModel
from krypt.modules.base import BaseModule


class XSSModule(BaseModule):
    @property
    def name(self) -> str:
        return "xss"

    @property
    def description(self) -> str:
        return "Defensive Cross-Site Scripting (XSS) & Reflection Assessment"

    async def run(self, target: str, scan_id: Optional[str] = None, **kwargs) -> List[FindingModel]:
        """Test candidate endpoints for reflected XSS and inadequate HTML encoding."""
        self.check_scope(target)
        self._findings.clear()

        # Gather endpoints to test
        endpoints = [
            {"path": "/search", "params": ["q", "query", "term", "s"]},
            {"path": "/", "params": ["msg", "message", "name", "redirect", "search"]},
            {"path": "/profile", "params": ["name", "bio", "status"]},
            {"path": "/feedback", "params": ["comment", "message", "author"]},
        ]

        # Merge with discovered endpoints
        discovered = db.get_endpoints(target)
        for dep in discovered:
            parsed = urlparse(dep.url)
            path = parsed.path
            params = [p.strip() for p in (dep.parameters or "").split(",") if p.strip()]
            if params and not any(e["path"] == path for e in endpoints):
                endpoints.append({"path": path, "params": params, "method": dep.method})

        for ep in endpoints:
            path = ep["path"]
            method = ep.get("method", "GET")
            full_url = urljoin(target, path)
            for param in ep.get("params", []):
                await self._test_reflection(
                    target=target,
                    full_url=full_url,
                    path=path,
                    method=method,
                    param_name=param,
                    scan_id=scan_id
                )

        return self._findings

    async def _test_reflection(
        self,
        target: str,
        full_url: str,
        path: str,
        method: str,
        param_name: str,
        scan_id: Optional[str] = None
    ) -> None:
        """Inject unique harmless canary tokens and inspect reflection and encoding behavior."""
        nonce = f"{random.randint(10000, 99999)}"
        canary_tag = f"<krypt_probe_{nonce}>"
        canary_attr = f'"krypt_attr_{nonce}"'
        canary_js = f"'krypt_js_{nonce}'"

        test_payload = f"{canary_tag}{canary_attr}{canary_js}"
        params = {param_name: test_payload}

        if method == "POST":
            resp = await http_client.post(full_url, data=params)
        else:
            resp = await http_client.get(full_url, params=params)

        if not resp or resp.status_code not in (200, 400, 422, 500):
            return

        body = resp.text
        content_type = resp.headers.get("content-type", "")

        # If it's a JSON response, reflection isn't HTML XSS unless reflected unescaped in HTML context
        if "application/json" in content_type:
            return

        # Check unencoded tag reflection (<krypt_probe_...>)
        if canary_tag in body:
            ev_text = (
                f"Harmless test probe `{canary_tag}` was reflected completely unescaped in response body "
                f"at endpoint '{path}' in parameter '{param_name}'.\n"
                f"Content-Type: {content_type} | HTTP Status: {resp.status_code}."
            )
            
            self.add_finding(
                target_url=target,
                vulnerability="Reflected Cross-Site Scripting (XSS)",
                severity="HIGH",
                confidence="HIGH",
                endpoint=path,
                parameter=param_name,
                evidence_text=ev_text,
                impact=(
                    "Execution of arbitrary client-side JavaScript in victim browser sessions, "
                    "leading to session hijacking, defacement, or credential theft."
                ),
                remediation=(
                    "Implement context-aware contextual output encoding (HTML Entity Encoding, Attribute Encoding) "
                    "and enforce a strict Content-Security-Policy (CSP)."
                ),
                references=[
                    "https://owasp.org/www-community/attacks/xss/",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
                ],
                scan_id=scan_id,
                raw_evidence={
                    "request": {"url": full_url, "method": method, "parameter": param_name, "probe": test_payload},
                    "response": {"status_code": resp.status_code, "body_snippet": body[:1000]},
                    "observation": "Unencoded HTML tag reflection detected"
                }
            )
        elif canary_attr in body:
            ev_text = (
                f"Attribute probe `{canary_attr}` was reflected without quote escaping "
                f"at endpoint '{path}' in parameter '{param_name}'."
            )
            self.add_finding(
                target_url=target,
                vulnerability="Potential Attribute-Context XSS",
                severity="MEDIUM",
                confidence="MEDIUM",
                endpoint=path,
                parameter=param_name,
                evidence_text=ev_text,
                impact="Potential attribute breakout and client-side script execution.",
                remediation="Apply HTML attribute encoding to all user-controlled data inserted into HTML tag attributes.",
                references=["https://owasp.org/www-community/attacks/xss/"],
                scan_id=scan_id
            )
