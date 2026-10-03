"""
Authorization & Broken Access Control Assessment Module for KRYPT CLI.
Tests access boundaries for privileged, administrative, and restricted endpoints.
"""

from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from krypt.core.http import http_client
from krypt.database.models import FindingModel
from krypt.modules.base import BaseModule

ADMIN_CANDIDATE_PATHS = [
    "/admin",
    "/admin/dashboard",
    "/admin/users",
    "/admin/settings",
    "/api/admin/users",
    "/api/admin/stats",
    "/manage",
    "/administrator",
]


class AuthorizationModule(BaseModule):
    @property
    def name(self) -> str:
        return "authz"

    @property
    def description(self) -> str:
        return "Authorization & Broken Access Control Assessment (Admin Route Boundaries)"

    async def run(self, target: str, scan_id: Optional[str] = None, **kwargs) -> List[FindingModel]:
        """Test access boundaries on privileged routes without credentials or with unprivileged token."""
        self.check_scope(target)
        self._findings.clear()

        # Check explicit test headers if provided (e.g. lab identity)
        test_headers = kwargs.get("headers", {})

        for path in ADMIN_CANDIDATE_PATHS:
            full_url = urljoin(target, path)
            resp = await http_client.get(full_url, headers=test_headers)

            if not resp:
                continue

            # If an administrative endpoint returns 200 OK without redirecting to login or returning 401/403
            if resp.status_code == 200:
                body_lower = resp.text.lower()
                # Ensure it's not a generic 404 or login page returning 200
                is_admin_content = any(k in body_lower for k in ("admin", "dashboard", "user list", "manage", "role", "privilege", "system"))
                is_login_page = "password" in body_lower and ("login" in body_lower or "sign in" in body_lower)

                if is_admin_content and not is_login_page:
                    ev_text = (
                        f"Privileged administrative route '{path}' was directly accessible "
                        f"without valid administrator credentials (HTTP status {resp.status_code})."
                    )

                    self.add_finding(
                        target_url=target,
                        vulnerability="Broken Access Control (Unrestricted Administrative Endpoint)",
                        severity="HIGH",
                        confidence="HIGH",
                        endpoint=path,
                        parameter="N/A",
                        evidence_text=ev_text,
                        impact=(
                            "Unauthenticated or unprivileged users can access administrative controls, "
                            "view sensitive operational data, or manipulate configurations."
                        ),
                        remediation=(
                            "Enforce strict server-side role-based access control (RBAC) checks on all "
                            "administrative routes and APIs. Deny access by default."
                        ),
                        references=[
                            "https://owasp.org/Top10/A01_2021-Broken_Access_Control/",
                            "https://cwe.mitre.org/data/definitions/284.html"
                        ],
                        scan_id=scan_id,
                        raw_evidence={
                            "request": {"url": full_url, "method": "GET"},
                            "response": {"status_code": resp.status_code, "body_snippet": resp.text[:1000]},
                            "observation": f"Unprotected admin endpoint {path} returned HTTP 200"
                        }
                    )

        return self._findings
