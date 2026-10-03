"""
Insecure Direct Object Reference (IDOR) Assessment Module for KRYPT CLI.
Tests object-level authorization by validating whether resource identifiers can be accessed across tenant boundaries.
"""

from typing import Any, Dict, List, Optional
from urllib.parse import urljoin

from krypt.core.http import http_client
from krypt.database.models import FindingModel
from krypt.modules.base import BaseModule

IDOR_CANDIDATES = [
    {"path": "/profile", "param": "id", "val_a": "1", "val_b": "2"},
    {"path": "/api/users", "param": "id", "val_a": "1", "val_b": "2"},
    {"path": "/api/orders", "param": "id", "val_a": "101", "val_b": "102"},
    {"path": "/account", "param": "user_id", "val_a": "1", "val_b": "2"},
]


class IDORModule(BaseModule):
    @property
    def name(self) -> str:
        return "idor"

    @property
    def description(self) -> str:
        return "Insecure Direct Object Reference (IDOR) & Object-Level Authorization Assessment"

    async def run(self, target: str, scan_id: Optional[str] = None, **kwargs) -> List[FindingModel]:
        """Test for missing object-level access controls across numerical/identifier resources."""
        self.check_scope(target)
        self._findings.clear()

        # Test configured candidate paths
        for candidate in IDOR_CANDIDATES:
            path = candidate["path"]
            param = candidate["param"]
            val_a = candidate["val_a"]
            val_b = candidate["val_b"]

            url_a = urljoin(target, f"{path}?{param}={val_a}")
            url_b = urljoin(target, f"{path}?{param}={val_b}")

            resp_a = await http_client.get(url_a)
            resp_b = await http_client.get(url_b)

            if resp_a and resp_b and resp_a.status_code == 200 and resp_b.status_code == 200:
                # If both returned 200 and their bodies contain distinct non-empty contents
                if resp_a.text != resp_b.text and len(resp_a.text) > 20 and len(resp_b.text) > 20:
                    ev_text = (
                        f"Resource access across distinct object IDs (`{param}={val_a}` vs `{param}={val_b}`) "
                        f"at endpoint '{path}' succeeded without authorization challenge (HTTP 200 on both requests).\n"
                        f"Response bodies differ, indicating access to multiple user records."
                    )

                    self.add_finding(
                        target_url=target,
                        vulnerability="Insecure Direct Object Reference (IDOR)",
                        severity="HIGH",
                        confidence="HIGH",
                        endpoint=path,
                        parameter=param,
                        evidence_text=ev_text,
                        impact=(
                            "Horizontal privilege escalation: an unprivileged user can view or alter records "
                            "belonging to other users by modifying the object identifier."
                        ),
                        remediation=(
                            "Implement server-side authorization checks verifying that the requesting user "
                            "owns or is explicitly permitted to access the requested resource object ID."
                        ),
                        references=[
                            "https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html",
                            "https://cwe.mitre.org/data/definitions/639.html"
                        ],
                        scan_id=scan_id,
                        raw_evidence={
                            "request_a": {"url": url_a},
                            "response_a_status": resp_a.status_code,
                            "request_b": {"url": url_b},
                            "response_b_status": resp_b.status_code,
                            "observation": f"Direct object iteration on {param} yielded unauthenticated records"
                        }
                    )

        return self._findings
