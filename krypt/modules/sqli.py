"""
Defensive SQL Injection Assessment Module for KRYPT CLI.
Performs controlled parameter probing, syntax boundary analysis, and error signature detection.
Does NOT perform database dumping, data extraction, or destructive modification.
"""

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse, parse_qs, urlencode

from krypt.core.http import http_client
from krypt.database.db import db
from krypt.database.models import FindingModel
from krypt.evidence.store import EvidenceStore
from krypt.modules.base import BaseModule

# Common SQL syntax error signatures across database engines
SQL_ERROR_PATTERNS = [
    (re.compile(r"sqlite3\.OperationalError|syntax error near|unrecognized token", re.IGNORECASE), "SQLite"),
    (re.compile(r"You have an error in your SQL syntax|mysql_fetch_|check the manual that corresponds to your MySQL", re.IGNORECASE), "MySQL"),
    (re.compile(r"PG::SyntaxError|unterminated quoted string at or near|ERROR:\s+syntax error at or near", re.IGNORECASE), "PostgreSQL"),
    (re.compile(r"Microsoft OLE DB Provider for SQL Server|Unclosed quotation mark before the character string", re.IGNORECASE), "MSSQL"),
    (re.compile(r"ORA-01756|quoted string not properly terminated|ORA-00933", re.IGNORECASE), "Oracle"),
]

# Controlled, benign probe characters for boundary detection
PROBES = [
    ("'", "Single quote syntax boundary probe"),
    ("''", "Escaped double-single quote normalization probe"),
    ("' OR '1'='1", "Controlled boolean tautology probe"),
    ("' AND '1'='2", "Controlled boolean false probe"),
]


class SQLInjectionModule(BaseModule):
    @property
    def name(self) -> str:
        return "sqli"

    @property
    def description(self) -> str:
        return "Defensive SQL Injection Assessment (Error & Boolean Differential Analysis)"

    async def run(self, target: str, scan_id: Optional[str] = None, **kwargs) -> List[FindingModel]:
        """Run controlled SQL injection assessment against discovered and common endpoints."""
        self.check_scope(target)
        self._findings.clear()

        # Gather target endpoints to test
        endpoints_to_test = [
            {"path": "/search", "params": ["q", "query", "term", "id", "search"]},
            {"path": "/login", "method": "POST", "params": ["username", "email", "user"]},
            {"path": "/api/users", "params": ["id", "user_id", "filter"]},
            {"path": "/profile", "params": ["id", "user"]},
            {"path": "/items", "params": ["id", "category"]},
        ]

        # Merge with any endpoints previously discovered by crawler
        discovered_eps = db.get_endpoints(target)
        for dep in discovered_eps:
            parsed = urlparse(dep.url)
            path = parsed.path
            params = [p.strip() for p in (dep.parameters or "").split(",") if p.strip()]
            if params and not any(e["path"] == path for e in endpoints_to_test):
                endpoints_to_test.append({"path": path, "params": params, "method": dep.method})

        for ep in endpoints_to_test:
            path = ep["path"]
            method = ep.get("method", "GET")
            full_url = urljoin(target, path)
            params_list = ep.get("params", ["id"])

            for param_name in params_list:
                await self._test_parameter(
                    target=target,
                    full_url=full_url,
                    path=path,
                    method=method,
                    param_name=param_name,
                    scan_id=scan_id
                )

        return self._findings

    async def _test_parameter(
        self,
        target: str,
        full_url: str,
        path: str,
        method: str,
        param_name: str,
        scan_id: Optional[str] = None
    ) -> None:
        """Perform controlled syntax and differential tests on a single parameter."""
        # 1. Baseline request
        baseline_params = {param_name: "test123"}
        if method == "POST":
            baseline_resp = await http_client.post(full_url, data=baseline_params)
        else:
            baseline_resp = await http_client.get(full_url, params=baseline_params)

        if not baseline_resp:
            return

        baseline_status = baseline_resp.status_code
        baseline_len = len(baseline_resp.text)

        # 2. Test benign syntax probes
        for probe_val, probe_desc in PROBES:
            test_params = {param_name: probe_val}
            if method == "POST":
                resp = await http_client.post(full_url, data=test_params)
            else:
                resp = await http_client.get(full_url, params=test_params)

            if not resp:
                continue

            resp_text = resp.text

            # Check for database error messages
            for error_regex, db_engine in SQL_ERROR_PATTERNS:
                if error_regex.search(resp_text) and not error_regex.search(baseline_resp.text):
                    ev_text = (
                        f"Controlled probe `{probe_val}` elicited unhandled database error signature "
                        f"for {db_engine} at endpoint '{path}' in parameter '{param_name}'.\n"
                        f"Response status: {resp.status_code} (Baseline: {baseline_status})."
                    )

                    finding = self.add_finding(
                        target_url=target,
                        vulnerability=f"SQL Injection ({db_engine})",
                        severity="CRITICAL",
                        confidence="HIGH",
                        endpoint=path,
                        parameter=param_name,
                        evidence_text=ev_text,
                        impact=(
                            "Potential unauthorized database read/write access, authentication bypass, "
                            "or data exposure."
                        ),
                        remediation=(
                            "Use parameterized queries (prepared statements) or an established Object-Relational "
                            "Mapping (ORM) layer. Never concatenate user input directly into SQL statements."
                        ),
                        references=[
                            "https://owasp.org/www-community/attacks/SQL_Injection",
                            "https://cwe.mitre.org/data/definitions/89.html"
                        ],
                        scan_id=scan_id,
                        raw_evidence={
                            "request": {"url": full_url, "method": method, "parameter": param_name, "probe": probe_val},
                            "response": {"status_code": resp.status_code, "body_snippet": resp_text[:1000]},
                            "observation": f"Matched error signature for {db_engine}"
                        }
                    )
                    return  # Parameter already confirmed vulnerable

            # Check for boolean differential anomaly (e.g. ' OR '1'='1 causes status 200/auth bypass or distinct response)
            if probe_val == "' OR '1'='1" and resp.status_code == 200 and baseline_status != 200:
                ev_text = (
                    f"Controlled boolean condition probe `{probe_val}` caused significant response state change "
                    f"(HTTP {resp.status_code} vs Baseline HTTP {baseline_status}) at endpoint '{path}'."
                )
                self.add_finding(
                    target_url=target,
                    vulnerability="Potential SQL Injection (Boolean Differential)",
                    severity="HIGH",
                    confidence="MEDIUM",
                    endpoint=path,
                    parameter=param_name,
                    evidence_text=ev_text,
                    impact="Potential authentication bypass or logic alteration via SQL injection.",
                    remediation="Employ parameterized statements with bind variables for all SQL query parameters.",
                    references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                    scan_id=scan_id
                )
                return
