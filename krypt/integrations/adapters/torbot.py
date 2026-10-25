"""
TorBot Adapter for KRYPT CLI.
Provides controlled Dark Web (.onion) OSINT gathering and link-tree mapping via Tor SOCKS5 proxy.
"""

import asyncio
from datetime import datetime
import json
import os
from pathlib import Path
import socket
from typing import Any, Dict, List, Optional, Tuple

from krypt.core.logger import logger, audit_log
from krypt.integrations.adapters.base import BaseAdapter
from krypt.integrations.models import AdapterResult
from krypt.safety.scope import ScopeEngine, ScopeViolationException


class TorBotAdapter(BaseAdapter):
    """
    Adapter for DedSecInside/TorBot darknet OSINT crawler.
    Enforces explicit onion opt-in, Tor SOCKS5 reachability verification,
    dry-run execution capabilities, and strict target scope boundaries.
    """

    def __init__(
        self,
        base_dir: Optional[Path] = None,
    ):
        root = base_dir or Path(__file__).resolve().parents[3]
        venv_path = root / "integrations" / "venvs" / "torbot"
        executable_path = venv_path / "bin" / "torbot"

        super().__init__(
            name="TorBot",
            display_name="TorBot Dark Web Intelligence Suite",
            venv_path=venv_path,
            executable_path=executable_path,
            upstream_repo="DedSecInside/TorBot",
            upstream_branch="dev",
            commit_sha="1cc500ff2bae6c2cce3a3accd3e55a9c69f51034",
            license_str="GPL-3.0",
            runtime_python="3.12.15",
            description="Dark web OSINT crawler and link-relationship analyzer for .onion services.",
            capabilities=[
                "onion_link_discovery",
                "hidden_service_metadata_inspection",
                "onion_email_extraction",
                "relationship_tree_mapping",
                "socks5_tor_routing",
            ],
            external_services=["local_tor_socks5_proxy"],
            safety_notes="Requires active Tor SOCKS5 daemon (default 127.0.0.1:9050 or 9150). Fail-closed opt-in.",
        )

    @classmethod
    def is_tor_proxy_alive(cls, host: str = "127.0.0.1", port: int = 9050, timeout: float = 1.5) -> bool:
        """Verify reachability of local Tor SOCKS5 proxy daemon."""
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    @classmethod
    def detect_tor_proxy(cls) -> Tuple[Optional[str], Optional[int]]:
        """Attempt discovery of active Tor proxy on standard ports (9050 or 9150)."""
        for port in (9050, 9150):
            if cls.is_tor_proxy_alive("127.0.0.1", port):
                return "127.0.0.1", port
        return None, None

    async def run(
        self,
        target: str,
        depth: int = 1,
        proxy_host: Optional[str] = None,
        proxy_port: Optional[int] = None,
        disable_socks5: bool = False,
        dry_run: bool = False,
        timeout: int = 60,
        **kwargs: Any,
    ) -> AdapterResult:
        """
        Execute TorBot crawl against target.
        """
        target_str = target.strip()
        result = self.init_result(target_str)

        # 1. Scope Verification
        # For onion domains or internet targets, verify scope
        is_valid, scope_err = self.validate_scope(
            target_str,
            is_active=True,
            allow_passive=False,
        )
        if not is_valid:
            result.block(scope_err or f"Target '{target_str}' is not registered in authorized scope.")
            result.completed_at = datetime.utcnow().isoformat() + "Z"
            return result

        if not self.is_installed():
            result.fail(f"TorBot executable not found at {self.executable_path}")
            result.completed_at = datetime.utcnow().isoformat() + "Z"
            return result

        # 2. Tor SOCKS5 Proxy Check
        effective_host = proxy_host or "127.0.0.1"
        effective_port = proxy_port or 9050

        if not disable_socks5:
            # Check configured port or auto-detect 9150
            if not self.is_tor_proxy_alive(effective_host, effective_port):
                detected_h, detected_p = self.detect_tor_proxy()
                if detected_h and detected_p:
                    effective_host, effective_port = detected_h, detected_p
                elif not dry_run:
                    result.fail(
                        f"Tor SOCKS5 proxy unreachable at {effective_host}:{effective_port}.\n"
                        f"TorBot requires an active Tor daemon to route traffic safely to hidden services.\n"
                        f"Start Tor via: 'brew services start tor' or specify a running proxy with --proxy-port."
                    )
                    result.completed_at = datetime.utcnow().isoformat() + "Z"
                    return result

        # 3. Dry-Run Handling
        if dry_run:
            result.status = "SUCCESS"
            result.findings.append({
                "category": "dry_run_plan",
                "item": target_str,
                "details": f"Dry-run validated. Target authorized in scope; Tor proxy configured at {effective_host}:{effective_port}.",
                "source_tool": self.name,
                "severity": "info",
                "extra": {
                    "depth": depth,
                    "proxy": f"{effective_host}:{effective_port}",
                    "disable_socks5": disable_socks5,
                },
            })
            result.completed_at = datetime.utcnow().isoformat() + "Z"
            return result

        # 4. Command Setup
        res_file_name = f"torbot_res_{result.run_id}.json"
        cmd = [
            str(self.executable_path),
            "-u", target_str,
            "--depth", str(max(1, min(depth, 3))),
            "--save", "json",
            "--result-file", res_file_name,
        ]
        if disable_socks5:
            cmd.append("--disable-socks5")
        else:
            cmd.extend(["--host", effective_host, "--port", str(effective_port)])

        audit_log("TORBOT_RUN", target_str, "INVOKE", f"Depth={depth} Proxy={effective_host}:{effective_port}")

        # 5. Execution
        exec_res = await self.execute_cmd(
            cmd=cmd,
            timeout=timeout,
            run_id=result.run_id,
        )

        result.completed_at = datetime.utcnow().isoformat() + "Z"
        result.scope = {
            "target": target_str,
            "depth": depth,
            "proxy": f"{effective_host}:{effective_port}" if not disable_socks5 else "disabled",
        }

        if exec_res.timed_out:
            result.fail(f"TorBot crawl timed out after {timeout} seconds.")
            return result

        # Evidence capture
        result.evidence.append({
            "evidence_id": f"ev_{result.run_id}_stdout",
            "tool": self.name,
            "evidence_type": "stdout",
            "content": exec_res.stdout[:50000],
            "created_at": datetime.utcnow().isoformat() + "Z",
        })

        if exec_res.stderr:
            result.evidence.append({
                "evidence_id": f"ev_{result.run_id}_stderr",
                "tool": self.name,
                "evidence_type": "stderr",
                "content": exec_res.stderr[:20000],
                "created_at": datetime.utcnow().isoformat() + "Z",
            })

        # 6. Parse structured result file
        json_file = exec_res.run_dir / res_file_name
        if json_file.exists():
            result.output_files.append(str(json_file))
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    result.raw_result = data
                    
                    # Extract findings from TorBot JSON schema
                    # Format can be dict or list of nodes
                    if isinstance(data, dict):
                        links = data.get("links", [])
                        emails = data.get("emails", [])
                        title = data.get("title", "")
                        if title:
                            result.findings.append({
                                "category": "page_title",
                                "item": title,
                                "details": f"HTML title for {target_str}",
                                "source_tool": self.name,
                                "severity": "info",
                            })
                        for link in links:
                            result.findings.append({
                                "category": "onion_link",
                                "item": str(link),
                                "details": "Discovered hyperlink on hidden service",
                                "source_tool": self.name,
                                "severity": "info",
                            })
                        for email in emails:
                            result.findings.append({
                                "category": "email",
                                "item": str(email),
                                "details": "Discovered email address on hidden service",
                                "source_tool": self.name,
                                "severity": "info",
                            })
            except Exception as e:
                result.add_error(f"Error parsing TorBot result JSON: {e}")

        # Parse from stdout if json was empty
        if not result.findings and exec_res.stdout:
            for line in exec_res.stdout.splitlines():
                sline = line.strip()
                if ".onion" in sline:
                    for token in sline.split():
                        if ".onion" in token and len(token) > 10:
                            result.findings.append({
                                "category": "onion_link",
                                "item": token.strip("(),'\""),
                                "details": "Onion address extracted from output stream",
                                "source_tool": self.name,
                                "severity": "info",
                            })

        if exec_res.exit_code != 0 and not result.findings:
            result.fail(f"TorBot exited with code {exec_res.exit_code}: {exec_res.stderr or exec_res.stdout[:200]}")
        elif exec_res.exit_code != 0 and result.findings:
            result.status = "PARTIAL"

        return result
