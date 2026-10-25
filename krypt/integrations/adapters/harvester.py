"""
theHarvester Adapter for KRYPT CLI.
Provides multi-source OSINT harvesting (domains, hosts, IPs, emails) with strict scope controls.
"""

from datetime import datetime
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from krypt.core.logger import logger, audit_log
from krypt.integrations.adapters.base import BaseAdapter
from krypt.integrations.models import AdapterResult, ToolFinding
from krypt.safety.validator import is_valid_domain


class HarvesterAdapter(BaseAdapter):
    """
    Adapter for laramies/theHarvester OSINT reconnaissance engine.
    Passive OSINT is permitted across public targets; active DNS/vhost brute-force
    strictly requires an authorized, registered target in KRYPT's scope database.
    """

    def __init__(
        self,
        base_dir: Optional[Path] = None,
    ):
        root = base_dir or Path(__file__).resolve().parents[3]
        venv_path = root / "integrations" / "venvs" / "theHarvester"
        executable_path = venv_path / "bin" / "theHarvester"

        super().__init__(
            name="theHarvester",
            display_name="theHarvester OSINT Suite",
            venv_path=venv_path,
            executable_path=executable_path,
            upstream_repo="laramies/theHarvester",
            upstream_branch="master",
            commit_sha="6790b147f52309e4eee22ed941db1d285ab2ec23",
            license_str="GPL-2.0-only",
            runtime_python="3.14.7",
            description="OSINT reconnaissance aggregator for domains, subdomains, emails, and IP ranges.",
            capabilities=[
                "passive_subdomain_enumeration",
                "email_discovery",
                "host_ip_mapping",
                "active_dns_bruteforce",
                "certificate_transparency_harvesting",
            ],
            external_services=["crtsh", "duckduckgo", "hackertarget", "otx", "threatcrowd"],
            safety_notes="Active DNS brute-force requires confirmed target registration in KRYPT scope.",
        )

    def extract_domain(self, target: str) -> str:
        """Extract root hostname/domain from URL or bare domain input."""
        target = target.strip()
        if "://" in target:
            parsed = urlparse(target)
            return parsed.hostname or target
        return target.split(":")[0].split("/")[0]

    async def run(
        self,
        target: str,
        sources: str = "crtsh,duckduckgo,hackertarget",
        limit: int = 100,
        active: bool = False,
        timeout: int = 90,
        **kwargs: Any,
    ) -> AdapterResult:
        """
        Execute theHarvester against the target domain.
        """
        domain = self.extract_domain(target)
        result = self.init_result(domain)

        # 1. Validation
        if not is_valid_domain(domain):
            result.fail(f"Invalid domain format: '{domain}'")
            result.completed_at = datetime.utcnow().isoformat() + "Z"
            return result

        # 2. Scope verification
        is_active_assessment = bool(active)
        is_valid, scope_err = self.validate_scope(
            domain,
            is_active=is_active_assessment,
            allow_passive=not is_active_assessment
        )
        if not is_valid:
            result.block(scope_err or f"Scope check failed for {domain}")
            result.completed_at = datetime.utcnow().isoformat() + "Z"
            return result

        if not self.is_installed():
            result.fail(f"theHarvester executable not found at {self.executable_path}")
            result.completed_at = datetime.utcnow().isoformat() + "Z"
            return result

        # 3. Execution setup
        out_prefix = f"harvest_{result.run_id}"
        cmd = [
            str(self.executable_path),
            "-d", domain,
            "-b", sources,
            "-l", str(limit),
            "-f", out_prefix,
        ]
        if active:
            cmd.append("-a")

        audit_log("THEHARVESTER_RUN", domain, "INVOKE", f"Sources={sources} Active={active} Limit={limit}")

        # 4. Spawning subprocess in isolated run directory
        exec_res = await self.execute_cmd(
            cmd=cmd,
            timeout=timeout,
            run_id=result.run_id,
        )

        result.completed_at = datetime.utcnow().isoformat() + "Z"
        result.scope = {
            "domain": domain,
            "active_mode": active,
            "sources": sources,
            "limit": limit,
        }

        # 5. Process execution status and outputs
        if exec_res.timed_out:
            result.fail(f"theHarvester execution timed out after {timeout} seconds.")
            return result

        # Collect raw evidence
        result.evidence.append({
            "evidence_id": f"ev_{result.run_id}_stdout",
            "tool": self.name,
            "evidence_type": "stdout",
            "content": exec_res.stdout[:50000],  # bounded size
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

        # 6. Parse structured results
        # Look for JSON output file generated by theHarvester: <out_prefix>.json
        json_file = exec_res.run_dir / f"{out_prefix}.json"
        xml_file = exec_res.run_dir / f"{out_prefix}.xml"

        parsed_data: Dict[str, Any] = {}
        if json_file.exists():
            result.output_files.append(str(json_file))
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    parsed_data = json.load(f)
                    result.raw_result = parsed_data
            except Exception as e:
                result.add_error(f"Failed to read JSON output file: {e}")

        if xml_file.exists():
            result.output_files.append(str(xml_file))

        # 7. Normalize findings from JSON or stdout
        hosts = parsed_data.get("hosts", [])
        ips = parsed_data.get("ips", [])
        emails = parsed_data.get("emails", [])
        urls = parsed_data.get("interesting_urls", [])

        # Parse from stdout if json was empty
        if not hosts and not emails and not ips and exec_res.stdout:
            in_hosts_section = False
            in_emails_section = False
            in_ips_section = False
            for line in exec_res.stdout.splitlines():
                sline = line.strip()
                if "[*] Hosts found:" in line:
                    in_hosts_section = True
                    in_emails_section = False
                    in_ips_section = False
                    continue
                elif "[*] Emails found:" in line:
                    in_emails_section = True
                    in_hosts_section = False
                    in_ips_section = False
                    continue
                elif "[*] IPs found:" in line:
                    in_ips_section = True
                    in_hosts_section = False
                    in_emails_section = False
                    continue
                elif line.startswith("[*]") or line.startswith("[-]"):
                    in_hosts_section = False
                    in_emails_section = False
                    in_ips_section = False
                    continue

                if sline and not sline.startswith("-") and not sline.startswith("Searching"):
                    if in_hosts_section and ":" in sline:
                        parts = sline.split(":")
                        hosts.append(parts[0].strip())
                        if len(parts) > 1 and parts[1].strip():
                            ips.append(parts[1].strip())
                    elif in_hosts_section:
                        hosts.append(sline)
                    elif in_emails_section and "@" in sline:
                        emails.append(sline)
                    elif in_ips_section:
                        ips.append(sline)

        # Build normalized findings
        seen = set()
        for host in set(hosts):
            if host and host not in seen:
                seen.add(host)
                result.findings.append({
                    "category": "subdomain",
                    "item": host,
                    "details": f"Subdomain discovered for {domain}",
                    "source_tool": self.name,
                    "severity": "info",
                    "extra": {"domain": domain},
                })

        for ip in set(ips):
            if ip and ip not in seen:
                seen.add(ip)
                result.findings.append({
                    "category": "ip_address",
                    "item": ip,
                    "details": f"Associated IP address for {domain}",
                    "source_tool": self.name,
                    "severity": "info",
                    "extra": {"domain": domain},
                })

        for email in set(emails):
            if email and email not in seen:
                seen.add(email)
                result.findings.append({
                    "category": "email",
                    "item": email,
                    "details": f"Public email address found for {domain}",
                    "source_tool": self.name,
                    "severity": "info",
                    "extra": {"domain": domain},
                })

        for url in set(urls):
            if url and url not in seen:
                seen.add(url)
                result.findings.append({
                    "category": "url",
                    "item": url,
                    "details": f"Discovered endpoint for {domain}",
                    "source_tool": self.name,
                    "severity": "info",
                    "extra": {"domain": domain},
                })

        if exec_res.exit_code != 0 and not result.findings:
            result.fail(f"theHarvester exited with code {exec_res.exit_code}: {exec_res.stderr or exec_res.stdout[:200]}")
        elif exec_res.exit_code != 0 and result.findings:
            result.status = "PARTIAL"

        return result
