"""
Photon Adapter for KRYPT CLI.
Provides deep crawler, endpoint discovery, parameter analysis, and secret-key extraction.
"""

from datetime import datetime
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from krypt.core.logger import logger, audit_log
from krypt.integrations.adapters.base import BaseAdapter
from krypt.integrations.models import AdapterResult
from krypt.safety.scope import ScopeEngine, ScopeViolationException


class PhotonAdapter(BaseAdapter):
    """
    Adapter for s0md3v/Photon crawling and OSINT exploration engine.
    Crawling constitutes active interaction with target services and strictly
    requires target registration and fail-closed scope enforcement.
    """

    def __init__(
        self,
        base_dir: Optional[Path] = None,
    ):
        root = base_dir or Path(__file__).resolve().parents[3]
        venv_path = root / "integrations" / "venvs" / "photon"
        python_bin = venv_path / "bin" / "python"
        self.script_path = root / "integrations" / "vendor" / "Photon" / "photon.py"

        super().__init__(
            name="Photon",
            display_name="Photon Web Crawler & Intelligence Suite",
            venv_path=venv_path,
            executable_path=python_bin,
            upstream_repo="s0md3v/Photon",
            upstream_branch="master",
            commit_sha="c8d2566841d69a268b244609921143d84b72b0c6",
            license_str="GPL-3.0",
            runtime_python="3.11.16",
            description="Fast, multi-threaded web crawler for URL, parameter, script, and secret extraction.",
            capabilities=[
                "recursive_web_crawling",
                "parameter_discovery",
                "script_discovery",
                "secret_key_regex_matching",
                "external_link_mapping",
                "robots_and_sitemap_extraction",
            ],
            external_services=[],
            safety_notes="Active crawling strictly restricted to registered targets. Rate-limited and depth-capped.",
        )

    def is_installed(self) -> bool:
        """Verify that both the python interpreter and the photon.py script exist."""
        return (
            self.executable_path.exists()
            and self.script_path.exists()
            and os.access(str(self.executable_path), os.X_OK)
        )

    def normalize_url(self, target: str) -> str:
        """Ensure clean URL format with scheme."""
        t = target.strip()
        if not t.startswith(("http://", "https://")):
            return f"http://{t}"
        return t

    async def run(
        self,
        target: str,
        level: int = 2,
        threads: int = 4,
        timeout: int = 60,
        keys: bool = True,
        export_format: str = "json",
        **kwargs: Any,
    ) -> AdapterResult:
        """
        Execute Photon crawling against the target URL.
        """
        target_url = self.normalize_url(target)
        result = self.init_result(target_url)

        # 1. Fail-closed scope verification
        is_valid, scope_err = self.validate_scope(
            target_url,
            is_active=True,
            allow_passive=False,
        )
        if not is_valid:
            result.block(scope_err or f"Target '{target_url}' not authorized in registered scope.")
            result.completed_at = datetime.utcnow().isoformat() + "Z"
            return result

        if not self.is_installed():
            result.fail(f"Photon script or python runtime missing at {self.script_path}")
            result.completed_at = datetime.utcnow().isoformat() + "Z"
            return result

        # 2. Command setup
        # Photon saves output in a directory named after domain or explicitly via -o
        out_dirname = f"photon_out_{result.run_id}"
        cmd = [
            str(self.executable_path),
            str(self.script_path),
            "-u", target_url,
            "-l", str(max(1, min(level, 5))),  # safe bounds [1, 5]
            "-t", str(max(1, min(threads, 10))),  # safe bounds [1, 10]
            "-o", out_dirname,
            "--timeout", str(timeout),
        ]
        if keys:
            cmd.append("--keys")
        if export_format in ("json", "csv"):
            cmd.extend(["-e", export_format])

        audit_log("PHOTON_RUN", target_url, "INVOKE", f"Level={level} Threads={threads} Keys={keys}")

        # 3. Execution
        exec_res = await self.execute_cmd(
            cmd=cmd,
            timeout=timeout + 30,
            run_id=result.run_id,
        )

        result.completed_at = datetime.utcnow().isoformat() + "Z"
        result.scope = {
            "target_url": target_url,
            "level": level,
            "threads": threads,
            "keys_enabled": keys,
        }

        if exec_res.timed_out:
            result.fail(f"Photon crawl timed out after {timeout} seconds.")
            return result

        # Collect raw evidence
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

        # 4. Parse extracted files
        # Check both relative to run_dir and current working directory
        out_dir = exec_res.run_dir / out_dirname
        if not out_dir.exists():
            # Photon might use domain name as fallback directory name
            parsed = urlparse(target_url)
            fallback_dir = exec_res.run_dir / (parsed.netloc or "target")
            if fallback_dir.exists():
                out_dir = fallback_dir

        if out_dir.exists():
            for root_dir, _, files in os.walk(out_dir):
                for f in files:
                    file_path = Path(root_dir) / f
                    result.output_files.append(str(file_path))

            # Read URLs
            urls_file = out_dir / "urls.txt"
            if urls_file.exists():
                try:
                    with open(urls_file, "r", encoding="utf-8") as uf:
                        for line in uf:
                            u = line.strip()
                            if u:
                                result.findings.append({
                                    "category": "endpoint",
                                    "item": u,
                                    "details": "Discovered target URL endpoint",
                                    "source_tool": self.name,
                                    "severity": "info",
                                    "extra": {"url": u},
                                })
                except Exception as e:
                    result.add_error(f"Error reading urls.txt: {e}")

            # Read Parameters / Fuzzable endpoints
            params_file = out_dir / "fuzzable.txt"
            if not params_file.exists():
                params_file = out_dir / "params.txt"
            if params_file.exists():
                try:
                    with open(params_file, "r", encoding="utf-8") as pf:
                        for line in pf:
                            p = line.strip()
                            if p:
                                result.findings.append({
                                    "category": "parameter",
                                    "item": p,
                                    "details": "Fuzzable URL parameter candidate",
                                    "source_tool": self.name,
                                    "severity": "info",
                                    "extra": {"parameter_url": p},
                                })
                except Exception as e:
                    result.add_error(f"Error reading params: {e}")

            # Read JavaScript scripts
            scripts_file = out_dir / "scripts.txt"
            if scripts_file.exists():
                try:
                    with open(scripts_file, "r", encoding="utf-8") as sf:
                        for line in sf:
                            s = line.strip()
                            if s:
                                result.findings.append({
                                    "category": "script",
                                    "item": s,
                                    "details": "Discovered client-side JavaScript asset",
                                    "source_tool": self.name,
                                    "severity": "info",
                                    "extra": {"script_url": s},
                                })
                except Exception as e:
                    result.add_error(f"Error reading scripts.txt: {e}")

            # Read secret keys / tokens if found
            keys_file = out_dir / "keys.json"
            if not keys_file.exists():
                keys_file = out_dir / "keys.txt"
            if keys_file.exists():
                try:
                    if keys_file.suffix == ".json":
                        with open(keys_file, "r", encoding="utf-8") as kf:
                            keys_data = json.load(kf)
                            for k, v in keys_data.items():
                                result.findings.append({
                                    "category": "secret_exposure",
                                    "item": str(k),
                                    "details": f"Potential credential or secret pattern matched: {str(v)[:40]}...",
                                    "source_tool": self.name,
                                    "severity": "medium",
                                    "extra": {"key_name": str(k)},
                                })
                    else:
                        with open(keys_file, "r", encoding="utf-8") as kf:
                            for line in kf:
                                if line.strip():
                                    result.findings.append({
                                        "category": "secret_exposure",
                                        "item": line.strip()[:60],
                                        "details": "Potential secret or sensitive credential pattern",
                                        "source_tool": self.name,
                                        "severity": "medium",
                                    })
                except Exception as e:
                    result.add_error(f"Error reading keys: {e}")

        # If photon produced findings in stdout
        if not result.findings and exec_res.stdout:
            for line in exec_res.stdout.splitlines():
                if "URL: " in line:
                    u = line.split("URL: ")[-1].strip()
                    result.findings.append({
                        "category": "endpoint",
                        "item": u,
                        "details": "Endpoint parsed from crawl stdout",
                        "source_tool": self.name,
                        "severity": "info",
                    })

        if exec_res.exit_code != 0 and not result.findings:
            result.fail(f"Photon exited with code {exec_res.exit_code}: {exec_res.stderr or exec_res.stdout[:200]}")
        elif exec_res.exit_code != 0 and result.findings:
            result.status = "PARTIAL"

        return result
