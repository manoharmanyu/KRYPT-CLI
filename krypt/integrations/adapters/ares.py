"""
ARES Adapter for KRYPT CLI.
Provides safe, controlled integration with the ARES Automated Red Team Engagement System.
Enforces read-only inspection, module cataloging, engagement doctor checks, and strict scope verification.
"""

from datetime import datetime
import json
import os
from pathlib import Path
from typing import Any, Dict, List, Optional

from krypt.core.logger import logger, audit_log
from krypt.integrations.adapters.base import BaseAdapter
from krypt.integrations.models import AdapterResult
from krypt.safety.scope import ScopeEngine


class ARESAdapter(BaseAdapter):
    """
    Adapter for Mafifrizi/ARES framework.
    Exposes safe prerequisite inspection, module capability auditing, engagement scope validation,
    and attack surface mapping without executing unconstrained destructive attacks.
    """

    def __init__(
        self,
        base_dir: Optional[Path] = None,
    ):
        root = base_dir or Path(__file__).resolve().parents[3]
        venv_path = root / "integrations" / "venvs" / "ares"
        executable_path = venv_path / "bin" / "ares"

        super().__init__(
            name="ARES",
            display_name="ARES Red Team Engagement System",
            venv_path=venv_path,
            executable_path=executable_path,
            upstream_repo="Mafifrizi/ARES",
            upstream_branch="main",
            commit_sha="3e1a9dd5137cc778b19a0aae6cd4218853f4f603",
            license_str="MIT",
            runtime_python="3.11.16",
            description="Autonomous red-team engagement platform for security posture and control auditing.",
            capabilities=[
                "engagement_scope_validation",
                "attack_module_catalog_inspection",
                "prerequisite_doctor_diagnostics",
                "campaign_configuration_auditing",
                "mitre_att&ck_matrix_mapping",
            ],
            external_services=[],
            safety_notes="Active exploit execution strictly gated; default mode restricted to audit and discovery.",
        )

    async def run(
        self,
        target: str = "local_audit",
        action: str = "doctor",
        module_name: Optional[str] = None,
        timeout: int = 60,
        **kwargs: Any,
    ) -> AdapterResult:
        """
        Execute safe ARES capability inspection.
        Supported actions: 'doctor', 'modules', 'info', 'targets', 'campaigns'.
        """
        target_str = target.strip()
        result = self.init_result(target_str)

        if not self.is_installed():
            result.fail(f"ARES executable not found at {self.executable_path}")
            result.completed_at = datetime.utcnow().isoformat() + "Z"
            return result

        # Scope verification: if action is target-specific, enforce scope
        if target_str not in ("local_audit", "system", "all"):
            is_valid, scope_err = self.validate_scope(
                target_str,
                is_active=True,
                allow_passive=False,
            )
            if not is_valid:
                result.block(scope_err or f"Scope check failed for {target_str}")
                result.completed_at = datetime.utcnow().isoformat() + "Z"
                return result

        # Command determination
        cmd = [str(self.executable_path)]
        action_clean = action.lower().strip()

        if action_clean == "doctor":
            cmd.append("doctor")
        elif action_clean in ("modules", "module_list", "list_modules"):
            cmd.extend(["module", "list"])
        elif action_clean in ("info", "module_info") and module_name:
            cmd.extend(["module", "info", module_name])
        elif action_clean in ("targets", "target_list"):
            cmd.extend(["target", "list"])
        elif action_clean in ("campaigns", "campaign_list"):
            cmd.extend(["campaign", "list"])
        else:
            # Fallback to general help or doctor
            cmd.append("doctor")

        audit_log("ARES_RUN", target_str, "INVOKE", f"Action={action_clean} Module={module_name}")

        exec_res = await self.execute_cmd(
            cmd=cmd,
            timeout=timeout,
            run_id=result.run_id,
        )

        result.completed_at = datetime.utcnow().isoformat() + "Z"
        result.scope = {
            "target": target_str,
            "action": action_clean,
            "module_name": module_name,
        }

        if exec_res.timed_out:
            result.fail(f"ARES execution timed out after {timeout} seconds.")
            return result

        # Capture evidence
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

        # Parse findings from output
        if action_clean == "doctor":
            # Extract checks passed / warnings
            for line in exec_res.stdout.splitlines():
                sline = line.strip()
                if "✓" in sline or "OK" in sline or "PASS" in sline:
                    result.findings.append({
                        "category": "environment_check",
                        "item": sline.replace("✓", "").strip()[:80],
                        "details": "ARES environmental prerequisite satisfied",
                        "source_tool": self.name,
                        "severity": "info",
                    })
                elif "✗" in sline or "WARN" in sline or "FAIL" in sline:
                    result.findings.append({
                        "category": "environment_warning",
                        "item": sline.replace("✗", "").strip()[:80],
                        "details": "ARES environmental prerequisite missing or warning",
                        "source_tool": self.name,
                        "severity": "low",
                    })
        elif action_clean in ("modules", "module_list", "list_modules"):
            # Extract listed modules
            for line in exec_res.stdout.splitlines():
                sline = line.strip()
                if "." in sline and not sline.startswith("http") and len(sline.split()) >= 1:
                    mod_id = sline.split()[0]
                    if any(prefix in mod_id for prefix in ("ad.", "recon.", "web.", "cloud.", "privesc.")):
                        result.findings.append({
                            "category": "available_module",
                            "item": mod_id,
                            "details": f"Registered attack/audit module in ARES catalog: {sline}",
                            "source_tool": self.name,
                            "severity": "info",
                        })

        # If no specific findings extracted, provide summary
        if not result.findings and exec_res.exit_code == 0:
            result.findings.append({
                "category": "operation_summary",
                "item": f"ARES {action_clean}",
                "details": f"Executed ARES {action_clean} successfully.",
                "source_tool": self.name,
                "severity": "info",
            })

        if exec_res.exit_code != 0 and not result.findings:
            result.fail(f"ARES command failed with exit code {exec_res.exit_code}: {exec_res.stderr or exec_res.stdout[:200]}")
        elif exec_res.exit_code != 0:
            result.status = "PARTIAL"

        return result
