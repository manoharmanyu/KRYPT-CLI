"""
Base Adapter Specification for Upstream Tool Integrations.
Provides common contract, scope checks, execution isolation, and result normalization.
"""

from abc import ABC, abstractmethod
from datetime import datetime
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from krypt.core.logger import logger, audit_log
from krypt.evidence.redactor import redact_text
from krypt.integrations.executor import SubprocessExecutor, ExecutionResult
from krypt.integrations.models import AdapterResult, ToolFinding, ToolInfo
from krypt.safety.scope import ScopeEngine, ScopeViolationException


class BaseAdapter(ABC):
    """
    Abstract base class for all third-party tool adapters.
    Guarantees consistent scope enforcement, subprocess isolation, and result formatting.
    """

    def __init__(
        self,
        name: str,
        display_name: str,
        venv_path: Path,
        executable_path: Path,
        upstream_repo: str,
        upstream_branch: str,
        commit_sha: str,
        license_str: str,
        runtime_python: str,
        description: str,
        capabilities: List[str],
        external_services: Optional[List[str]] = None,
        safety_notes: str = "",
    ):
        self.name = name
        self.display_name = display_name
        self.venv_path = Path(venv_path)
        self.executable_path = Path(executable_path)
        self.upstream_repo = upstream_repo
        self.upstream_branch = upstream_branch
        self.commit_sha = commit_sha
        self.license_str = license_str
        self.runtime_python = runtime_python
        self.description = description
        self.capabilities = capabilities
        self.external_services = external_services or []
        self.safety_notes = safety_notes

    def is_installed(self) -> bool:
        """Check whether the tool executable and virtual environment exist."""
        return self.executable_path.exists() and os.access(str(self.executable_path), os.X_OK)

    def get_info(self) -> ToolInfo:
        """Return standardized tool metadata and runtime readiness."""
        installed = self.is_installed()
        return ToolInfo(
            name=self.name,
            display_name=self.display_name,
            upstream_repo=self.upstream_repo,
            upstream_branch=self.upstream_branch,
            commit_sha=self.commit_sha,
            license=self.license_str,
            runtime_python=self.runtime_python,
            venv_path=str(self.venv_path),
            executable=str(self.executable_path),
            installed=installed,
            description=self.description,
            capabilities=self.capabilities,
            external_services=self.external_services,
            safety_notes=self.safety_notes,
            version=self.get_version() if installed else "Not installed",
        )

    def get_version(self) -> str:
        """Return tool version string, fallback to commit SHA."""
        return self.commit_sha[:8]

    def validate_scope(
        self,
        target: str,
        is_active: bool = True,
        allow_passive: bool = False
    ) -> Tuple[bool, Optional[str]]:
        """
        Validate target against KRYPT's fail-closed scope engine.
        Returns (is_valid, error_message).
        """
        try:
            ScopeEngine.check_scope(
                target_input=target,
                is_active_assessment=is_active,
                allow_passive=allow_passive
            )
            return True, None
        except ScopeViolationException as sve:
            err = str(sve)
            logger.warning(f"Scope violation in {self.name} adapter: {err}")
            return False, err
        except Exception as e:
            err = f"Scope evaluation error: {str(e)}"
            logger.error(err)
            return False, err

    def init_result(self, target: str, run_id: Optional[str] = None) -> AdapterResult:
        """Initialize a new standardized AdapterResult container."""
        started_at = datetime.utcnow().isoformat() + "Z"
        rid = run_id or f"{self.name}_{int(datetime.utcnow().timestamp())}"
        return AdapterResult(
            tool=self.name,
            run_id=rid,
            started_at=started_at,
            completed_at="",
            target=target,
            status="SUCCESS",
            findings=[],
            evidence=[],
            errors=[],
            output_files=[],
            raw_result=None,
        )

    async def execute_cmd(
        self,
        cmd: List[str],
        cwd: Optional[Path] = None,
        env: Optional[Dict[str, str]] = None,
        timeout: int = 120,
        run_id: Optional[str] = None,
    ) -> ExecutionResult:
        """Execute a subprocess command through SubprocessExecutor."""
        return await SubprocessExecutor.run(
            cmd=cmd,
            cwd=cwd,
            env=env,
            timeout=timeout,
            tool_name=self.name,
            run_id=run_id,
        )

    @abstractmethod
    async def run(self, target: str, **kwargs: Any) -> AdapterResult:
        """Execute the adapter against a target with options."""
        pass

    async def doctor(self) -> Dict[str, Any]:
        """Perform diagnostic health check for this adapter."""
        installed = self.is_installed()
        health: Dict[str, Any] = {
            "name": self.name,
            "display_name": self.display_name,
            "installed": installed,
            "executable": str(self.executable_path),
            "venv_path": str(self.venv_path),
            "commit_sha": self.commit_sha,
            "status": "HEALTHY" if installed else "MISSING",
            "message": "Executable ready" if installed else f"Executable not found at {self.executable_path}",
        }

        if installed:
            # Test executing --help or version
            try:
                res = await self.execute_cmd(
                    [str(self.executable_path), "--help"],
                    timeout=10,
                )
                if res.exit_code == 0 or "help" in res.stdout.lower() or "help" in res.stderr.lower():
                    health["smoke_test"] = "PASSED"
                else:
                    health["smoke_test"] = f"EXIT_{res.exit_code}"
                    health["status"] = "WARNING"
            except Exception as e:
                health["smoke_test"] = f"ERROR: {str(e)}"
                health["status"] = "UNHEALTHY"

        return health
