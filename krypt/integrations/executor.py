"""
Secure Subprocess Execution Engine for Upstream Integrations.
Handles process spawning, timeouts, argument sanitization, output directory isolation,
environment control, and automatic secret redaction.
"""

import asyncio
from datetime import datetime
import os
from pathlib import Path
import shutil
import uuid
from typing import Any, Dict, List, Optional, Tuple

from krypt.core.logger import logger, audit_log
from krypt.evidence.redactor import redact_text
from krypt.utils.filesystem import KRYPT_HOME, ensure_krypt_dirs


class ExecutionResult:
    """Detailed outcome of an isolated subprocess run."""
    def __init__(
        self,
        cmd: List[str],
        exit_code: int,
        stdout: str,
        stderr: str,
        run_dir: Path,
        duration_seconds: float,
        timed_out: bool = False,
    ):
        self.cmd = cmd
        self.exit_code = exit_code
        self.stdout = stdout
        self.stderr = stderr
        self.run_dir = run_dir
        self.duration_seconds = duration_seconds
        self.timed_out = timed_out

    @property
    def is_success(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


class SubprocessExecutor:
    """Manages secure execution of third-party tool binaries."""

    @classmethod
    def create_run_directory(cls, tool_name: str, run_id: Optional[str] = None) -> Tuple[str, Path]:
        """
        Create a dedicated, isolated execution directory inside ~/.krypt/runs/<tool_name>_<run_id>.
        Guarantees path containment to prevent path traversal.
        """
        ensure_krypt_dirs()
        rid = run_id or uuid.uuid4().hex[:12]
        safe_tool = "".join(c for c in tool_name if c.isalnum() or c in ("-", "_")).lower()
        base_runs_dir = KRYPT_HOME / "runs"
        base_runs_dir.mkdir(parents=True, exist_ok=True)
        
        run_dir = base_runs_dir / f"{safe_tool}_{rid}"
        run_dir.mkdir(parents=True, exist_ok=True)

        # Enforce canonical path containment
        resolved_run_dir = run_dir.resolve()
        resolved_base = base_runs_dir.resolve()
        if not str(resolved_run_dir).startswith(str(resolved_base)):
            raise ValueError(f"Path traversal detected in run directory creation: {run_dir}")

        return rid, resolved_run_dir

    @classmethod
    async def run(
        cls,
        cmd: List[str],
        cwd: Optional[Path] = None,
        env: Optional[Dict[str, str]] = None,
        timeout: int = 120,
        tool_name: str = "generic",
        run_id: Optional[str] = None,
    ) -> ExecutionResult:
        """
        Execute an isolated subprocess with argument arrays, timeouts, and safe capture.
        Never concatenates shell strings.
        """
        rid, run_dir = cls.create_run_directory(tool_name, run_id)
        working_dir = cwd or run_dir

        # Base environment: inherit standard PATH and minimal variables
        exec_env = os.environ.copy()
        if env:
            exec_env.update(env)

        # Ensure executable exists
        executable = cmd[0]
        if not os.path.isabs(executable):
            resolved_exec = shutil.which(executable)
            if not resolved_exec:
                return ExecutionResult(
                    cmd=cmd,
                    exit_code=127,
                    stdout="",
                    stderr=f"Executable '{executable}' not found on system PATH.",
                    run_dir=run_dir,
                    duration_seconds=0.0
                )
            cmd[0] = resolved_exec

        audit_log("SUBPROCESS_EXEC", cmd[0], "START", f"Tool={tool_name} RunID={rid} ArgsCount={len(cmd)-1}")
        start_time = datetime.utcnow()

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=str(working_dir),
                env=exec_env,
            )

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    process.communicate(),
                    timeout=float(timeout)
                )
                timed_out = False
            except asyncio.TimeoutError:
                timed_out = True
                try:
                    process.terminate()
                    await asyncio.sleep(0.5)
                    if process.returncode is None:
                        process.kill()
                    stdout_bytes, stderr_bytes = await process.communicate()
                except Exception as term_err:
                    logger.warning(f"Error terminating timed out process: {term_err}")
                    stdout_bytes, stderr_bytes = b"", b"Process timed out and termination failed."

            duration = (datetime.utcnow() - start_time).total_seconds()
            stdout_text = redact_text(stdout_bytes.decode("utf-8", errors="replace"))
            stderr_text = redact_text(stderr_bytes.decode("utf-8", errors="replace"))
            exit_code = process.returncode if process.returncode is not None else (124 if timed_out else 1)

            # Persist execution log in run directory
            log_file = run_dir / "execution.log"
            try:
                with open(log_file, "w", encoding="utf-8") as f:
                    f.write(f"Command: {' '.join(cmd)}\n")
                    f.write(f"Exit Code: {exit_code}\n")
                    f.write(f"Duration: {duration:.2f}s\n")
                    f.write(f"Timed Out: {timed_out}\n\n")
                    f.write("=== STDOUT ===\n")
                    f.write(stdout_text)
                    f.write("\n\n=== STDERR ===\n")
                    f.write(stderr_text)
            except Exception as write_err:
                logger.warning(f"Failed to write execution log: {write_err}")

            status_str = "TIMEOUT" if timed_out else ("SUCCESS" if exit_code == 0 else f"FAILED_{exit_code}")
            audit_log("SUBPROCESS_EXEC", cmd[0], status_str, f"Duration={duration:.2f}s RunDir={run_dir}")

            return ExecutionResult(
                cmd=cmd,
                exit_code=exit_code,
                stdout=stdout_text,
                stderr=stderr_text,
                run_dir=run_dir,
                duration_seconds=duration,
                timed_out=timed_out
            )

        except Exception as e:
            duration = (datetime.utcnow() - start_time).total_seconds()
            err_msg = f"Subprocess spawning error: {str(e)}"
            logger.error(err_msg)
            audit_log("SUBPROCESS_EXEC", cmd[0], "ERROR", err_msg)
            return ExecutionResult(
                cmd=cmd,
                exit_code=1,
                stdout="",
                stderr=err_msg,
                run_dir=run_dir,
                duration_seconds=duration,
                timed_out=False
            )
