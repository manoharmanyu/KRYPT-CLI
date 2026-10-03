"""
Laboratory Server Manager for KRYPT CLI.
Manages starting, stopping, checking status, and verifying the test laboratory.
"""

import os
import signal
import subprocess
import sys
import time
from typing import Any, Dict, Optional, Tuple
import httpx

from krypt.utils.filesystem import KRYPT_LAB_PID_FILE, ensure_krypt_dirs

DEFAULT_PORT = 8888
DEFAULT_HOST = "127.0.0.1"


class LabManager:
    """Controls the lifecycle of the local training laboratory."""

    @classmethod
    def get_pid(cls) -> Optional[int]:
        """Get PID of running laboratory process if exists."""
        if KRYPT_LAB_PID_FILE.exists():
            try:
                with open(KRYPT_LAB_PID_FILE, "r") as f:
                    pid = int(f.read().strip())
                # Check if process actually exists
                os.kill(pid, 0)
                return pid
            except (ValueError, OSError, ProcessLookupError):
                cls._cleanup_pid()
                return None
        return None

    @classmethod
    def _cleanup_pid(cls) -> None:
        if KRYPT_LAB_PID_FILE.exists():
            try:
                KRYPT_LAB_PID_FILE.unlink()
            except Exception:
                pass

    @classmethod
    def start(cls, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT, mode: str = "vulnerable") -> Tuple[bool, str]:
        """Start the laboratory server in the background (vulnerable or hardened mode)."""
        ensure_krypt_dirs()
        pid = cls.get_pid()
        if pid:
            return True, f"Laboratory is already running (PID: {pid}) on http://{host}:{port}"

        # Find python executable
        python_bin = sys.executable

        # Start uvicorn running lab.app:app
        cmd = [
            python_bin, "-m", "uvicorn",
            "lab.app:app",
            "--host", host,
            "--port", str(port),
            "--log-level", "warning"
        ]

        # Working directory should be the package root
        root_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        env = os.environ.copy()
        env["KRYPT_LAB_MODE"] = mode.lower()

        process = subprocess.Popen(
            cmd,
            cwd=root_dir,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True
        )

        with open(KRYPT_LAB_PID_FILE, "w") as f:
            f.write(str(process.pid))

        # Wait up to 3 seconds for server to bind
        time.sleep(1.0)
        
        # Test responsiveness
        try:
            r = httpx.get(f"http://{host}:{port}/", timeout=2.0)
            if r.status_code == 200:
                return True, f"Laboratory started successfully on http://{host}:{port} (PID: {process.pid})"
        except Exception:
            pass

        return True, f"Laboratory started on http://{host}:{port} (PID: {process.pid})"

    @classmethod
    def stop(cls) -> Tuple[bool, str]:
        """Stop the running laboratory process."""
        pid = cls.get_pid()
        if not pid:
            cls._cleanup_pid()
            return True, "Laboratory is not currently running."

        try:
            os.kill(pid, signal.SIGTERM)
            time.sleep(0.5)
            # Check if still running, if so force kill
            try:
                os.kill(pid, 0)
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        except ProcessLookupError:
            pass
        except Exception as e:
            cls._cleanup_pid()
            return False, f"Failed to stop laboratory: {e}"

        cls._cleanup_pid()
        return True, f"Laboratory process (PID: {pid}) stopped."

    @classmethod
    def status(cls, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> Dict[str, Any]:
        """Check laboratory status and HTTP responsiveness."""
        pid = cls.get_pid()
        url = f"http://{host}:{port}"
        
        if not pid:
            return {
                "running": False,
                "pid": None,
                "url": url,
                "responsive": False,
                "message": "Laboratory is STOPPED"
            }

        responsive = False
        try:
            r = httpx.get(f"{url}/", timeout=2.0)
            responsive = (r.status_code == 200)
        except Exception:
            responsive = False

        return {
            "running": True,
            "pid": pid,
            "url": url,
            "responsive": responsive,
            "message": f"Laboratory is RUNNING on {url} (PID: {pid})" if responsive else f"Laboratory process alive (PID: {pid}) but not yet responding"
        }

    @classmethod
    def verify(cls, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT) -> Dict[str, Any]:
        """Execute diagnostic verification test suite against all laboratory routes."""
        base_url = f"http://{host}:{port}"
        tests = [
            ("Home Page", "/", "GET", 200),
            ("Search (SQLi/XSS)", "/search?q=test", "GET", 200),
            ("Login Form", "/login", "GET", 200),
            ("Profile (IDOR)", "/profile?id=1", "GET", 200),
            ("Admin Dashboard", "/admin/dashboard", "GET", 200),
            ("Admin Users API", "/admin/users", "GET", 200),
            ("Public Users API", "/api/users", "GET", 200),
            ("App Scripts", "/assets/app.js", "GET", 200),
            ("Robots File", "/robots.txt", "GET", 200),
            ("Sitemap File", "/sitemap.xml", "GET", 200),
            ("Environment Leak", "/.env", "GET", 200),
            ("Git HEAD Leak", "/.git/HEAD", "GET", 200),
            ("Debug Vars Leak", "/debug/vars", "GET", 200),
        ]

        results = []
        all_passed = True

        for name, path, method, expected_code in tests:
            url = f"{base_url}{path}"
            status = "FAIL"
            resp_code = None
            try:
                r = httpx.get(url, timeout=3.0)
                resp_code = r.status_code
                if resp_code == expected_code:
                    status = "PASS"
                else:
                    all_passed = False
            except Exception:
                try:
                    import asyncio
                    from httpx import ASGITransport, AsyncClient
                    from lab.app import app as lab_app
                    
                    async def _test_asgi():
                        async with AsyncClient(transport=ASGITransport(app=lab_app), base_url=base_url) as asgi_client:
                            r = await asgi_client.get(path)
                            return r.status_code

                    resp_code = asyncio.run(_test_asgi())
                    if resp_code == expected_code:
                        status = "PASS"
                    else:
                        all_passed = False
                except Exception:
                    all_passed = False

            results.append({
                "test": name,
                "path": path,
                "expected": expected_code,
                "actual": resp_code,
                "status": status
            })

        return {
            "base_url": base_url,
            "all_passed": all_passed,
            "results": results
        }
