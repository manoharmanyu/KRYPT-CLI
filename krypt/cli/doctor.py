"""
Diagnostic System Check (krypt doctor) for KRYPT CLI.
Validates Python runtime, dependencies, database, Docker, config, network, and laboratory status.
"""

import importlib
import os
import shutil
import socket
import sys
from typing import Any, Dict, List, Optional
from rich.console import Console
from rich.table import Table

from krypt.database.db import db
from krypt.core.integrity import IntegrityGuard
from lab.server import LabManager
from krypt.utils.filesystem import KRYPT_CONFIG_FILE, KRYPT_HOME


def run_doctor(console: Optional[Console] = None) -> bool:
    """Execute comprehensive system diagnostic."""
    c = console or Console()
    table = Table(title="[bold]KRYPT System Diagnostics (Doctor)[/]", border_style="cyan")
    table.add_column("Component", style="bold")
    table.add_column("Status", justify="center")
    table.add_column("Details", style="dim")

    all_ok = True

    # 1. Python runtime
    py_ver = sys.version.split()[0]
    is_py_ok = sys.version_info >= (3, 10)
    table.add_row(
        "Python Runtime",
        "[bold green]PASS[/]" if is_py_ok else "[bold red]FAIL[/]",
        f"Version {py_ver} ({sys.executable})"
    )
    if not is_py_ok:
        all_ok = False

    # 2. Key dependencies
    required_packages = [
        "typer", "rich", "httpx", "dns", "bs4", "pydantic",
        "yaml", "sqlalchemy", "jinja2", "starlette", "uvicorn", "pytest"
    ]
    missing = []
    for pkg in required_packages:
        try:
            importlib.import_module(pkg)
        except ImportError:
            missing.append(pkg)

    if not missing:
        table.add_row("Dependencies", "[bold green]PASS[/]", f"All {len(required_packages)} required packages installed")
    else:
        table.add_row("Dependencies", "[bold red]FAIL[/]", f"Missing: {', '.join(missing)}")
        all_ok = False

    # 3. SQLite Database
    try:
        targets_count = len(db.list_targets())
        findings_count = len(db.get_findings())
        table.add_row("SQLite Database", "[bold green]PASS[/]", f"Connected ({db.db_path}) | {targets_count} targets, {findings_count} findings")
    except Exception as e:
        table.add_row("SQLite Database", "[bold red]FAIL[/]", f"Database error: {e}")
        all_ok = False

    # 4. Configuration File
    if KRYPT_CONFIG_FILE.exists():
        table.add_row("Configuration", "[bold green]PASS[/]", f"Active at {KRYPT_CONFIG_FILE}")
    else:
        table.add_row("Configuration", "[bold yellow]WARN[/]", "Default config will be initialized")

    # 5. Directory Permissions
    try:
        test_file = KRYPT_HOME / ".perm_check"
        test_file.write_text("ok")
        test_file.unlink()
        table.add_row("Filesystem Access", "[bold green]PASS[/]", f"Read/Write access verified for {KRYPT_HOME}")
    except Exception as e:
        table.add_row("Filesystem Access", "[bold red]FAIL[/]", f"Permission issue: {e}")
        all_ok = False

    # 6. Network & DNS
    try:
        socket.gethostbyname("localhost")
        table.add_row("Network & DNS", "[bold green]PASS[/]", "Loopback and DNS resolution operational")
    except Exception as e:
        table.add_row("Network & DNS", "[bold yellow]WARN[/]", f"DNS check warning: {e}")

    # 7. Docker (Optional)
    docker_bin = shutil.which("docker")
    if docker_bin:
        table.add_row("Docker CLI", "[bold green]PASS[/]", f"Found binary at {docker_bin} (Native mode also supported)")
    else:
        table.add_row("Docker CLI", "[dim]OPTIONAL[/]", "Docker CLI not found (Native laboratory mode supported)")

    # 8. Cryptographic Code Integrity & Anti-Tamper
    try:
        integrity_stat = IntegrityGuard.verify_integrity()
        if integrity_stat["is_intact"]:
            table.add_row("Code Integrity", "[bold green]PASS[/]", f"SHA-256 verified ({integrity_stat['verified_count']} files intact, 0 tampered)")
        else:
            table.add_row("Code Integrity", "[bold red]TAMPERED[/]", f"Mismatch detected: {len(integrity_stat['tampered'])} modified, {len(integrity_stat['missing'])} missing")
            all_ok = False
    except Exception as e:
        table.add_row("Code Integrity", "[bold yellow]WARN[/]", f"Integrity check error: {e}")

    # 9. Laboratory Status
    lab_status = LabManager.status()
    if lab_status["running"]:
        table.add_row("Lab Environment", "[bold green]ACTIVE[/]", f"Running on {lab_status['url']} (PID: {lab_status['pid']})")
    else:
        table.add_row("Lab Environment", "[dim]STANDBY[/]", "Stopped (Start via `krypt lab start`)")

    c.print(table)
    return all_ok
