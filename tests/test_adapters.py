"""
Unit and Integration Tests for Upstream Multi-Tool Adapters (theHarvester, Photon, TorBot, ARES).
Verifies registry discovery, fail-closed scope enforcement, subprocess isolation, and result contracts.
"""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, patch
import pytest
from typer.testing import CliRunner

from krypt.cli.main import app
from krypt.database.db import db
from krypt.integrations.adapters.ares import ARESAdapter
from krypt.integrations.adapters.base import BaseAdapter
from krypt.integrations.adapters.harvester import HarvesterAdapter
from krypt.integrations.adapters.photon import PhotonAdapter
from krypt.integrations.adapters.torbot import TorBotAdapter
from krypt.integrations.executor import ExecutionResult
from krypt.integrations.models import AdapterResult
from krypt.integrations.registry import ToolRegistry, registry

runner = CliRunner()


def test_registry_catalogs_four_tools():
    """Verify tool registry enumerates all four integrated tools with correct metadata."""
    tools = registry.list_tools()
    assert len(tools) == 4
    tool_names = {t.name.lower() for t in tools}
    assert "theharvester" in tool_names
    assert "photon" in tool_names
    assert "torbot" in tool_names
    assert "ares" in tool_names

    # Check licenses and commit SHAs
    harvester_info = next(t for t in tools if t.name == "theHarvester")
    assert harvester_info.license == "GPL-2.0-only"
    assert harvester_info.commit_sha == "6790b147f52309e4eee22ed941db1d285ab2ec23"
    assert harvester_info.runtime_python == "3.14.7"

    photon_info = next(t for t in tools if t.name == "Photon")
    assert photon_info.license == "GPL-3.0"
    assert photon_info.commit_sha == "c8d2566841d69a268b244609921143d84b72b0c6"
    assert photon_info.runtime_python == "3.11.16"

    torbot_info = next(t for t in tools if t.name == "TorBot")
    assert torbot_info.license == "GPL-3.0"
    assert torbot_info.commit_sha == "1cc500ff2bae6c2cce3a3accd3e55a9c69f51034"
    assert torbot_info.runtime_python == "3.12.15"

    ares_info = next(t for t in tools if t.name == "ARES")
    assert ares_info.license == "MIT"
    assert ares_info.commit_sha == "3e1a9dd5137cc778b19a0aae6cd4218853f4f603"
    assert ares_info.runtime_python == "3.11.16"


def test_registry_adapter_lookups():
    """Verify alias and case-insensitive resolution of adapters."""
    assert registry.get_adapter("harvester") is not None
    assert registry.get_adapter("theHarvester") is not None
    assert registry.get_adapter("PHOTON") is not None
    assert registry.get_adapter("torbot") is not None
    assert registry.get_adapter("ares") is not None
    assert registry.get_adapter("nonexistent_tool") is None


def test_adapters_are_installed():
    """Verify that all four virtualenvs and executables are present and installed."""
    for adapter in registry.list_adapters():
        assert adapter.is_installed() is True, f"{adapter.name} executable not found at {adapter.executable_path}"


@pytest.mark.asyncio
async def test_harvester_scope_enforcement():
    """Active DNS brute force must fail closed on unregistered targets."""
    adapter = registry.get_adapter("theHarvester")
    assert isinstance(adapter, HarvesterAdapter)

    # Unregistered target with active=True
    res = await adapter.run("unregistered-target-scope.com", active=True)
    assert res.status == "BLOCKED"
    assert any("not registered in authorized scope" in err.lower() for err in res.errors)


@pytest.mark.asyncio
async def test_harvester_mocked_execution(tmp_path):
    """Verify theHarvester output parsing from execution result."""
    adapter = registry.get_adapter("theHarvester")
    fake_stdout = """
[*] Target: example.com
[*] Searching DuckDuckGo...
[*] Hosts found: 2
sub1.example.com:93.184.216.34
sub2.example.com:93.184.216.35
[*] Emails found: 1
admin@example.com
[*] IPs found: 1
93.184.216.34
"""
    mock_res = ExecutionResult(
        cmd=["theHarvester", "-d", "example.com"],
        exit_code=0,
        stdout=fake_stdout,
        stderr="",
        run_dir=tmp_path,
        duration_seconds=2.0,
    )

    with patch.object(adapter, "execute_cmd", new_callable=AsyncMock) as mock_exec:
        mock_exec.return_value = mock_res
        result = await adapter.run("example.com", sources="duckduckgo", active=False)
        assert result.status == "SUCCESS"
        assert len(result.findings) >= 3

        categories = {f["category"] for f in result.findings}
        assert "subdomain" in categories
        assert "email" in categories
        assert "ip_address" in categories


@pytest.mark.asyncio
async def test_photon_scope_enforcement():
    """Active crawling must fail closed on unregistered target."""
    adapter = registry.get_adapter("Photon")
    assert isinstance(adapter, PhotonAdapter)

    res = await adapter.run("http://unregistered-crawling-site.com")
    assert res.status == "BLOCKED"
    assert any("registered in authorized scope" in err.lower() for err in res.errors)


@pytest.mark.asyncio
async def test_photon_mocked_file_parsing(tmp_path):
    """Verify Photon output file discovery and finding normalization."""
    adapter = registry.get_adapter("Photon")
    
    # Register target to satisfy scope
    target_url = "http://127.0.0.1:9999"
    db.add_target(target_url, notes="test target")

    # Simulate photon run output directory
    run_dir = tmp_path / "runs"
    run_dir.mkdir(parents=True)
    out_dir = run_dir / "127.0.0.1:9999"
    out_dir.mkdir(parents=True)

    (out_dir / "urls.txt").write_text("http://127.0.0.1:9999/admin\nhttp://127.0.0.1:9999/login\n", encoding="utf-8")
    (out_dir / "params.txt").write_text("http://127.0.0.1:9999/search?q=test\n", encoding="utf-8")
    (out_dir / "scripts.txt").write_text("http://127.0.0.1:9999/static/main.js\n", encoding="utf-8")
    (out_dir / "keys.json").write_text('{"aws_secret": "AKIAIOSFODNN7EXAMPLE"}', encoding="utf-8")

    mock_res = ExecutionResult(
        cmd=["python", "photon.py", "-u", target_url],
        exit_code=0,
        stdout="Photon crawling finished.",
        stderr="",
        run_dir=run_dir,
        duration_seconds=3.0,
    )

    with patch.object(adapter, "execute_cmd", new_callable=AsyncMock) as mock_exec:
        mock_exec.return_value = mock_res
        result = await adapter.run(target_url)
        assert result.status == "SUCCESS"
        assert len(result.findings) >= 4

        categories = {f["category"] for f in result.findings}
        assert "endpoint" in categories
        assert "parameter" in categories
        assert "script" in categories
        assert "secret_exposure" in categories

    db.remove_target(target_url)


@pytest.mark.asyncio
async def test_torbot_scope_and_proxy_fail():
    """TorBot rejects unregistered onion address and handles unreachable proxy."""
    adapter = registry.get_adapter("TorBot")
    assert isinstance(adapter, TorBotAdapter)

    # 1. Scope fail
    res = await adapter.run("http://unregistered-hidden.onion")
    assert res.status == "BLOCKED"

    # 2. Register target
    onion_target = "http://authorized-test.onion"
    db.add_target(onion_target, notes="onion test")

    # Test unreachable Tor proxy
    with patch.object(adapter, "is_tor_proxy_alive", return_value=False):
        with patch.object(adapter, "detect_tor_proxy", return_value=(None, None)):
            res2 = await adapter.run(onion_target, dry_run=False)
            assert res2.status == "FAILED"
            assert any("tor socks5 proxy unreachable" in err.lower() for err in res2.errors)

    # Test dry run
    res3 = await adapter.run(onion_target, dry_run=True)
    assert res3.status == "SUCCESS"
    assert res3.findings[0]["category"] == "dry_run_plan"

    db.remove_target(onion_target)


@pytest.mark.asyncio
async def test_ares_safe_modes(tmp_path):
    """Verify ARES runs safe doctor checks and module listings."""
    adapter = registry.get_adapter("ARES")
    assert isinstance(adapter, ARESAdapter)

    mock_res = ExecutionResult(
        cmd=["ares", "doctor"],
        exit_code=0,
        stdout="✓ [OK] cryptography 50.0.2\n✗ [WARN] impacket missing\n",
        stderr="",
        run_dir=tmp_path,
        duration_seconds=1.0,
    )

    with patch.object(adapter, "execute_cmd", new_callable=AsyncMock) as mock_exec:
        mock_exec.return_value = mock_res
        result = await adapter.run(action="doctor")
        assert result.status == "SUCCESS"
        assert len(result.findings) == 2
        categories = {f["category"] for f in result.findings}
        assert "environment_check" in categories
        assert "environment_warning" in categories


def test_cli_tools_list():
    """Verify krypt tools list command execution."""
    result = runner.invoke(app, ["--no-banner", "tools", "list"])
    assert result.exit_code == 0
    assert "Photon" in result.stdout
    assert "TorBot" in result.stdout
    assert "ARES" in result.stdout
    assert "theHarvest" in result.stdout

    # Test JSON mode
    json_result = runner.invoke(app, ["--no-banner", "tools", "list", "--json"])
    assert json_result.exit_code == 0
    assert "theHarvester" in json_result.stdout


def test_cli_tools_doctor():
    """Verify krypt tools doctor command execution."""
    result = runner.invoke(app, ["--no-banner", "tools", "doctor"])
    assert result.exit_code == 0
    assert "HEALTHY" in result.stdout
    assert "PASSED" in result.stdout
