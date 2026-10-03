"""
End-to-End CLI tests using Typer CliRunner.
"""

from typer.testing import CliRunner
from krypt.cli.main import app
from krypt.database.db import db

runner = CliRunner()


def test_cli_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "KRYPT CLI" in result.stdout
    assert "0.1.0" in result.stdout


def test_cli_doctor():
    result = runner.invoke(app, ["doctor"])
    assert result.exit_code == 0
    assert "KRYPT System Diagnostics" in result.stdout


def test_cli_target_lifecycle():
    # 1. Add target
    res_add = runner.invoke(app, ["target", "add", "http://127.0.0.1:8888", "--notes", "Test Lab"])
    assert res_add.exit_code == 0
    assert "Target Authorization Granted" in res_add.stdout

    # 2. List targets
    res_list = runner.invoke(app, ["target", "list"])
    assert res_list.exit_code == 0
    assert "127.0.0.1" in res_list.stdout

    # 3. Target info
    res_info = runner.invoke(app, ["target", "info", "http://127.0.0.1:8888"])
    assert res_info.exit_code == 0
    assert "Target Profile" in res_info.stdout


def test_cli_plugins_list():
    result = runner.invoke(app, ["plugins", "list"])
    assert result.exit_code == 0
    assert "OSINT Modules" in result.stdout
    assert "SECURITY Modules" in result.stdout


def test_cli_config_get_set():
    res_set = runner.invoke(app, ["config", "set", "socks5.enabled", "true"])
    assert res_set.exit_code == 0
    
    res_get = runner.invoke(app, ["config", "get", "socks5.enabled"])
    assert res_get.exit_code == 0
    assert "True" in res_get.stdout

    # Reset
    runner.invoke(app, ["config", "set", "socks5.enabled", "false"])


def test_cli_graph():
    result = runner.invoke(app, ["graph", "http://127.0.0.1:8888"])
    assert result.exit_code == 0
    assert "Target Architecture" in result.stdout
