"""
Integration tests for security assessment modules against the laboratory app.
"""

import pytest
from httpx import ASGITransport, AsyncClient
from lab.app import app
from krypt.database.db import db
from krypt.modules.auth import AuthModule
from krypt.modules.authz import AuthorizationModule
from krypt.modules.exposure import ExposureModule
from krypt.modules.headers import HeadersModule
from krypt.modules.idor import IDORModule
from krypt.modules.sqli import SQLInjectionModule
from krypt.modules.xss import XSSModule


@pytest.fixture(autouse=True)
def register_lab_target():
    db.add_target("http://127.0.0.1:8888", notes="Integration Lab")


@pytest.mark.asyncio
async def test_sqli_module_against_lab(monkeypatch):
    """Test SQL injection detection against the lab."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8888") as client:
        # Patch http_client to use ASGI test client
        from krypt.core import http
        monkeypatch.setattr(http.http_client, "_client", client)
        
        mod = SQLInjectionModule()
        findings = await mod.run("http://127.0.0.1:8888")
        
        assert len(findings) > 0
        vuln_names = [f.vulnerability for f in findings]
        assert any("SQL Injection" in name for name in vuln_names)


@pytest.mark.asyncio
async def test_xss_module_against_lab(monkeypatch):
    """Test XSS detection against the lab."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8888") as client:
        from krypt.core import http
        monkeypatch.setattr(http.http_client, "_client", client)
        
        mod = XSSModule()
        findings = await mod.run("http://127.0.0.1:8888")
        
        assert len(findings) > 0
        assert any("XSS" in f.vulnerability for f in findings)


@pytest.mark.asyncio
async def test_authz_module_against_lab(monkeypatch):
    """Test Broken Access Control detection on /admin."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8888") as client:
        from krypt.core import http
        monkeypatch.setattr(http.http_client, "_client", client)
        
        mod = AuthorizationModule()
        findings = await mod.run("http://127.0.0.1:8888")
        
        assert len(findings) > 0
        assert any("Broken Access Control" in f.vulnerability for f in findings)


@pytest.mark.asyncio
async def test_exposure_module_against_lab(monkeypatch):
    """Test Sensitive file exposure (.env, .git/HEAD)."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://127.0.0.1:8888") as client:
        from krypt.core import http
        monkeypatch.setattr(http.http_client, "_client", client)
        
        mod = ExposureModule()
        findings = await mod.run("http://127.0.0.1:8888")
        
        assert len(findings) >= 2
        endpoints = [f.endpoint for f in findings]
        assert "/.env" in endpoints
        assert "/.git/HEAD" in endpoints
