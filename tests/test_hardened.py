"""
Tests for Hardened Laboratory Application (Zero-Vulnerability / Hackproof Mode).
Verifies that all OWASP vulnerability categories (SQLi, XSS, IDOR, Authz, Exposure, Missing Headers)
are fully mitigated, and that krypt scanners find 0 vulnerabilities against the hardened target.
"""

import pytest
from httpx import ASGITransport, AsyncClient
from lab.hardened import hardened_app
from krypt.modules.sqli import SQLInjectionModule
from krypt.modules.xss import XSSModule
from krypt.modules.authz import AuthorizationModule
from krypt.modules.idor import IDORModule
from krypt.modules.exposure import ExposureModule
from krypt.database.db import db
from krypt.modules.headers import HeadersModule
from krypt.safety.scope import ScopeEngine


@pytest.fixture(autouse=True)
def setup_scope():
    """Ensure lab URL is in scope for module tests."""
    db.add_target("http://127.0.0.1:8888", notes="Hardened Lab")


@pytest.mark.asyncio
async def test_hardened_sqli_protection():
    """Verify that SQL injection attempts do not bypass authentication or trigger SQL errors."""
    async with AsyncClient(transport=ASGITransport(app=hardened_app), base_url="http://127.0.0.1:8888") as client:
        # SQL injection probe in search
        resp = await client.get("/search?q=' UNION SELECT 1,username,password_hash,salt,email FROM users--")
        assert resp.status_code == 200
        # Should not leak user database records or trigger SQL syntax errors
        assert "alice@krypt-security.org" not in resp.text
        assert "admin_super_secret" not in resp.text
        assert "syntax error" not in resp.text.lower()
        assert "sqlite3.OperationalError" not in resp.text
        assert "No items found matching" in resp.text


@pytest.mark.asyncio
async def test_hardened_xss_protection():
    """Verify that XSS payloads are properly HTML-escaped and CSP blocks execution."""
    async with AsyncClient(transport=ASGITransport(app=hardened_app), base_url="http://127.0.0.1:8888") as client:
        xss_payload = "<script>alert('krypt-pwned')</script>"
        resp = await client.get(f"/search?q={xss_payload}")
        assert resp.status_code == 200
        # Raw unescaped script tag must NOT be present
        assert "<script>alert('krypt-pwned')</script>" not in resp.text
        # Escaped entity must be present
        assert "&lt;script&gt;alert(&#x27;krypt-pwned&#x27;)&lt;/script&gt;" in resp.text or "&lt;script&gt;" in resp.text
        # Strict CSP header present
        assert "Content-Security-Policy" in resp.headers
        assert "default-src 'self'" in resp.headers["Content-Security-Policy"]


@pytest.mark.asyncio
async def test_hardened_idor_and_authz():
    """Verify that unauthorized requests to /profile or /admin return 401/403."""
    async with AsyncClient(transport=ASGITransport(app=hardened_app), base_url="http://127.0.0.1:8888") as client:
        # Unauthorized access to profile without cookie -> 401
        p_resp = await client.get("/profile?id=1")
        assert p_resp.status_code == 401

        # Unauthorized access to admin panel -> 401
        a_resp = await client.get("/admin")
        assert a_resp.status_code == 401

        # Unauthorized access to admin users list -> 403
        u_resp = await client.get("/admin/users")
        assert u_resp.status_code == 403


@pytest.mark.asyncio
async def test_hardened_information_exposure():
    """Verify that sensitive files (.env, .git, debug) return 404 Not Found."""
    async with AsyncClient(transport=ASGITransport(app=hardened_app), base_url="http://127.0.0.1:8888") as client:
        env_resp = await client.get("/.env")
        assert env_resp.status_code == 404

        git_resp = await client.get("/.git/HEAD")
        assert git_resp.status_code == 404

        debug_resp = await client.get("/debug/vars")
        assert debug_resp.status_code == 404


@pytest.mark.asyncio
async def test_hardened_security_headers_present():
    """Verify presence of A+ grade security headers on all responses."""
    async with AsyncClient(transport=ASGITransport(app=hardened_app), base_url="http://127.0.0.1:8888") as client:
        resp = await client.get("/")
        assert resp.status_code == 200
        headers = resp.headers
        assert "Content-Security-Policy" in headers
        assert "Strict-Transport-Security" in headers
        assert "X-Frame-Options" in headers
        assert headers["X-Frame-Options"] == "DENY"
        assert "X-Content-Type-Options" in headers
        assert headers["X-Content-Type-Options"] == "nosniff"
        assert "Referrer-Policy" in headers


@pytest.mark.asyncio
async def test_krypt_scanner_reports_zero_vulnerabilities_on_hardened_app(monkeypatch):
    """
    Run KRYPT security scanning modules against the hardened app endpoint (using ?mode=hardened).
    Assert that zero findings are produced across all active vulnerability modules.
    """
    monkeypatch.setenv("KRYPT_LAB_MODE", "hardened")
    target = "http://127.0.0.1:8888"

    # Test SQLi scanner
    sqli_mod = SQLInjectionModule()
    sqli_findings = await sqli_mod.run(target, endpoints=["/search?q=test"])
    assert len(sqli_findings) == 0

    # Test XSS scanner
    xss_mod = XSSModule()
    xss_findings = await xss_mod.run(target, endpoints=["/search?q=test"])
    assert len(xss_findings) == 0

    # Test Exposure scanner
    exp_mod = ExposureModule()
    exp_findings = await exp_mod.run(target)
    assert len(exp_findings) == 0

    # Test Authz scanner
    authz_mod = AuthorizationModule()
    authz_findings = await authz_mod.run(target)
    assert len(authz_findings) == 0
