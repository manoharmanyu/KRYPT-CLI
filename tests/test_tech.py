"""
Unit tests for technology fingerprinting and security header analysis.
"""

from krypt.recon.headers import HeaderAnalyzer
from krypt.recon.tech import TechFingerprinter


def test_tech_fingerprinting_nginx_and_django():
    headers = {
        "server": "nginx/1.24.0",
        "set-cookie": "csrftoken=abc123xyz; Path=/",
    }
    html = "<div csrfmiddlewaretoken='xyz'></div>"
    matches = TechFingerprinter.fingerprint("http://test.local", headers=headers, html_text=html)
    
    names = {m.name for m in matches}
    assert "Nginx" in names
    assert "Django" in names


def test_security_headers_missing_csp():
    headers = {
        "server": "Apache/2.4.50",
        "set-cookie": "session_id=12345; Path=/; Secure",
    }
    report = HeaderAnalyzer.analyze("http://test.local", headers=headers)
    
    failed_headers = {h.header_name for h in report.header_results if h.status == "FAIL"}
    assert "Content-Security-Policy" in failed_headers
    assert "Strict-Transport-Security" in failed_headers
    assert "X-Frame-Options" in failed_headers

    assert len(report.cookie_results) == 1
    # HttpOnly missing
    assert "Missing 'HttpOnly' flag" in report.cookie_results[0].issues
