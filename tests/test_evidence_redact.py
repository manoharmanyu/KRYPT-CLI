"""
Unit tests for evidence and secret redactor.
"""

from krypt.evidence.redactor import redact_text, redact_dict, redact_headers


def test_redact_bearer_token():
    text = "Authorization header contains Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    redacted = redact_text(text)
    assert "Bearer [REDACTED_TOKEN]" in redacted
    assert "eyJhbGci" not in redacted


def test_redact_password_in_text():
    text = 'User login payload: password="SuperSecretPassword123!"'
    redacted = redact_text(text)
    assert "SuperSecretPassword123!" not in redacted
    assert "[REDACTED]" in redacted


def test_redact_headers():
    headers = {
        "Authorization": "Bearer secret_api_key_1234567890",
        "Cookie": "session_id=abcdef123456; Path=/",
        "Content-Type": "application/json",
    }
    cleaned = redact_headers(headers)
    assert cleaned["Authorization"] == "Bearer [REDACTED]"
    assert cleaned["Cookie"] == "[REDACTED]"
    assert cleaned["Content-Type"] == "application/json"


def test_redact_nested_dict():
    data = {
        "user": "admin",
        "api_key": "secret_live_key_99812",
        "nested": {
            "token": "tok_xyz_12345",
            "active": True
        }
    }
    cleaned = redact_dict(data)
    assert cleaned["api_key"] == "[REDACTED]"
    assert cleaned["nested"]["token"] == "[REDACTED]"
    assert cleaned["user"] == "admin"
    assert cleaned["nested"]["active"] is True
