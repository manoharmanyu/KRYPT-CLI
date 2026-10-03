"""
Evidence and log redactor for KRYPT CLI.
Ensures no sensitive credentials, secrets, tokens, or private data are logged or stored unmasked.
"""

import re
from typing import Any, Dict, List, Union

SENSITIVE_KEY_PATTERNS = [
    re.compile(r"(api[_-]?key|token|auth|bearer|secret|password|passwd|pwd|private[_-]?key|session|cookie|jwt)", re.IGNORECASE),
]

SENSITIVE_VALUE_REGEXES = [
    (re.compile(r"(Bearer\s+)[A-Za-z0-9_\-\.]{10,}", re.IGNORECASE), r"\1[REDACTED_TOKEN]"),
    (re.compile(r"(Basic\s+)[A-Za-z0-9+/=]{8,}", re.IGNORECASE), r"\1[REDACTED_BASIC_AUTH]"),
    (re.compile(r'(["\']?(?:password|token|secret|api_key|apiKey|authToken)["\']?\s*[:=]\s*["\'])([^"\']{3,})(["\'])', re.IGNORECASE), r"\1[REDACTED]\3"),
    (re.compile(r'(password=)[^&\s]+', re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r'(token=)[^&\s]+', re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r'(key=)[^&\s]+', re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r'PHPSESSID=[A-Za-z0-9]+', re.IGNORECASE), r"PHPSESSID=[REDACTED_SESSION]"),
    (re.compile(r'sessionid=[A-Za-z0-9]+', re.IGNORECASE), r"sessionid=[REDACTED_SESSION]"),
    (re.compile(r'connect\.sid=[A-Za-z0-9%_\-]+', re.IGNORECASE), r"connect.sid=[REDACTED_SESSION]"),
    (re.compile(r'-----BEGIN [A-Z ]+ PRIVATE KEY-----[^-]+-----END [A-Z ]+ PRIVATE KEY-----', re.DOTALL), r"[REDACTED_PRIVATE_KEY]"),
]


def redact_text(text: str) -> str:
    """Redact sensitive patterns from a text string."""
    if not isinstance(text, str):
        return text
    
    result = text
    for pattern, replacement in SENSITIVE_VALUE_REGEXES:
        result = pattern.sub(replacement, result)
    return result


def redact_dict(data: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively redact sensitive keys and values from a dictionary."""
    if not isinstance(data, dict):
        return data

    cleaned: Dict[str, Any] = {}
    for key, value in data.items():
        # Check if key itself indicates sensitive content
        is_sensitive_key = any(pattern.search(str(key)) for pattern in SENSITIVE_KEY_PATTERNS)
        
        if is_sensitive_key and isinstance(value, (str, int, float)):
            cleaned[key] = "[REDACTED]"
        elif isinstance(value, dict):
            cleaned[key] = redact_dict(value)
        elif isinstance(value, list):
            cleaned[key] = [
                redact_dict(item) if isinstance(item, dict)
                else (redact_text(item) if isinstance(item, str) else item)
                for item in value
            ]
        elif isinstance(value, str):
            cleaned[key] = redact_text(value)
        else:
            cleaned[key] = value

    return cleaned


def redact_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """Redact HTTP headers containing credentials."""
    sensitive_headers = {
        "authorization", "proxy-authorization", "cookie", "set-cookie",
        "x-api-key", "x-auth-token", "api-key", "token", "session"
    }
    
    redacted = {}
    for k, v in headers.items():
        if k.lower() in sensitive_headers:
            if k.lower() == "authorization" and "bearer" in v.lower():
                redacted[k] = "Bearer [REDACTED]"
            elif k.lower() == "authorization" and "basic" in v.lower():
                redacted[k] = "Basic [REDACTED]"
            else:
                redacted[k] = "[REDACTED]"
        else:
            redacted[k] = redact_text(v)
    return redacted
