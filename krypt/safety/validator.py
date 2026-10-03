"""
Target validation and sanitization utilities for KRYPT CLI.
"""

import re
from typing import Optional, Tuple
from urllib.parse import urlparse

DOMAIN_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)
IPV4_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)


def is_valid_domain(domain: str) -> bool:
    """Check if string is a valid domain or localhost."""
    if not domain or len(domain) > 255:
        return False
    if domain in ("localhost", "127.0.0.1", "::1"):
        return True
    return bool(DOMAIN_REGEX.match(domain) or IPV4_REGEX.match(domain))


def clean_target_url(target: str) -> str:
    """Ensure target has http/https scheme and clean formatting."""
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        return f"http://{target}"
    return target


def parse_target(target: str) -> Tuple[str, str, int, str]:
    """Parse target into (clean_url, host, port, scheme)."""
    clean_url = clean_target_url(target)
    parsed = urlparse(clean_url)
    host = parsed.hostname or target
    scheme = parsed.scheme or "http"
    port = parsed.port or (443 if scheme == "https" else 80)
    return clean_url, host, port, scheme
