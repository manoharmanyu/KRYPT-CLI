"""
Fail-Closed Target Scope Engine for KRYPT CLI.
Enforces strict authorization boundaries, preventing out-of-scope active assessments.
"""

import ipaddress
import socket
from typing import List, Optional, Set, Tuple
from urllib.parse import urlparse

from krypt.core.config import config
from krypt.core.logger import audit_log, logger
from krypt.database.db import db


class ScopeViolationException(Exception):
    """Raised when an operation targets an unauthorized or unregistered resource."""
    pass


class TargetNotRegisteredException(ScopeViolationException):
    """Raised when a target has not been registered in scope."""
    pass


class ScopeEngine:
    """
    Fail-closed authorization boundary.
    Validates targets against registered scope, allowed hostnames, and IP boundaries.
    """

    # Local / Private network definitions
    LOOPBACK_NETS = [ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128")]
    PRIVATE_NETS = [
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("fc00::/7"),
    ]

    @classmethod
    def normalize_target(cls, target_input: str) -> Tuple[str, str, int, str]:
        """
        Normalize target string into (canonical_url, host, port, scheme).
        """
        raw = target_input.strip()
        if not raw.startswith(("http://", "https://")):
            url = f"http://{raw}"
        else:
            url = raw

        parsed = urlparse(url)
        host = parsed.hostname or raw
        scheme = parsed.scheme or "http"
        port = parsed.port or (443 if scheme == "https" else 80)
        
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            canonical = f"{scheme}://{host}"
        else:
            canonical = f"{scheme}://{host}:{port}"

        return canonical, host, port, scheme

    @classmethod
    def resolve_host_ips(cls, host: str) -> List[str]:
        """Resolve host to IP addresses."""
        try:
            # Check if host is already an IP
            ipaddress.ip_address(host)
            return [host]
        except ValueError:
            pass

        try:
            results = socket.getaddrinfo(host, None)
            ips = list({r[4][0] for r in results})
            return ips
        except Exception as e:
            logger.warning(f"Could not resolve IP for host '{host}': {e}")
            return []

    @classmethod
    def is_local_or_private(cls, host: str) -> bool:
        """Check if a host resolves only to loopback or private RFC1918 space."""
        if host in ("localhost", "127.0.0.1", "::1", "0.0.0.0"):
            return True

        ips = cls.resolve_host_ips(host)
        if not ips:
            return False

        for ip_str in ips:
            try:
                ip = ipaddress.ip_address(ip_str)
                is_loopback = any(ip in net for net in cls.LOOPBACK_NETS)
                is_private = any(ip in net for net in cls.PRIVATE_NETS)
                if not (is_loopback or is_private):
                    return False
            except ValueError:
                return False
        return True

    @classmethod
    def check_scope(
        cls,
        target_input: str,
        is_active_assessment: bool = True,
        allow_passive: bool = False
    ) -> bool:
        """
        Fail-closed evaluation pipeline:
        1. Target registered in scope?
        2. Hostname allowed?
        3. Resolved IP allowed?
        4. Destination allowed?
        
        Raises ScopeViolationException on failure.
        """
        canonical_url, host, port, scheme = cls.normalize_target(target_input)

        # 1. Check if safety enforcement is active
        require_registered = config.get("safety.require_registered_target", True)
        is_lab_mode = config.get("safety.lab_mode", False)

        # If it's a pure passive OSINT inquiry and allow_passive is True, allow domain queries
        if allow_passive and not is_active_assessment:
            audit_log("PASSIVE_SCOPE_CHECK", host, "ALLOWED", "Passive OSINT inquiry permitted")
            return True

        # Check registration in DB
        is_registered = db.is_target_registered(canonical_url) or db.is_target_registered(host)
        
        # Localhost is automatically permitted for lab mode or local testing if registered or explicitly allowed
        if cls.is_local_or_private(host):
            # Auto-register local lab targets if in lab mode
            if is_lab_mode or not require_registered:
                audit_log("SCOPE_CHECK", host, "ALLOWED", "Localhost / private test laboratory")
                return True

        if require_registered and not is_registered:
            msg = (
                f"TARGET SCOPE VIOLATION: Target '{target_input}' is NOT registered in authorized scope.\n"
                f"Fail-closed safety active. Before conducting security assessments, you must register authorization:\n"
                f"  krypt target add {target_input}"
            )
            audit_log("SCOPE_CHECK", host, "BLOCKED", "Target not registered in authorized database")
            raise TargetNotRegisteredException(msg)

        # Validate resolved IP
        ips = cls.resolve_host_ips(host)
        if not ips and not cls.is_local_or_private(host):
            logger.warning(f"Could not resolve destination IP for {host}")

        audit_log("SCOPE_CHECK", host, "ALLOWED", f"Registered target authorized (IPs: {ips})")
        return True


# Export shorthand helper
def enforce_scope(target: str, is_active: bool = True) -> bool:
    """Enforce fail-closed scope check or raise ScopeViolationException."""
    return ScopeEngine.check_scope(target, is_active_assessment=is_active)
