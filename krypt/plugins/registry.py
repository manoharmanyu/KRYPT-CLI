"""
Plugin and Module Registry for KRYPT CLI.
Tracks available OSINT sources, Web recon tools, and Security assessment modules.
"""

from typing import Any, Dict, List, Optional
from krypt.modules.auth import AuthModule
from krypt.modules.authz import AuthorizationModule
from krypt.modules.base import BaseModule
from krypt.modules.exposure import ExposureModule
from krypt.modules.headers import HeadersModule
from krypt.modules.idor import IDORModule
from krypt.modules.sqli import SQLInjectionModule
from krypt.modules.xss import XSSModule


class PluginRegistry:
    """Central registry of all built-in and extensible KRYPT plugins."""

    OSINT_PLUGINS = [
        {"name": "dns", "category": "OSINT", "description": "DNS Record Enumeration (A, AAAA, MX, NS, TXT, CNAME, SOA)"},
        {"name": "subdomains", "category": "OSINT", "description": "Passive and DNS Subdomain Discovery & IP Resolution"},
        {"name": "emails", "category": "OSINT", "description": "Public Email Indicator Harvester"},
        {"name": "certificates", "category": "OSINT", "description": "TLS/SSL Certificate & Certificate Transparency (crt.sh) Inspector"},
        {"name": "public_records", "category": "OSINT", "description": "RDAP and Public Registry Metadata Collector"},
    ]

    WEB_PLUGINS = [
        {"name": "crawler", "category": "WEB", "description": "Asynchronous BFS Web Crawler & Asset Map"},
        {"name": "endpoints", "category": "WEB", "description": "Endpoint Inventory and Parameter Extractor"},
        {"name": "scripts", "category": "WEB", "description": "JavaScript Static Analysis & API Route Discovery"},
        {"name": "headers", "category": "WEB", "description": "HTTP Security Headers & Cookies Analyzer"},
        {"name": "technology", "category": "WEB", "description": "Technology Stack Fingerprinting (Servers, Frameworks, CDNs)"},
    ]

    SECURITY_MODULES: Dict[str, BaseModule] = {
        "sqli": SQLInjectionModule(),
        "xss": XSSModule(),
        "auth": AuthModule(),
        "authz": AuthorizationModule(),
        "idor": IDORModule(),
        "exposure": ExposureModule(),
        "headers": HeadersModule(),
    }

    @classmethod
    def get_security_module(cls, name: str) -> Optional[BaseModule]:
        """Retrieve security module instance by name."""
        return cls.SECURITY_MODULES.get(name.lower())

    @classmethod
    def list_all(cls) -> Dict[str, List[Dict[str, Any]]]:
        """List all plugins grouped by category."""
        sec_list = [
            {
                "name": mod.name,
                "category": "SECURITY",
                "description": mod.description
            }
            for mod in cls.SECURITY_MODULES.values()
        ]
        return {
            "OSINT": cls.OSINT_PLUGINS,
            "WEB": cls.WEB_PLUGINS,
            "SECURITY": sec_list,
        }
