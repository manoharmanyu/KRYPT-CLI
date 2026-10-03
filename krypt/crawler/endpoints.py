"""
Endpoint Inventory and Normalization Engine for KRYPT CLI.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from krypt.database.db import db
from krypt.database.models import EndpointModel
from krypt.safety.scope import ScopeEngine


@dataclass
class DiscoveredEndpoint:
    method: str
    url: str
    path: str
    parameters: List[str] = field(default_factory=list)
    content_type: str = ""
    discovered_from: str = ""
    confidence: str = "HIGH"


class EndpointManager:
    """Manages endpoint discovery and retrieval."""

    @classmethod
    def get_target_endpoints(cls, target: str) -> List[DiscoveredEndpoint]:
        """Fetch all discovered endpoints for target."""
        canonical_url, host, port, scheme = ScopeEngine.normalize_target(target)
        models = db.get_endpoints(canonical_url) or db.get_endpoints(host)
        
        results = []
        for m in models:
            params = [p.strip() for p in m.parameters.split(",") if p.strip()] if m.parameters else []
            results.append(
                DiscoveredEndpoint(
                    method=m.method,
                    url=m.url,
                    path=m.path or urlparse(m.url).path,
                    parameters=params,
                    content_type=m.content_type or "",
                    discovered_from=m.discovered_from or "crawler",
                    confidence=m.confidence or "HIGH"
                )
            )
        return results
