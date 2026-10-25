"""
Tool Registry and Discovery Engine for KRYPT CLI.
Manages adapter lifecycle, metadata cataloging, discovery, and health diagnostics.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

from krypt.integrations.adapters.ares import ARESAdapter
from krypt.integrations.adapters.base import BaseAdapter
from krypt.integrations.adapters.harvester import HarvesterAdapter
from krypt.integrations.adapters.photon import PhotonAdapter
from krypt.integrations.adapters.torbot import TorBotAdapter
from krypt.integrations.models import ToolInfo


class ToolRegistry:
    """
    Central registry for upstream tool integrations.
    Provides discovery, metadata retrieval, adapter resolution, and health diagnostics.
    """

    def __init__(self, base_dir: Optional[Path] = None):
        self.base_dir = base_dir or Path(__file__).resolve().parents[2]
        self._adapters: Dict[str, BaseAdapter] = {}
        self._initialize_adapters()

    def _initialize_adapters(self) -> None:
        """Instantiate all configured adapters with proper base directory."""
        adapters = [
            HarvesterAdapter(base_dir=self.base_dir),
            PhotonAdapter(base_dir=self.base_dir),
            TorBotAdapter(base_dir=self.base_dir),
            ARESAdapter(base_dir=self.base_dir),
        ]
        for adapter in adapters:
            self._adapters[adapter.name.lower()] = adapter

    def list_adapters(self) -> List[BaseAdapter]:
        """Return list of all registered adapter instances."""
        return list(self._adapters.values())

    def list_tools(self) -> List[ToolInfo]:
        """Return metadata and readiness info for all integrated tools."""
        return [adapter.get_info() for adapter in self._adapters.values()]

    def get_adapter(self, name: str) -> Optional[BaseAdapter]:
        """
        Lookup an adapter by name (case-insensitive with common aliases).
        """
        clean_name = name.strip().lower()
        alias_map = {
            "harvester": "theharvester",
            "theharvester": "theharvester",
            "the_harvester": "theharvester",
            "photon": "photon",
            "torbot": "torbot",
            "tor_bot": "torbot",
            "ares": "ares",
        }
        resolved = alias_map.get(clean_name, clean_name)
        return self._adapters.get(resolved)

    async def doctor(self) -> Dict[str, Any]:
        """
        Run comprehensive diagnostic health checks across all integrated adapters.
        """
        results: Dict[str, Any] = {}
        for key, adapter in self._adapters.items():
            results[adapter.name] = await adapter.doctor()
        return results


# Global registry instance
registry = ToolRegistry()
