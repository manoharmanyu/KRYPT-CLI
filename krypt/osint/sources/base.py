"""
Base Source interface for KRYPT OSINT engine.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, List
from krypt.osint.models import IntelReport


class BaseSource(ABC):
    """Abstract base class for all OSINT intelligence sources."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Name of the OSINT source."""
        pass

    @property
    @abstractmethod
    def category(self) -> str:
        """Category: DNS, Subdomain, Email, Certificate, Public metadata, etc."""
        pass

    @abstractmethod
    async def collect(self, domain: str) -> Dict[str, Any]:
        """
        Collect intelligence for the target domain.
        Returns raw unstructured or semi-structured data from the source.
        """
        pass

    @abstractmethod
    def normalize(self, raw_data: Dict[str, Any], report: IntelReport) -> None:
        """
        Normalize collected data into standardized fields within the IntelReport.
        """
        pass
