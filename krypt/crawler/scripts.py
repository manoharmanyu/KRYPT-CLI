"""
JavaScript Analysis Engine for KRYPT CLI.
Safely downloads within-scope scripts, analyzes AST/regex patterns for API routes, endpoints, parameters, and public config.
"""

from dataclasses import dataclass, field
import re
from typing import Any, Dict, List, Set
from urllib.parse import urljoin, urlparse

from krypt.core.http import http_client
from krypt.core.logger import logger
from krypt.database.db import db
from krypt.safety.scope import ScopeEngine

JS_ENDPOINT_PATTERNS = [
    re.compile(r"""(?:fetch|axios(?:\.get|\.post|\.put|\.delete)?|\$\.ajax|\$\.get|\$\.post)\s*\(\s*["'`](/[a-zA-Z0-9_\-/.?&=]+)["'`]""", re.IGNORECASE),
    re.compile(r"""["'`](/(?:api|v[0-9]|rest|auth|admin|user|users|items|products|data|debug|login|logout|register|order|cart)[a-zA-Z0-9_/.-]*)["'`]""", re.IGNORECASE),
    re.compile(r"""path\s*:\s*["'`](/[a-zA-Z0-9_\-/.?&=]+)["'`]""", re.IGNORECASE),
    re.compile(r"""endpoint\s*:\s*["'`](/[a-zA-Z0-9_\-/.?&=]+)["'`]""", re.IGNORECASE),
    re.compile(r"""url\s*:\s*["'`](/[a-zA-Z0-9_\-/.?&=]+)["'`]""", re.IGNORECASE),
]

JS_PARAM_PATTERNS = [
    re.compile(r"""params\s*:\s*\{([^}]+)\}""", re.IGNORECASE),
    re.compile(r"""[?&]([a-zA-Z0-9_\-]+)=(?:[^&"'`\s]*)""", re.IGNORECASE),
    re.compile(r"""(?:["']?)([a-zA-Z0-9_]{3,30})(?:["']?)\s*:\s*(?:req\.query|req\.body|params)""", re.IGNORECASE),
]

JS_CONFIG_PATTERNS = [
    re.compile(r"""(?:REACT_APP|NEXT_PUBLIC|VITE|ENV|CONFIG)_[A-Z0-9_]+\s*[:=]\s*["']([^"']+)["']""", re.IGNORECASE),
    re.compile(r"""(?:baseURL|apiUrl|apiHost|serverUrl)\s*:\s*["']([^"']+)["']""", re.IGNORECASE),
]


@dataclass
class ScriptAnalysisResult:
    script_url: str
    endpoints: List[str] = field(default_factory=list)
    parameters: List[str] = field(default_factory=list)
    configurations: List[str] = field(default_factory=list)
    url_patterns: List[str] = field(default_factory=list)


class ScriptAnalyzer:
    """Extracts endpoints, parameters, and public configurations from JavaScript files."""

    @classmethod
    async def analyze_script(cls, script_url: str, base_url: str) -> ScriptAnalysisResult:
        result = ScriptAnalysisResult(script_url=script_url)
        
        try:
            resp = await http_client.get(script_url, timeout=5.0)
            if not resp or resp.status_code != 200:
                return result

            content = resp.text
            endpoints_set: Set[str] = set()
            params_set: Set[str] = set()
            configs_set: Set[str] = set()

            # 1. Extract endpoint routes
            for pattern in JS_ENDPOINT_PATTERNS:
                matches = pattern.findall(content)
                for m in matches:
                    if isinstance(m, str) and len(m) > 1 and not m.endswith((".js", ".css", ".png", ".jpg", ".svg", ".woff")):
                        endpoints_set.add(m)
                        # Add to endpoint inventory
                        full_ep = urljoin(base_url, m)
                        db.add_endpoint(
                            target_url=base_url,
                            method="GET",
                            url=full_ep,
                            path=m,
                            discovered_from=f"js:{script_url}",
                            confidence="HIGH"
                        )

            # 2. Extract parameters
            for pattern in JS_PARAM_PATTERNS:
                matches = pattern.findall(content)
                for m in matches:
                    if isinstance(m, str):
                        for sub_param in re.findall(r"""([a-zA-Z0-9_]{2,20})""", m):
                            params_set.add(sub_param)

            # 3. Extract public config
            for pattern in JS_CONFIG_PATTERNS:
                matches = pattern.findall(content)
                for m in matches:
                    if isinstance(m, str) and len(m) < 100:
                        configs_set.add(m)

            result.endpoints = sorted(list(endpoints_set))
            result.parameters = sorted(list(params_set))
            result.configurations = sorted(list(configs_set))
            result.url_patterns = [ep for ep in result.endpoints if ":" in ep or "{" in ep]

        except Exception as e:
            logger.debug(f"Error analyzing script {script_url}: {e}")

        return result

    @classmethod
    async def analyze_target_scripts(cls, target: str) -> List[ScriptAnalysisResult]:
        """Fetch and analyze all in-scope scripts discovered on target."""
        canonical_url, host, port, scheme = ScopeEngine.normalize_target(target)
        ScopeEngine.check_scope(target, is_active_assessment=False, allow_passive=True)

        results: List[ScriptAnalysisResult] = []

        # 1. Fetch home page to find script tags
        resp = await http_client.get(canonical_url)
        if not resp:
            return results

        from bs4 import BeautifulSoup
        soup = BeautifulSoup(resp.text, "html.parser")
        script_urls = set()

        for s in soup.find_all("script"):
            src = s.get("src")
            if src:
                full_script_url = urljoin(canonical_url, src.strip())
                # Enforce same-origin / in-scope for script downloads
                parsed_s = urlparse(full_script_url)
                if parsed_s.hostname == host or host in (parsed_s.hostname or ""):
                    script_urls.add(full_script_url)

        for s_url in list(script_urls)[:20]:
            res = await cls.analyze_script(s_url, canonical_url)
            results.append(res)

        return results
