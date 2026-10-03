"""
HTML and JavaScript Parser for KRYPT Crawler.
Extracts links, forms, parameters, scripts, and API endpoint patterns.
"""

from dataclasses import dataclass, field
import re
from typing import Any, Dict, List, Set
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup

# Regex to discover potential API routes and endpoints inside text / JS
ENDPOINT_REGEX = re.compile(
    r"""(?:["'])(/(?:api|v[0-9]|rest|auth|admin|user|users|items|products|data|debug|login|logout|register|cart|checkout|order)[a-zA-Z0-9_/.-]*)(?:["'])""",
    re.IGNORECASE
)

PARAM_REGEX = re.compile(
    r"""[?&]([a-zA-Z0-9_\-\[\]]+)=(?:[^&#]*)""",
    re.IGNORECASE
)


@dataclass
class FormInfo:
    action: str
    method: str
    inputs: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class ParsedPage:
    url: str
    links: Set[str] = field(default_factory=set)
    scripts: Set[str] = field(default_factory=set)
    forms: List[FormInfo] = field(default_factory=list)
    endpoints: Set[str] = field(default_factory=set)
    parameters: Set[str] = field(default_factory=set)


class HtmlParser:
    """Extracts structured resources from HTML body."""

    @classmethod
    def parse(cls, base_url: str, html_text: str) -> ParsedPage:
        page = ParsedPage(url=base_url)
        if not html_text:
            return page

        soup = BeautifulSoup(html_text, "html.parser")

        # 1. Extract Links <a href>
        for a_tag in soup.find_all("a", href=True):
            href = a_tag["href"].strip()
            if href and not href.startswith(("javascript:", "mailto:", "tel:", "#")):
                full_url = urljoin(base_url, href)
                # Strip fragments
                parsed = urlparse(full_url)
                clean_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                if parsed.query:
                    clean_url += f"?{parsed.query}"
                    for param_match in PARAM_REGEX.findall(f"?{parsed.query}"):
                        page.parameters.add(param_match)
                page.links.add(clean_url)

        # 2. Extract Scripts <script src>
        for script_tag in soup.find_all("script"):
            src = script_tag.get("src")
            if src:
                script_url = urljoin(base_url, src.strip())
                page.scripts.add(script_url)
            elif script_tag.string:
                # Analyze inline JavaScript
                matches = ENDPOINT_REGEX.findall(script_tag.string)
                for m in matches:
                    page.endpoints.add(m)

        # 3. Extract Forms <form action method>
        for form_tag in soup.find_all("form"):
            action = form_tag.get("action", "")
            method = (form_tag.get("method") or "GET").upper()
            full_action = urljoin(base_url, action) if action else base_url

            inputs = []
            for inp in form_tag.find_all(["input", "select", "textarea"]):
                inp_name = inp.get("name")
                if inp_name:
                    inp_type = inp.get("type", "text")
                    inp_val = inp.get("value", "")
                    inputs.append({"name": inp_name, "type": inp_type, "default": inp_val})
                    page.parameters.add(inp_name)

            page.forms.append(FormInfo(action=full_action, method=method, inputs=inputs))
            page.links.add(full_action)

        # 4. Extract regex API endpoints in raw HTML
        for m in ENDPOINT_REGEX.findall(html_text):
            page.endpoints.add(m)

        return page
