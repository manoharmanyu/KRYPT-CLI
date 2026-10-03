"""
Web Reconnaissance Engine for KRYPT CLI.
Performs comprehensive reconnaissance: HTTP status, TLS, redirects, headers, robots, sitemaps, and tech stack.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import httpx

from krypt.core.http import http_client
from krypt.database.db import db
from krypt.recon.headers import HeaderAnalyzer, SecurityHeadersReport
from krypt.recon.tech import TechFingerprinter, TechnologyMatch
from krypt.safety.scope import ScopeEngine


@dataclass
class ReconReport:
    target_url: str
    host: str
    status_code: Optional[int] = None
    is_https: bool = False
    redirect_chain: List[str] = field(default_factory=list)
    server_banner: Optional[str] = None
    technologies: List[TechnologyMatch] = field(default_factory=list)
    headers_report: Optional[SecurityHeadersReport] = None
    robots_rules: List[str] = field(default_factory=list)
    sitemap_urls: List[str] = field(default_factory=list)
    page_title: Optional[str] = None
    meta_description: Optional[str] = None
    response_headers: Dict[str, str] = field(default_factory=dict)


class ReconEngine:
    """Orchestrates web reconnaissance for target URL."""

    async def run(self, target: str) -> ReconReport:
        """Execute full reconnaissance."""
        canonical_url, host, port, scheme = ScopeEngine.normalize_target(target)
        ScopeEngine.check_scope(target, is_active_assessment=False, allow_passive=True)

        report = ReconReport(
            target_url=canonical_url,
            host=host,
            is_https=(scheme == "https")
        )

        # 1. Primary HTTP request
        resp = await http_client.get(canonical_url, follow_redirects=True)
        if resp:
            report.status_code = resp.status_code
            report.response_headers = dict(resp.headers)
            report.server_banner = resp.headers.get("server") or resp.headers.get("x-powered-by")
            
            # Check redirect history
            if resp.history:
                report.redirect_chain = [str(r.url) for r in resp.history] + [str(resp.url)]

            # Parse HTML metadata
            html = resp.text
            soup = BeautifulSoup(html, "html.parser")
            if soup.title and soup.title.string:
                report.page_title = soup.title.string.strip()
            
            desc_tag = soup.find("meta", attrs={"name": "description"})
            if desc_tag and desc_tag.get("content"):
                report.meta_description = desc_tag["content"].strip()

            # 2. Technology fingerprinting
            report.technologies = TechFingerprinter.fingerprint(
                target_url=canonical_url,
                response=resp,
                html_text=html
            )

            # 3. Security headers analysis
            report.headers_report = HeaderAnalyzer.analyze(
                target_url=canonical_url,
                response=resp
            )

            # Add discovered root endpoint to DB
            db.add_endpoint(
                target_url=canonical_url,
                method="GET",
                url=str(resp.url),
                path=urlparse(str(resp.url)).path or "/",
                discovered_from="recon",
                confidence="HIGH"
            )

        # 4. Fetch robots.txt
        robots_url = urljoin(canonical_url, "/robots.txt")
        robots_resp = await http_client.get(robots_url)
        if robots_resp and robots_resp.status_code == 200:
            for line in robots_resp.text.splitlines()[:20]:
                line = line.strip()
                if line and not line.startswith("#"):
                    report.robots_rules.append(line)
                    # If it has a sitemap line, record it
                    if line.lower().startswith("sitemap:"):
                        report.sitemap_urls.append(line.split(":", 1)[1].strip())

        # 5. Fetch sitemap.xml
        if not report.sitemap_urls:
            sitemap_url = urljoin(canonical_url, "/sitemap.xml")
            sitemap_resp = await http_client.get(sitemap_url)
            if sitemap_resp and sitemap_resp.status_code == 200:
                report.sitemap_urls.append(sitemap_url)

        return report
