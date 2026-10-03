"""
Technology Fingerprinting Engine for KRYPT CLI.
Detects web servers, frameworks, programming languages, and CDN/WAF indicators safely.
"""

from dataclasses import dataclass
import re
from typing import Any, Dict, List, Optional
import httpx
from bs4 import BeautifulSoup

from krypt.database.db import db


@dataclass
class TechnologyMatch:
    name: str
    category: str
    confidence: str  # HIGH, MEDIUM, LOW
    version: str = ""
    evidence: str = ""


class TechFingerprinter:
    """Detects web technologies from HTTP response headers, cookies, and HTML patterns."""

    SIGNATURES = [
        # Web Servers
        {
            "name": "Nginx",
            "category": "Web Server",
            "headers": {"server": r"nginx(?:/([0-9.]+))?"},
        },
        {
            "name": "Apache",
            "category": "Web Server",
            "headers": {"server": r"Apache(?:/([0-9.]+))?"},
        },
        {
            "name": "Microsoft IIS",
            "category": "Web Server",
            "headers": {"server": r"Microsoft-IIS(?:/([0-9.]+))?"},
        },
        {
            "name": "Caddy",
            "category": "Web Server",
            "headers": {"server": r"Caddy"},
        },
        {
            "name": "LiteSpeed",
            "category": "Web Server",
            "headers": {"server": r"LiteSpeed"},
        },
        # Backend Frameworks & Runtimes
        {
            "name": "Express / Node.js",
            "category": "Backend Framework",
            "headers": {"x-powered-by": r"Express"},
        },
        {
            "name": "PHP",
            "category": "Programming Language",
            "headers": {
                "x-powered-by": r"PHP(?:/([0-9.]+))?",
                "set-cookie": r"PHPSESSID",
            },
        },
        {
            "name": "Laravel",
            "category": "Backend Framework",
            "headers": {"set-cookie": r"laravel_session|XSRF-TOKEN"},
        },
        {
            "name": "Django",
            "category": "Backend Framework",
            "headers": {"set-cookie": r"csrftoken|django"},
            "html": [r"csrfmiddlewaretoken"],
        },
        {
            "name": "Flask",
            "category": "Backend Framework",
            "headers": {"set-cookie": r"session="},
            "html": [r"Flask"],
        },
        {
            "name": "FastAPI / Uvicorn",
            "category": "Backend Framework",
            "headers": {"server": r"uvicorn"},
        },
        {
            "name": "Starlette",
            "category": "Backend Framework",
            "headers": {"server": r"starlette"},
        },
        {
            "name": "Ruby on Rails",
            "category": "Backend Framework",
            "headers": {
                "x-powered-by": r"Phusion Passenger",
                "set-cookie": r"_session_id",
            },
        },
        {
            "name": "ASP.NET",
            "category": "Backend Framework",
            "headers": {
                "x-powered-by": r"ASP\.NET",
                "x-aspnet-version": r"([0-9.]+)",
            },
        },
        # CMS & Frontend Frameworks
        {
            "name": "WordPress",
            "category": "CMS",
            "html": [r"/wp-content/", r"/wp-includes/", r"wp-embed\.min\.js"],
            "meta": {"generator": r"WordPress"},
        },
        {
            "name": "Drupal",
            "category": "CMS",
            "headers": {"x-generator": r"Drupal"},
            "meta": {"generator": r"Drupal"},
        },
        {
            "name": "React",
            "category": "Frontend Framework",
            "html": [r"data-reactroot", r"_reactInternalInstance", r"react\.production\.min\.js", r"__REACT_DEVTOOLS_GLOBAL_HOOK__"],
        },
        {
            "name": "Next.js",
            "category": "Frontend Framework",
            "headers": {"x-powered-by": r"Next\.js"},
            "html": [r"/_next/static/", r"__NEXT_DATA__"],
        },
        {
            "name": "Vue.js",
            "category": "Frontend Framework",
            "html": [r"data-v-[a-f0-9]+", r"vue\.runtime\.min\.js", r"__vue__"],
        },
        # CDN & Cloud / WAF
        {
            "name": "Cloudflare",
            "category": "CDN / WAF",
            "headers": {"server": r"cloudflare", "cf-ray": r".+"},
        },
        {
            "name": "Amazon CloudFront",
            "category": "CDN",
            "headers": {"x-amz-cf-id": r".+", "via": r"CloudFront"},
        },
        {
            "name": "Fastly",
            "category": "CDN",
            "headers": {"x-fastly-request-id": r".+", "fastly-debug-digest": r".+"},
        },
    ]

    @classmethod
    def fingerprint(
        cls,
        target_url: str,
        response: Optional[httpx.Response] = None,
        html_text: str = "",
        headers: Optional[Dict[str, str]] = None
    ) -> List[TechnologyMatch]:
        """Analyze HTTP headers, cookies, and body to identify technologies."""
        matches: List[TechnologyMatch] = []
        resp_headers = {k.lower(): v for k, v in (headers or (response.headers if response else {})).items()}
        html = html_text or (response.text if response else "")
        
        soup = BeautifulSoup(html, "html.parser") if html else None

        for sig in cls.SIGNATURES:
            tech_name = sig["name"]
            category = sig["category"]
            matched = False
            confidence = "HIGH"
            version = ""
            evidence_parts = []

            # 1. Header checks
            if "headers" in sig:
                for h_key, pattern in sig["headers"].items():
                    if h_key in resp_headers:
                        val = resp_headers[h_key]
                        regex = re.compile(pattern, re.IGNORECASE)
                        match_obj = regex.search(val)
                        if match_obj:
                            matched = True
                            if match_obj.groups() and match_obj.group(1):
                                version = match_obj.group(1)
                            evidence_parts.append(f"Header '{h_key}: {val}' matches pattern '{pattern}'")

            # 2. Meta tags
            if soup and "meta" in sig:
                for m_name, pattern in sig["meta"].items():
                    meta_tag = soup.find("meta", attrs={"name": m_name})
                    if meta_tag and meta_tag.get("content"):
                        content = meta_tag["content"]
                        if re.search(pattern, content, re.IGNORECASE):
                            matched = True
                            evidence_parts.append(f"Meta tag <meta name='{m_name}' content='{content}'>")

            # 3. HTML body regex patterns
            if html and "html" in sig:
                for pattern in sig["html"]:
                    if re.search(pattern, html, re.IGNORECASE):
                        matched = True
                        confidence = "MEDIUM" if not evidence_parts else "HIGH"
                        evidence_parts.append(f"HTML body contains indicator '{pattern}'")

            if matched:
                match_result = TechnologyMatch(
                    name=tech_name,
                    category=category,
                    confidence=confidence,
                    version=version,
                    evidence="; ".join(evidence_parts)
                )
                matches.append(match_result)
                
                # Persist to database
                db.add_technology(
                    target_url=target_url,
                    name=tech_name,
                    version=version,
                    category=category,
                    confidence=confidence,
                    evidence=match_result.evidence
                )

        return matches
